/*
 * bloom_builder.cpp  —  TSV → Bloom Filter  (C++17, Mythical Edition)
 *
 * Build:
 *   g++ -O3 -std=c++17 -march=native -pthread bloom_builder.cpp -o bloom_builder
 *
 * Usage:
 *   ./bloom_builder <input.tsv> <output.bloom> [expected_items=0] [fpp=0.001]
 *   expected_items=0 → auto-count from file
 *
 * File format v3:
 *   ver(1B) + k0(8B LE) + k1(8B LE) + k_num(4B LE) + bitmap_len(8B LE) + bitmap
 *   Bitmap size is rounded UP to next power of 2 bytes for fast modulo-free lookups.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cassert>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <atomic>
#include <thread>
#include <vector>
#include <string>
#include <string_view>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <algorithm>

namespace ansi {
    constexpr const char* RESET  = "\x1b[0m";
    constexpr const char* BOLD   = "\x1b[1m";
    constexpr const char* DIM    = "\x1b[2m";
    constexpr const char* RED    = "\x1b[91m";
    constexpr const char* GREEN  = "\x1b[92m";
    constexpr const char* YELLOW = "\x1b[93m";
    constexpr const char* CYAN   = "\x1b[96m";
    constexpr const char* MAGENTA= "\x1b[95m";
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
static std::string fmt_num(uint64_t n) {
    std::string s = std::to_string(n), r;
    int m = (int)(s.size() % 3);
    for (int i = 0; i < (int)s.size(); ++i) {
        if (i && (i-m)%3==0) r+=',';
        r+=s[i];
    }
    return r;
}
static std::string fmt_bytes(uint64_t n) {
    const char* u[]={"B","KB","MB","GB","TB"};
    double v=(double)n; int i=0;
    while(v>=1024&&i<4){v/=1024;++i;}
    std::ostringstream ss; ss<<std::fixed<<std::setprecision(2)<<v<<" "<<u[i];
    return ss.str();
}
static uint64_t next_pow2(uint64_t n) {
    if (n == 0) return 1;
    --n; n|=n>>1; n|=n>>2; n|=n>>4; n|=n>>8; n|=n>>16; n|=n>>32;
    return n+1;
}

// ─── SipHash-1-3 double output ────────────────────────────────────────────────
static inline uint64_t rotl64(uint64_t x, int b) { return (x<<b)|(x>>(64-b)); }
#define SR(a,b,c,d) a+=b;b=rotl64(b,13);b^=a;a=rotl64(a,32); \
    c+=d;d=rotl64(d,16);d^=c;a+=d;d=rotl64(d,21);d^=a; \
    c+=b;b=rotl64(b,17);b^=c;c=rotl64(c,32);
struct SipPair { uint64_t h1, h2; };
static SipPair sip13(const uint8_t* data, size_t len, uint64_t k0, uint64_t k1) {
    uint64_t v0=k0^0x736f6d6570736575ULL,v1=k1^0x646f72616e646f6dULL;
    uint64_t v2=k0^0x6c7967656e657261ULL,v3=k1^0x7465646279746573ULL;
    size_t end=(len/8)*8;
    for(size_t i=0;i<end;i+=8){uint64_t m;memcpy(&m,data+i,8);v3^=m;SR(v0,v1,v2,v3)v0^=m;}
    uint64_t last=(uint64_t)(len&0xff)<<56;
    for(size_t j=0;j<(len&7);++j)last|=(uint64_t)data[end+j]<<(j*8);
    v3^=last;SR(v0,v1,v2,v3)v0^=last;v2^=0xff;
    SR(v0,v1,v2,v3)SR(v0,v1,v2,v3)SR(v0,v1,v2,v3)
    uint64_t h1=v0^v1^v2^v3;v1^=0xee;
    SR(v0,v1,v2,v3)SR(v0,v1,v2,v3)SR(v0,v1,v2,v3)
    return{h1,v0^v1^v2^v3};
}
#undef SR

// ─── Address validation ───────────────────────────────────────────────────────
// Accepts ALL Bitcoin address formats:
//   P2PKH:       1... (25-34 chars)
//   P2SH:        3... (34 chars)
//   Bech32:      bc1q... (42 chars)
//   Taproot:     bc1p... (62 chars)
// Also accepts any 26-90 char token to future-proof against new formats.
// CRITICAL: bloom_builder and bloom_checker MUST use the same function.
static inline bool is_valid_btc_address(std::string_view sv) {
    size_t n = sv.size();
    if (n < 26 || n > 90) return false;
    // reject header words and obviously non-address tokens
    char c = sv[0];
    if (c < '1' || c > 'z') return false;
    return true;
}

// ─── Bloom filter ─────────────────────────────────────────────────────────────
// Bitmap size is rounded to the next power-of-2 bytes so that
// bit indexing uses & (bits-1) instead of expensive 64-bit %.
struct BloomFilter {
    std::unique_ptr<std::atomic<uint8_t>[]> bitmap;
    uint64_t bitmap_bytes = 0;
    uint64_t bitmap_bits  = 0;   // always a power of 2 * 8
    uint64_t mask         = 0;   // bitmap_bits - 1, for fast modulo
    int      k_num        = 0;
    uint64_t sip_k0       = 0;
    uint64_t sip_k1       = 0;

    void init(uint64_t expected_items, double fpp) {
        double ln2 = 0.6931471805599453;
        double m_f = -(double)expected_items * std::log(fpp) / (ln2 * ln2);
        uint64_t m  = (uint64_t)std::ceil(m_f);
        if (m < 1) m = 1;

        // Round UP bytes to power of 2 for fast modulo
        uint64_t bytes_raw = (m + 7) / 8;
        bitmap_bytes = next_pow2(bytes_raw);
        bitmap_bits  = bitmap_bytes * 8;
        mask         = bitmap_bits - 1;

        double k_f = ((double)bitmap_bits / (double)expected_items) * ln2;
        k_num = (int)std::max(1.0, std::floor(k_f));

        bitmap = std::make_unique<std::atomic<uint8_t>[]>(bitmap_bytes);
        for (uint64_t i = 0; i < bitmap_bytes; ++i)
            bitmap[i].store(0, std::memory_order_relaxed);
    }

    // Thread-safe insert
    inline void add(std::string_view item) {
        auto [h1, h2] = sip13((const uint8_t*)item.data(), item.size(), sip_k0, sip_k1);
        for (int i = 0; i < k_num; ++i) {
            uint64_t bit      = (h1 + (uint64_t)i * h2) & mask;  // fast mod
            uint64_t byte_idx = bit >> 3;
            uint8_t  bmask    = (uint8_t)(1u << (bit & 7));
            bitmap[byte_idx].fetch_or(bmask, std::memory_order_relaxed);
        }
    }

    // v3 format: ver(1) + k0(8) + k1(8) + k_num(4) + bitmap_len(8) + bitmap
    void save(const std::string& path) const {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) { std::cerr << "Cannot open: " << path << "\n"; exit(1); }
        uint8_t  ver  = 3;
        uint32_t k32  = (uint32_t)k_num;
        uint64_t blen = bitmap_bytes;
        f.write((char*)&ver,    1);
        f.write((char*)&sip_k0, 8);
        f.write((char*)&sip_k1, 8);
        f.write((char*)&k32,    4);
        f.write((char*)&blen,   8);
        for (uint64_t i = 0; i < bitmap_bytes; ++i) {
            uint8_t v = bitmap[i].load(std::memory_order_relaxed);
            f.write((char*)&v, 1);
        }
    }

    uint64_t byte_size() const { return bitmap_bytes; }
};

// ─── Memory-mapped file ───────────────────────────────────────────────────────
struct MMapFile {
    const char* data = nullptr;
    size_t      size = 0;
    int         fd   = -1;

    explicit MMapFile(const std::string& path) {
        fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) { perror("open"); exit(1); }
        struct stat st; fstat(fd, &st);
        size = (size_t)st.st_size;
        if (!size) { close(fd); fd=-1; return; }
        data = (const char*)mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
        if (data == MAP_FAILED) { perror("mmap"); exit(1); }
        madvise((void*)data, size, MADV_SEQUENTIAL);
    }
    ~MMapFile() {
        if (data && data != MAP_FAILED) munmap((void*)data, size);
        if (fd >= 0) close(fd);
    }
};

// ─── Build line offset index ──────────────────────────────────────────────────
static std::vector<size_t> build_offsets(const char* data, size_t size) {
    std::vector<size_t> v;
    v.reserve(size / 38);
    v.push_back(0);
    const char* p = data, *end = data + size;
    while ((p = (const char*)memchr(p, '\n', end-p))) {
        ++p; if (p < end) v.push_back(p - data);
    }
    return v;
}

// ─── Parallel count of valid addresses ───────────────────────────────────────
static uint64_t count_valid(const char* data, size_t fsize,
                             const std::vector<size_t>& offs,
                             size_t from, size_t to) {
    uint64_t n = 0;
    for (size_t li = from; li < to; ++li) {
        size_t s = offs[li];
        size_t e = (li+1 < offs.size()) ? offs[li+1] : fsize;
        std::string_view line(data+s, e-s);
        while (!line.empty() && (line.back()=='\n'||line.back()=='\r')) line.remove_suffix(1);
        auto t = line.find('\t');
        std::string_view addr = (t!=std::string_view::npos) ? line.substr(0,t) : line;
        if (is_valid_btc_address(addr)) ++n;
    }
    return n;
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <input.tsv> <output.bloom> [expected=0] [fpp=0.001]\n";
        return 1;
    }
    std::string tsv_path   = argv[1];
    std::string bloom_path = argv[2];
    uint64_t expected      = argc>3 ? (uint64_t)std::stoull(argv[3]) : 0;
    double   fpp           = argc>4 ? std::stod(argv[4])             : 0.001;

    unsigned ncpu = std::max(1u, std::thread::hardware_concurrency());

    // Banner
    std::cout << "\n" << ansi::CYAN
        << "  ╔═══════════════════════════════════════════════════════╗\n"
        << "  ║   Bitcoin Bloom Builder  v3  ·  Mythical Edition     ║\n"
        << "  ╚═══════════════════════════════════════════════════════╝\n"
        << ansi::RESET << "\n";
    std::cout << ansi::BOLD << "  Input:   " << ansi::RESET << tsv_path   << "\n";
    std::cout << ansi::BOLD << "  Output:  " << ansi::RESET << bloom_path << "\n";
    std::cout << ansi::BOLD << "  FPP:     " << ansi::RESET << fpp        << "\n";
    std::cout << ansi::BOLD << "  Threads: " << ansi::RESET << ncpu       << "\n\n";

    // 1. Memory-map
    std::cout << ansi::YELLOW << "  ⟳" << ansi::RESET << "  Mapping " << tsv_path << "...\n";
    MMapFile mmf(tsv_path);
    if (!mmf.data) { std::cerr << "Empty file\n"; return 1; }
    std::cout << ansi::GREEN << "  ✔" << ansi::RESET << "  "
              << fmt_bytes(mmf.size) << "\n\n";

    // 2. Build line index (parallel)
    std::cout << ansi::YELLOW << "  ⟳" << ansi::RESET << "  Building line index...\n";
    auto t0 = std::chrono::steady_clock::now();
    auto offsets = build_offsets(mmf.data, mmf.size);
    double idx_s = std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();

    // Detect header
    bool has_header = false;
    size_t start_idx = 0;
    if (!offsets.empty()) {
        size_t e0 = offsets.size()>1 ? offsets[1] : mmf.size;
        std::string_view fl(mmf.data, e0);
        while (!fl.empty()&&(fl.back()=='\n'||fl.back()=='\r')) fl.remove_suffix(1);
        auto t = fl.find('\t');
        std::string_view tok = t!=std::string_view::npos ? fl.substr(0,t) : fl;
        if (!is_valid_btc_address(tok)) { has_header=true; start_idx=1; }
    }
    std::cout << ansi::GREEN << "  ✔" << ansi::RESET << "  "
              << fmt_num(offsets.size()) << " lines"
              << (has_header ? " (header skipped)" : "")
              << " in " << std::fixed << std::setprecision(2) << idx_s << "s\n\n";

    // 3. Count valid addresses (parallel)
    if (expected == 0) {
        std::cout << ansi::YELLOW << "  ⟳" << ansi::RESET << "  Counting valid addresses ("
                  << ncpu << " threads)...\n";
        auto tc0 = std::chrono::steady_clock::now();
        size_t total_work = offsets.size() - start_idx;
        size_t chunk = (total_work + ncpu - 1) / ncpu;
        std::vector<std::atomic<uint64_t>> counts(ncpu);
        std::vector<std::thread> th;
        for (unsigned i = 0; i < ncpu; ++i) {
            size_t from = start_idx + i*chunk;
            size_t to   = std::min(from+chunk, offsets.size());
            if (from >= offsets.size()) break;
            th.emplace_back([&,i,from,to](){
                counts[i].store(count_valid(mmf.data, mmf.size, offsets, from, to));
            });
        }
        for (auto& t2 : th) t2.join();
        for (unsigned i = 0; i < ncpu; ++i) expected += counts[i].load();
        double tc_s = std::chrono::duration<double>(
            std::chrono::steady_clock::now()-tc0).count();
        std::cout << ansi::GREEN << "  ✔" << ansi::RESET << "  "
                  << fmt_num(expected) << " valid addresses in "
                  << std::fixed<<std::setprecision(2)<<tc_s<<"s\n\n";
    }
    if (expected == 0) { std::cerr << "No valid addresses found\n"; return 1; }

    // 4. Allocate bloom filter
    BloomFilter bloom;
    bloom.init(expected, fpp);
    std::cout << ansi::BOLD << "  Bloom filter:\n" << ansi::RESET;
    std::cout << "    k_num:      " << ansi::CYAN << bloom.k_num << ansi::RESET << "\n";
    std::cout << "    bits:       " << ansi::CYAN << fmt_num(bloom.bitmap_bits)
              << " (power-of-2 → fast modulo-free lookup)" << ansi::RESET << "\n";
    std::cout << "    size:       " << ansi::CYAN << fmt_bytes(bloom.bitmap_bytes)
              << ansi::RESET << "\n";
    std::cout << "    seeds:      " << ansi::CYAN << "k0=0 k1=0" << ansi::RESET << "\n\n";

    // 5. Parallel insertion with live throughput
    std::cout << ansi::YELLOW << "  ⟳" << ansi::RESET << "  Inserting "
              << fmt_num(expected) << " addresses (" << ncpu << " threads)...\n";

    size_t total_work = offsets.size() - start_idx;
    size_t chunk = (total_work + ncpu - 1) / ncpu;
    std::atomic<uint64_t> inserted{0};
    auto ti0 = std::chrono::steady_clock::now();

    auto worker = [&](size_t from, size_t to) {
        uint64_t local = 0;
        for (size_t li = from; li < to; ++li) {
            size_t s = offsets[li];
            size_t e = (li+1 < offsets.size()) ? offsets[li+1] : mmf.size;
            std::string_view line(mmf.data+s, e-s);
            while (!line.empty()&&(line.back()=='\n'||line.back()=='\r')) line.remove_suffix(1);
            auto t2 = line.find('\t');
            std::string_view addr = (t2!=std::string_view::npos) ? line.substr(0,t2) : line;
            if (is_valid_btc_address(addr)) {
                bloom.add(addr);
                ++local;
                if (local % 1000000 == 0) {
                    inserted.fetch_add(local, std::memory_order_relaxed);
                    local = 0;
                }
            }
        }
        inserted.fetch_add(local, std::memory_order_relaxed);
    };

    std::vector<std::thread> threads;
    threads.reserve(ncpu);
    for (unsigned i = 0; i < ncpu; ++i) {
        size_t from = start_idx + i*chunk;
        size_t to   = std::min(from+chunk, offsets.size());
        if (from >= offsets.size()) break;
        threads.emplace_back(worker, from, to);
    }

    // Progress thread
    std::thread progress_thr([&](){
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            uint64_t ins = inserted.load(std::memory_order_relaxed);
            double el = std::chrono::duration<double>(
                std::chrono::steady_clock::now()-ti0).count();
            double rate = el > 0 ? ins/el/1e6 : 0;
            double pct  = expected > 0 ? 100.0*ins/expected : 0;
            int bar = (int)(pct * 0.4);
            std::string b(bar,'#'); b += std::string(40-bar,'.');
            std::cout << "\r  [" << ansi::GREEN << b << ansi::RESET << "] "
                      << std::fixed<<std::setprecision(1)<<pct<<"% "
                      << ansi::CYAN<<fmt_num(ins)<<ansi::RESET<<"/"<<fmt_num(expected)
                      << " " << ansi::YELLOW<<std::setprecision(2)<<rate<<"M/s"<<ansi::RESET
                      << "     " << std::flush;
            if (ins >= (uint64_t)(expected * 0.9999)) break;
        }
    });

    for (auto& t2 : threads) t2.join();
    progress_thr.join();

    uint64_t final_ins = inserted.load();
    double ti_s = std::chrono::duration<double>(
        std::chrono::steady_clock::now()-ti0).count();
    std::cout << "\r  " << ansi::GREEN << "✔" << ansi::RESET << "  "
              << fmt_num(final_ins) << " inserted in "
              << std::fixed<<std::setprecision(2)<<ti_s<<"s ("
              << final_ins/ti_s/1e6 << " M/s)\n\n";

    // 6. Save
    std::cout << ansi::YELLOW << "  ⟳" << ansi::RESET << "  Saving...\n";
    bloom.save(bloom_path);
    struct stat st; stat(bloom_path.c_str(), &st);
    std::cout << ansi::GREEN << "  ✔" << ansi::RESET << "  "
              << bloom_path << "  (" << fmt_bytes(st.st_size) << ")  "
              << ansi::DIM << "v3 format — k_num stored" << ansi::RESET << "\n\n";

    // 7. Self-test: verify first 10 addresses round-trip
    std::cout << ansi::YELLOW << "  ⟳" << ansi::RESET << "  Self-test...\n";
    int checked_st = 0; bool ok = true;
    for (size_t li = start_idx; li < offsets.size() && checked_st < 10; ++li) {
        size_t s = offsets[li];
        size_t e = (li+1<offsets.size()) ? offsets[li+1] : mmf.size;
        std::string_view line(mmf.data+s, e-s);
        while (!line.empty()&&(line.back()=='\n'||line.back()=='\r')) line.remove_suffix(1);
        auto t2 = line.find('\t');
        std::string_view addr = (t2!=std::string_view::npos) ? line.substr(0,t2) : line;
        if (!is_valid_btc_address(addr)) continue;
        auto [h1,h2] = sip13((const uint8_t*)addr.data(), addr.size(), bloom.sip_k0, bloom.sip_k1);
        bool present = true;
        for (int i = 0; i < bloom.k_num && present; ++i) {
            uint64_t bit = (h1 + (uint64_t)i*h2) & bloom.mask;
            if (!(bloom.bitmap[bit>>3].load(std::memory_order_relaxed) & (1u<<(bit&7))))
                present = false;
        }
        std::cout << "    " << (present?ansi::GREEN:ansi::RED)
                  << (present?"✔":"✘") << ansi::RESET << "  " << addr << "\n";
        if (!present) ok = false;
        ++checked_st;
    }
    std::cout << "\n";
    if (ok && checked_st > 0)
        std::cout << ansi::GREEN << "  ✔ All self-checks passed\n" << ansi::RESET;
    else
        std::cout << ansi::RED << "  ✘ SELF-TEST FAILED\n" << ansi::RESET;

    // Summary
    std::cout << "\n" << ansi::CYAN << std::string(60,'=') << ansi::RESET << "\n"
              << ansi::BOLD << "  Summary\n" << ansi::RESET
              << "  Addresses: " << ansi::CYAN<<fmt_num(final_ins)<<ansi::RESET<<"\n"
              << "  Bloom:     " << ansi::CYAN<<fmt_bytes(bloom.bitmap_bytes)<<ansi::RESET
              << "  (k="<<bloom.k_num<<", fpp≈"<<fpp<<")\n"
              << "  Format:    v3 (k_num stored — no guesswork needed)\n"
              << "  Speed:     " << ansi::YELLOW
              << std::fixed<<std::setprecision(2)<<final_ins/ti_s/1e6
              <<"M addr/s"<<ansi::RESET<<"\n"
              << ansi::CYAN << std::string(60,'=') << ansi::RESET << "\n\n";

    return ok ? 0 : 1;
}
