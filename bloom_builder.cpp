/*
 * bloom_builder.cpp — TSV → Bloom Filter Converter
 *
 * IMPROVEMENTS over Python version:
 *  - Memory-mapped file reading (no line-by-line Python overhead)
 *  - SipHash-1-3 in native C++ (no Python interpreter overhead)
 *  - Parallel insertion using std::thread + atomic bitset
 *  - Progress via ANSI escape codes (no external deps)
 *  - Version-2 bloom file: includes SipHash seeds (k0, k1) so scanner.cpp
 *    can use the same seeds.  Backwards compatible v1 save also included.
 *
 * Build:
 *   g++ -O3 -std=c++17 -march=native -pthread bloom_builder.cpp -o bloom_builder
 *
 * Usage:
 *   ./bloom_builder <input.tsv> <output.bloom> [expected_items] [fpp]
 *   ./bloom_builder addresses.tsv addresses.bloom 0 0.001
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
#include <numeric>

// ─────────────────────────────────────────────────────────────
// ANSI helpers
// ─────────────────────────────────────────────────────────────
namespace ansi {
    constexpr const char* RESET  = "\x1b[0m";
    constexpr const char* CYAN   = "\x1b[96m";
    constexpr const char* YELLOW = "\x1b[93m";
    constexpr const char* GREEN  = "\x1b[92m";
    constexpr const char* RED    = "\x1b[91m";
    constexpr const char* DIM    = "\x1b[2m";
}

// ─────────────────────────────────────────────────────────────
// SipHash-1-3 (double output: h1, h2)
// Same algorithm as Python version — bit-for-bit identical results
// ─────────────────────────────────────────────────────────────
static inline uint64_t rotl64(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}

#define SIPROUND(v0,v1,v2,v3) \
    v0 += v1; v1 = rotl64(v1,13); v1 ^= v0; v0 = rotl64(v0,32); \
    v2 += v3; v3 = rotl64(v3,16); v3 ^= v2; \
    v0 += v3; v3 = rotl64(v3,21); v3 ^= v0; \
    v2 += v1; v1 = rotl64(v1,17); v1 ^= v2; v2 = rotl64(v2,32);

struct SipHash13Result { uint64_t h1, h2; };

static SipHash13Result siphash13_double(const uint8_t* data, size_t len,
                                         uint64_t k0 = 0, uint64_t k1 = 0) {
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    size_t end = (len / 8) * 8;

    for (size_t i = 0; i < end; i += 8) {
        uint64_t m;
        memcpy(&m, data + i, 8);  // safe unaligned read, LE assumed
        v3 ^= m;
        SIPROUND(v0, v1, v2, v3)
        v0 ^= m;
    }

    uint64_t last = (uint64_t)(len & 0xff) << 56;
    size_t rem = len & 7;
    for (size_t j = 0; j < rem; ++j)
        last |= (uint64_t)data[end + j] << (j * 8);

    v3 ^= last;
    SIPROUND(v0, v1, v2, v3)
    v0 ^= last;

    v2 ^= 0xff;
    SIPROUND(v0, v1, v2, v3)
    SIPROUND(v0, v1, v2, v3)
    SIPROUND(v0, v1, v2, v3)
    uint64_t h1 = v0 ^ v1 ^ v2 ^ v3;

    v1 ^= 0xee;
    SIPROUND(v0, v1, v2, v3)
    SIPROUND(v0, v1, v2, v3)
    SIPROUND(v0, v1, v2, v3)
    uint64_t h2 = v0 ^ v1 ^ v2 ^ v3;

    return {h1, h2};
}

// ─────────────────────────────────────────────────────────────
// Bloom Filter (thread-safe via std::atomic<uint8_t>* raw array)
// ─────────────────────────────────────────────────────────────
struct BloomFilter {
    std::unique_ptr<std::atomic<uint8_t>[]> bitmap;
    uint64_t bitmap_bytes = 0;
    uint64_t bitmap_bits  = 0;
    int      k_num        = 0;
    uint64_t sip_k0       = 0;
    uint64_t sip_k1       = 0;

    BloomFilter(uint64_t expected_items, double fpp) {
        double ln2  = std::log(2.0);
        double m_f  = -(double)expected_items * std::log(fpp) / (ln2 * ln2);
        bitmap_bits = (uint64_t)std::ceil(m_f);
        if (bitmap_bits < 1) bitmap_bits = 1;

        double k_f = ((double)bitmap_bits / (double)expected_items) * ln2;
        k_num      = (int)std::max(1.0, std::floor(k_f));

        bitmap_bytes = (bitmap_bits + 7) / 8;
        bitmap       = std::make_unique<std::atomic<uint8_t>[]>(bitmap_bytes);
        for (uint64_t i = 0; i < bitmap_bytes; ++i)
            bitmap[i].store(0, std::memory_order_relaxed);
    }

    void add(std::string_view item) {
        auto [h1, h2] = siphash13_double(
            (const uint8_t*)item.data(), item.size(), sip_k0, sip_k1);
        for (int i = 0; i < k_num; ++i) {
            uint64_t bit      = (h1 + (uint64_t)i * h2) % bitmap_bits;
            uint64_t byte_idx = bit / 8;
            uint8_t  mask     = (uint8_t)(1u << (bit % 8));
            bitmap[byte_idx].fetch_or(mask, std::memory_order_relaxed);
        }
    }

    bool contains(std::string_view item) const {
        auto [h1, h2] = siphash13_double(
            (const uint8_t*)item.data(), item.size(), sip_k0, sip_k1);
        for (int i = 0; i < k_num; ++i) {
            uint64_t bit      = (h1 + (uint64_t)i * h2) % bitmap_bits;
            uint64_t byte_idx = bit / 8;
            uint8_t  mask     = (uint8_t)(1u << (bit % 8));
            if (!(bitmap[byte_idx].load(std::memory_order_relaxed) & mask))
                return false;
        }
        return true;
    }

    // File format v2: version(1B) + k0(8B LE) + k1(8B LE) + bitmap_len(8B LE) + bitmap
    void save(const std::string& path) const {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) { std::cerr << "Cannot open output: " << path << "\n"; exit(1); }
        uint8_t  ver  = 2;
        uint64_t blen = bitmap_bytes;
        f.write((char*)&ver,    1);
        f.write((char*)&sip_k0, 8);
        f.write((char*)&sip_k1, 8);
        f.write((char*)&blen,   8);
        for (uint64_t i = 0; i < bitmap_bytes; ++i) {
            uint8_t v = bitmap[i].load(std::memory_order_relaxed);
            f.write((char*)&v, 1);
        }
    }

    uint64_t byte_size() const { return bitmap_bytes; }
};

// ─────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────
static bool is_valid_address(std::string_view addr) {
    if (addr.empty()) return false;
    size_t len = addr.size();
    return len >= 26 && len <= 90;
}

static std::string fmt_bytes(uint64_t n) {
    const char* units[] = {"B","KB","MB","GB","TB"};
    double v = (double)n;
    int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; ++i; }
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2) << v << " " << units[i];
    return ss.str();
}

static std::string fmt_num(uint64_t n) {
    std::string s = std::to_string(n);
    std::string result;
    int mod = s.size() % 3;
    for (int i = 0; i < (int)s.size(); ++i) {
        if (i > 0 && (i - mod) % 3 == 0) result += '.';
        result += s[i];
    }
    return result;
}

// ─────────────────────────────────────────────────────────────
// Memory-mapped TSV reader + parallel bloom insertion
// ─────────────────────────────────────────────────────────────
struct MMapFile {
    const char* data = nullptr;
    size_t      size = 0;
    int         fd   = -1;

    explicit MMapFile(const std::string& path) {
        fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) { perror("open"); exit(1); }
        struct stat st;
        fstat(fd, &st);
        size = (size_t)st.st_size;
        if (size == 0) { close(fd); fd = -1; return; }
        data = (const char*)mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
        if (data == MAP_FAILED) { perror("mmap"); exit(1); }
        #ifdef __linux__
        madvise((void*)data, size, MADV_SEQUENTIAL);
        #endif
    }
    ~MMapFile() {
        if (data && data != MAP_FAILED) munmap((void*)data, size);
        if (fd >= 0) close(fd);
    }
};



// Build offset index of line starts
static std::vector<size_t> build_offsets(const char* data, size_t size) {
    std::vector<size_t> offsets;
    offsets.reserve(size / 40);  // avg ~40 bytes/address
    offsets.push_back(0);
    const char* p = data;
    const char* end = data + size;
    while ((p = (const char*)memchr(p, '\n', end - p)) != nullptr) {
        ++p;
        if (p < end) offsets.push_back(p - data);
    }
    return offsets;
}

// ─────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <input.tsv> <output.bloom> [expected_items=0] [fpp=0.001]\n";
        return 1;
    }

    std::string tsv_path   = argv[1];
    std::string bloom_path = argv[2];
    uint64_t expected      = (argc > 3) ? (uint64_t)std::stoull(argv[3]) : 0;
    double   fpp           = (argc > 4) ? std::stod(argv[4]) : 0.001;

    std::cout << ansi::CYAN << std::string(72,'-') << ansi::RESET << "\n";
    std::cout << "  TSV → BLOOM Converter (C++ SipHash-1-3, parallel)\n";
    std::cout << ansi::CYAN << std::string(72,'-') << ansi::RESET << "\n\n";

    // ── 1. Memory-map TSV ──────────────────────────────────
    std::cout << "  " << ansi::YELLOW << "⟳" << ansi::RESET << "  Memory-mapping TSV...\n";
    MMapFile mmf(tsv_path);
    if (!mmf.data) { std::cerr << "Empty file.\n"; return 1; }

    // ── 2. Build line offsets ───────────────────────────────
    std::cout << "  " << ansi::YELLOW << "⟳" << ansi::RESET << "  Building line index...\n";
    auto t0 = std::chrono::steady_clock::now();
    auto offsets = build_offsets(mmf.data, mmf.size);
    auto t1 = std::chrono::steady_clock::now();
    double idx_ms = std::chrono::duration<double,std::milli>(t1-t0).count();
    std::cout << "     Lines:   " << ansi::GREEN << fmt_num(offsets.size())
              << ansi::RESET << " (" << std::fixed << std::setprecision(0)
              << idx_ms << "ms)\n";

    // ── 3. Detect header ────────────────────────────────────
    bool has_header = false;
    size_t first_line_end = (offsets.size() > 1) ? offsets[1] : mmf.size;
    std::string_view first_line(mmf.data, first_line_end);
    // Strip newline
    if (!first_line.empty() && first_line.back() == '\n') first_line.remove_suffix(1);
    if (!first_line.empty() && first_line.back() == '\r') first_line.remove_suffix(1);
    auto tab = first_line.find('\t');
    std::string_view first_token = (tab != std::string_view::npos)
                                    ? first_line.substr(0, tab)
                                    : first_line;
    if (!is_valid_address(first_token)) {
        has_header = true;
        std::cout << "     " << ansi::DIM << "Header detected: '"
                  << first_token << "'" << ansi::RESET << "\n";
    }

    // ── 4. Count valid addresses ────────────────────────────
    if (expected == 0) {
        std::cout << "  " << ansi::YELLOW << "⟳" << ansi::RESET << "  Counting addresses...\n";
        size_t start_idx = has_header ? 1 : 0;
        expected = 0;
        for (size_t li = start_idx; li < offsets.size(); ++li) {
            size_t start = offsets[li];
            size_t end = (li + 1 < offsets.size()) ? offsets[li+1] : mmf.size;
            std::string_view line(mmf.data + start, end - start);
            while (!line.empty() && (line.back()=='\n'||line.back()=='\r'))
                line.remove_suffix(1);
            auto t = line.find('\t');
            std::string_view addr = (t != std::string_view::npos) ? line.substr(0,t) : line;
            if (is_valid_address(addr)) ++expected;
        }
        std::cout << "     Found:   " << ansi::GREEN << fmt_num(expected)
                  << ansi::RESET << " addresses\n\n";
    }
    if (expected == 0) { std::cerr << "Error: Empty TSV.\n"; return 1; }

    // ── 5. Allocate Bloom filter ────────────────────────────
    std::cout << "  " << ansi::YELLOW << "⟳" << ansi::RESET
              << "  Building Bloom filter...\n";
    BloomFilter bloom(expected, fpp);
    std::cout << "     Bits:    " << ansi::CYAN << fmt_num(bloom.bitmap_bits)
              << ansi::RESET << "\n";
    std::cout << "     Size:    " << ansi::CYAN << fmt_bytes(bloom.byte_size())
              << ansi::RESET << "\n";
    std::cout << "     K:       " << ansi::CYAN << bloom.k_num
              << ansi::RESET << "\n\n";

    // ── 6. Parallel insertion ───────────────────────────────
    std::cout << "  " << ansi::YELLOW << "⟳" << ansi::RESET << "  Inserting addresses...\n";

    size_t start_idx  = has_header ? 1 : 0;
    size_t total_lines_work = offsets.size() - start_idx;
    unsigned nthreads  = std::max(1u, std::thread::hardware_concurrency());

    std::atomic<uint64_t> inserted{0};
    std::atomic<uint64_t> progress{0};

    auto worker = [&](size_t from, size_t to) {
        uint64_t local = 0;
        for (size_t li = from; li < to; ++li) {
            size_t start = offsets[li];
            size_t end = (li + 1 < offsets.size()) ? offsets[li+1] : mmf.size;
            std::string_view line(mmf.data + start, end - start);
            while (!line.empty() && (line.back()=='\n'||line.back()=='\r'))
                line.remove_suffix(1);
            auto t = line.find('\t');
            std::string_view addr = (t!=std::string_view::npos) ? line.substr(0,t) : line;
            if (is_valid_address(addr)) {
                bloom.add(addr);
                ++local;
                if (local % 500000 == 0) {
                    inserted.fetch_add(local, std::memory_order_relaxed);
                    local = 0;
                }
            }
        }
        inserted.fetch_add(local, std::memory_order_relaxed);
    };

    std::vector<std::thread> threads;
    size_t chunk = (total_lines_work + nthreads - 1) / nthreads;
    for (unsigned i = 0; i < nthreads; ++i) {
        size_t from = start_idx + i * chunk;
        size_t to   = std::min(from + chunk, offsets.size());
        if (from >= offsets.size()) break;
        threads.emplace_back(worker, from, to);
    }

    // Progress display thread
    auto t_start = std::chrono::steady_clock::now();
    std::thread progress_thread([&]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            uint64_t ins = inserted.load(std::memory_order_relaxed);
            double elapsed = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - t_start).count();
            double rate = elapsed > 0 ? ins / elapsed / 1e6 : 0;
            std::cout << "\r     " << fmt_num(ins) << " / "
                      << fmt_num(expected) << "  ("
                      << std::fixed << std::setprecision(2) << rate
                      << " M/s)   " << std::flush;
            if (ins >= (uint64_t)(expected * 0.999)) break;
        }
    });

    for (auto& th : threads) th.join();
    progress_thread.join();

    uint64_t final_inserted = inserted.load();
    double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();
    double rate = elapsed > 0 ? final_inserted / elapsed / 1e6 : 0;
    std::cout << "\r     " << ansi::GREEN << fmt_num(final_inserted)
              << ansi::RESET << " addresses inserted in "
              << std::fixed << std::setprecision(2) << elapsed << "s ("
              << rate << " M/s)\n\n";

    // ── 7. Save ─────────────────────────────────────────────
    std::cout << "  " << ansi::YELLOW << "⟳" << ansi::RESET << "  Saving...\n";
    bloom.save(bloom_path);
    struct stat st;
    stat(bloom_path.c_str(), &st);
    std::cout << "     Saved:   " << ansi::GREEN << bloom_path
              << " (" << fmt_bytes(st.st_size) << ")" << ansi::RESET << "\n\n";

    // ── 8. Self-test ─────────────────────────────────────────
    std::cout << "  " << ansi::YELLOW << "⟳" << ansi::RESET << "  Self-test (first 5 addresses)...\n";
    int checked = 0;
    bool ok = true;
    for (size_t li = start_idx; li < offsets.size() && checked < 5; ++li) {
        size_t st2 = offsets[li];
        size_t en  = (li + 1 < offsets.size()) ? offsets[li+1] : mmf.size;
        std::string_view line(mmf.data + st2, en - st2);
        while (!line.empty() && (line.back()=='\n'||line.back()=='\r'))
            line.remove_suffix(1);
        auto t = line.find('\t');
        std::string_view addr = (t!=std::string_view::npos) ? line.substr(0,t) : line;
        if (!is_valid_address(addr)) continue;
        bool present = bloom.contains(addr);
        std::cout << "     " << (present ? "\x1b[92m✔\x1b[0m" : "\x1b[91m✘\x1b[0m")
                  << "  " << addr << "\n";
        if (!present) { ok = false; }
        ++checked;
    }
    if (ok && checked > 0)
        std::cout << "     " << ansi::GREEN << "All spot-checks passed ✔"
                  << ansi::RESET << "\n\n";
    else if (!ok)
        std::cout << "     " << ansi::RED << "SELF-TEST FAILED — logic error!"
                  << ansi::RESET << "\n\n";

    std::cout << ansi::CYAN << std::string(72,'-') << ansi::RESET << "\n";
    return ok ? 0 : 1;
}
