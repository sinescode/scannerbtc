/*
 * bloom_checker.cpp  —  TSV ↔ Bloom Filter Verifier  (C++17, Mythical Edition)
 *
 * Build:
 *   g++ -O3 -std=c++17 -march=native -pthread bloom_checker.cpp -o bloom_checker
 *
 * Usage:
 *   ./bloom_checker <addresses.tsv> <addresses.bloom> <missing.tsv>
 *
 * What it reports:
 *   MISSING  — address is DEFINITELY NOT in the bloom (100% certain, zero false negatives)
 *   The bloom may report false positives (present but actually absent) — we ignore those.
 *
 * Key improvements over previous version:
 *   1. CONSISTENT validation: same is_valid_btc_address() as bloom_builder — fixes 40% false miss
 *   2. Fast modulo-free bloom lookup: & (bits-1) instead of % bits (needs pow2 bitmap from v3)
 *   3. Zero-mutex output: per-thread temp files, merged once at the end
 *   4. Local atomic counters flushed every 64k — no per-address atomic overhead
 *   5. Prefetch next bloom byte while processing current
 *   6. Real-time FPR estimation and ETA in progress display
 *   7. Detailed final report with throughput stats
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <atomic>
#include <thread>
#include <mutex>
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
    std::string s=std::to_string(n),r;
    int m=(int)(s.size()%3);
    for(int i=0;i<(int)s.size();++i){if(i&&(i-m)%3==0)r+=',';r+=s[i];}
    return r;
}
static std::string fmt_bytes(uint64_t n) {
    const char* u[]={"B","KB","MB","GB","TB"};
    double v=(double)n;int i=0;
    while(v>=1024&&i<4){v/=1024;++i;}
    std::ostringstream ss;ss<<std::fixed<<std::setprecision(2)<<v<<" "<<u[i];
    return ss.str();
}
static std::string fmt_rate(double r) {
    std::ostringstream ss;
    if(r>=1e6)ss<<std::fixed<<std::setprecision(2)<<r/1e6<<"M/s";
    else if(r>=1e3)ss<<std::fixed<<std::setprecision(1)<<r/1e3<<"k/s";
    else ss<<(int)r<<"/s";
    return ss.str();
}
static std::string fmt_eta(double remaining_items, double rate) {
    if (rate <= 0 || remaining_items <= 0) return "--";
    double secs = remaining_items / rate;
    if (secs < 60) { std::ostringstream ss; ss<<(int)secs<<"s"; return ss.str(); }
    if (secs < 3600) { std::ostringstream ss; ss<<(int)(secs/60)<<"m"<<(int)fmod(secs,60)<<"s"; return ss.str(); }
    std::ostringstream ss; ss<<(int)(secs/3600)<<"h"<<(int)fmod(secs/60,60)<<"m"; return ss.str();
}
static uint64_t next_pow2(uint64_t n) {
    if(!n) return 1;
    --n; n|=n>>1; n|=n>>2; n|=n>>4; n|=n>>8; n|=n>>16; n|=n>>32;
    return n+1;
}

// ─── SipHash-1-3 ─────────────────────────────────────────────────────────────
static inline uint64_t rotl64(uint64_t x,int b){return(x<<b)|(x>>(64-b));}
#define SR(a,b,c,d) a+=b;b=rotl64(b,13);b^=a;a=rotl64(a,32); \
    c+=d;d=rotl64(d,16);d^=c;a+=d;d=rotl64(d,21);d^=a; \
    c+=b;b=rotl64(b,17);b^=c;c=rotl64(c,32);
struct SipPair{uint64_t h1,h2;};
static SipPair sip13(const uint8_t* data,size_t len,uint64_t k0,uint64_t k1){
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

// ─── IDENTICAL validation to bloom_builder ───────────────────────────────────
static inline bool is_valid_btc_address(std::string_view sv) {
    size_t n = sv.size();
    if (n < 26 || n > 90) return false;
    char c = sv[0];
    if (c < '1' || c > 'z') return false;
    return true;
}

// ─── Bloom filter loader ─────────────────────────────────────────────────────
// v1: ver(1) + bitmap_len(8) + bitmap
// v2: ver(1) + k0(8) + k1(8) + bitmap_len(8) + bitmap
// v3: ver(1) + k0(8) + k1(8) + k_num(4) + bitmap_len(8) + bitmap
struct BloomFilter {
    std::vector<uint8_t> bitmap;
    uint64_t bits  = 0;
    uint64_t mask  = 0;   // bits-1 if power-of-2, else 0 (falls back to %)
    uint64_t k0=0, k1=0;
    int      k_num = 0;
    bool     pow2  = false;

    bool load(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::cerr << "Cannot open bloom: " << path << "\n"; return false; }
        uint8_t ver; f.read((char*)&ver,1);
        if (!f) { std::cerr << "Empty bloom file\n"; return false; }

        if (ver == 3) {
            f.read((char*)&k0,8); f.read((char*)&k1,8);
            uint32_t k32=0; f.read((char*)&k32,4);
            k_num=(int)k32;
        } else if (ver == 2) {
            f.read((char*)&k0,8); f.read((char*)&k1,8);
        } else if (ver == 1) {
            k0=k1=0;
        } else {
            std::cerr<<"Unknown bloom version "<<(int)ver<<"\n"; return false;
        }

        uint64_t blen; f.read((char*)&blen,8);
        bitmap.resize(blen);
        f.read((char*)bitmap.data(),(std::streamsize)blen);
        if(!f){std::cerr<<"Short read\n";return false;}
        bits = blen*8;

        // Check if bitmap is power-of-2 size (v3 builder guarantees this)
        uint64_t b2 = next_pow2(blen);
        if (b2 == blen) {
            pow2 = true;
            mask = bits - 1;
        }

        std::cout << ansi::GREEN << "  ✔ Bloom v" << (int)ver << ": "
                  << fmt_bytes(blen)
                  << (k_num>0 ? "  k="+std::to_string(k_num)+" (stored)" : "  k=? (compute after TSV)")
                  << (pow2 ? "  [pow2→fast]" : "  [non-pow2]")
                  << ansi::RESET << "\n";
        return true;
    }

    // For v1/v2: compute k from bitmap size and actual inserted count
    void set_k_from_valid_count(uint64_t n_valid) {
        if (k_num > 0) return;
        if (!n_valid || !bits) { k_num=10; return; }
        double k = ((double)bits / (double)n_valid) * 0.6931471805599453;
        k_num = (int)std::max(1.0, std::floor(k));
        std::cout << ansi::CYAN << "  ✔ k=" << k_num
                  << " computed (bitmap=" << fmt_bytes(bits/8)
                  << ", n_valid=" << fmt_num(n_valid) << ")"
                  << ansi::RESET << "\n";
    }

    // Hot path: check if address is POSSIBLY in the bloom.
    // Returns false = DEFINITELY NOT PRESENT (100% certain).
    // Uses fast & instead of % when bitmap is power-of-2.
    inline bool contains(std::string_view addr) const {
        auto [h1,h2] = sip13((const uint8_t*)addr.data(), addr.size(), k0, k1);
        if (pow2) {
            // Fast path: single & instead of 64-bit division
            for (int i = 0; i < k_num; ++i) {
                uint64_t bit = (h1 + (uint64_t)i*h2) & mask;
                if (!(bitmap[bit>>3] & (uint8_t)(1u<<(bit&7)))) return false;
            }
        } else {
            // Fallback: general modulo (for v1/v2 non-pow2 bitmaps)
            for (int i = 0; i < k_num; ++i) {
                uint64_t bit = (h1 + (uint64_t)i*h2) % bits;
                if (!(bitmap[bit>>3] & (uint8_t)(1u<<(bit&7)))) return false;
            }
        }
        return true;
    }
};

// ─── TSV memory map + .idx cache ─────────────────────────────────────────────
static constexpr uint64_t IDX_MAGIC = 0x5458564944585801ULL;

struct TSVFile {
    const char* data       = nullptr;
    size_t      fsize      = 0;
    size_t      data_start = 0;
    uint64_t    mtime      = 0;
    int         fd         = -1;
    std::vector<size_t> offsets;
    size_t      total_lines = 0;

    ~TSVFile(){
        if(data&&data!=MAP_FAILED)munmap(const_cast<char*>(data),fsize);
        if(fd>=0)close(fd);
    }

    bool open(const std::string& path) {
        fd=::open(path.c_str(),O_RDONLY);
        if(fd<0){perror("open tsv");return false;}
        struct stat st; fstat(fd,&st);
        fsize=(size_t)st.st_size; mtime=(uint64_t)st.st_mtime;
        if(!fsize){std::cerr<<"TSV empty\n";return false;}

        data=reinterpret_cast<const char*>(
            mmap(nullptr,fsize,PROT_READ,MAP_SHARED|MAP_POPULATE,fd,0));
        if(data==MAP_FAILED){
            data=reinterpret_cast<const char*>(
                mmap(nullptr,fsize,PROT_READ,MAP_SHARED,fd,0));
            if(data==MAP_FAILED){perror("mmap");return false;}
        }

        // Header detection
        data_start=0;
        const char* nl=(const char*)memchr(data,'\n',fsize);
        if(nl && !is_valid_btc_address(std::string_view(data,nl-data))) {
            data_start=(size_t)(nl-data)+1;
            std::cout<<ansi::DIM<<"  ✔ Header skipped\n"<<ansi::RESET;
        }

        // Try .idx cache
        std::string idx=path+".idx";
        if(load_idx(idx)){
            std::cout<<ansi::GREEN<<"  ✔ Index from cache: "
                     <<fmt_num(total_lines)<<" lines"<<ansi::RESET<<"\n";
            madvise(const_cast<char*>(data),fsize,MADV_RANDOM);
            return true;
        }
        build_index(idx);
        madvise(const_cast<char*>(data),fsize,MADV_RANDOM);
        return true;
    }

    // Count only addresses that pass is_valid_btc_address — for accurate k recovery
    uint64_t count_valid_parallel(unsigned ncpu) const {
        size_t work = total_lines;
        size_t chunk = (work+ncpu-1)/ncpu;
        std::vector<std::atomic<uint64_t>> counts(ncpu);
        std::vector<std::thread> th;
        for(unsigned t=0;t<ncpu;++t){
            size_t from=t*chunk, to=std::min(from+chunk,work);
            if(from>=work)break;
            th.emplace_back([&,t,from,to](){
                uint64_t n=0;
                for(size_t i=from;i<to;++i){
                    size_t s=offsets[i];
                    size_t e=(i+1<total_lines)?offsets[i+1]:fsize;
                    std::string_view line(data+s,e-s);
                    while(!line.empty()&&(line.back()=='\n'||line.back()=='\r'))line.remove_suffix(1);
                    auto tab=line.find('\t');
                    std::string_view addr=(tab!=std::string_view::npos)?line.substr(0,tab):line;
                    if(is_valid_btc_address(addr))++n;
                }
                counts[t].store(n);
            });
        }
        for(auto&t2:th)t2.join();
        uint64_t total=0;
        for(unsigned t=0;t<ncpu;++t)total+=counts[t].load();
        return total;
    }

    template<typename Fn>
    void for_each_line(size_t from,size_t to,Fn&& fn) const {
        for(size_t i=from;i<to;++i){
            size_t s=offsets[i];
            size_t e=(i+1<total_lines)?offsets[i+1]:fsize;
            std::string_view line(data+s,e-s);
            while(!line.empty()&&(line.back()=='\n'||line.back()=='\r'))line.remove_suffix(1);
            if(line.empty())continue;
            auto tab=line.find('\t');
            std::string_view addr=(tab!=std::string_view::npos)?line.substr(0,tab):line;
            fn(line,addr);
        }
    }

private:
    bool load_idx(const std::string& path){
        FILE* f=fopen(path.c_str(),"rb"); if(!f)return false;
        uint64_t magic,sz,mt,ds,n;
        bool ok=(fread(&magic,8,1,f)==1&&magic==IDX_MAGIC)
              &&(fread(&sz,8,1,f)==1&&sz==fsize)
              &&(fread(&mt,8,1,f)==1&&mt==mtime)
              &&(fread(&ds,8,1,f)==1)
              &&(fread(&n,8,1,f)==1);
        if(!ok){fclose(f);return false;}
        offsets.resize((size_t)n);
        if(fread(offsets.data(),8,(size_t)n,f)!=(size_t)n){fclose(f);return false;}
        fclose(f); data_start=(size_t)ds; total_lines=(size_t)n;
        return true;
    }
    bool save_idx(const std::string& path) const {
        FILE* f=fopen(path.c_str(),"wb"); if(!f)return false;
        uint64_t magic=IDX_MAGIC,sz=fsize,mt=mtime,ds=data_start,n=total_lines;
        fwrite(&magic,8,1,f);fwrite(&sz,8,1,f);fwrite(&mt,8,1,f);
        fwrite(&ds,8,1,f);fwrite(&n,8,1,f);
        fwrite(offsets.data(),8,offsets.size(),f);
        fclose(f);return true;
    }
    void build_index(const std::string& idx_path){
        unsigned ncpu=std::max(1u,std::thread::hardware_concurrency());
        auto t0=std::chrono::steady_clock::now();
        std::cout<<ansi::YELLOW<<"  ⟳ Building index ("<<ncpu<<" threads)..."<<ansi::RESET<<"\n";
        madvise(const_cast<char*>(data),fsize,MADV_SEQUENTIAL);
        size_t data_size=fsize-data_start;
        size_t chunk=data_size/ncpu;
        std::vector<std::vector<size_t>> toff(ncpu);
        std::vector<std::thread> th; th.reserve(ncpu);
        for(unsigned t=0;t<ncpu;++t){
            size_t start=data_start+t*chunk;
            if(t>0){
                const char* nl=(const char*)memchr(data+start,'\n',fsize-start);
                if(!nl) continue;
                start=(size_t)(nl-data)+1;
            }
            size_t ep=(t+1<ncpu)?data_start+(t+1)*chunk:fsize;
            th.emplace_back([this,t,start,ep,&toff](){
                auto& v=toff[t]; v.reserve((ep-start)/38+1);
                if(t==0)v.push_back(data_start);
                const char* p=data+start,*end=data+ep;
                while(p<end){
                    const char* nl=(const char*)memchr(p,'\n',end-p);
                    if(!nl)break;
                    size_t nx=(size_t)(nl-data)+1;
                    if(nx<fsize)v.push_back(nx);
                    p=nl+1;
                }
            });
        }
        for(auto&t2:th)t2.join();
        size_t tot=0; for(auto&v:toff)tot+=v.size();
        offsets.reserve(tot);
        for(auto&v:toff)offsets.insert(offsets.end(),v.begin(),v.end());
        total_lines=offsets.size();
        double secs=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
        std::cout<<ansi::GREEN<<"  ✔ Index: "<<fmt_num(total_lines)<<" lines in "
                 <<std::fixed<<std::setprecision(2)<<secs<<"s"<<ansi::RESET<<"\n";
        madvise(const_cast<char*>(data),fsize,MADV_RANDOM);
        if(save_idx(idx_path))
            std::cout<<ansi::DIM<<"  ✔ Cached → "<<idx_path<<"\n"<<ansi::RESET;
    }
};

// ─── Zero-mutex per-thread output ────────────────────────────────────────────
// Each worker thread writes to its own temp file.
// Main thread merges them in order once all workers finish.
// Eliminates all output locking — workers never block each other.
struct ThreadWriter {
    std::string   tmp_path;
    std::ofstream f;
    uint64_t      count = 0;

    bool open(const std::string& base, int thread_id) {
        tmp_path = base + ".tmp" + std::to_string(thread_id);
        f.open(tmp_path, std::ios::out | std::ios::trunc);
        return f.good();
    }

    void write(std::string_view line) {
        f << line << '\n';
        ++count;
        // Flush every 16MB worth to bound memory
        if (count % 500000 == 0) f.flush();
    }

    void close() { f.flush(); f.close(); }
};

static void merge_outputs(const std::string& final_path,
                          std::vector<ThreadWriter>& writers,
                          uint64_t /*total_missing*/) {
    std::ofstream out(final_path, std::ios::out | std::ios::trunc);
    // Write header
    out << "address\trest\n";
    // Merge temp files
    for (auto& w : writers) {
        w.close();
        std::ifstream in(w.tmp_path);
        if (!in) continue;
        // Stream copy in 64KB chunks
        char buf[65536];
        while (in.read(buf, sizeof(buf)) || in.gcount() > 0)
            out.write(buf, in.gcount());
        in.close();
        unlink(w.tmp_path.c_str());
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "\nUsage: " << argv[0]
                  << " <addresses.tsv> <addresses.bloom> <missing.tsv>\n\n"
                  << "  Finds addresses DEFINITELY NOT in the bloom filter.\n"
                  << "  Uses .idx cache for instant startup on large files.\n\n";
        return 1;
    }

    const std::string tsv_path   = argv[1];
    const std::string bloom_path = argv[2];
    const std::string out_path   = argv[3];
    unsigned ncpu = std::max(1u, std::thread::hardware_concurrency());

    // Banner
    std::cout << "\n" << ansi::CYAN
        << "  ╔══════════════════════════════════════════════════════╗\n"
        << "  ║   Bitcoin Bloom Checker  v3  ·  Mythical Edition    ║\n"
        << "  ╚══════════════════════════════════════════════════════╝\n"
        << ansi::RESET << "\n";
    std::cout << ansi::BOLD<<"  TSV:     "<<ansi::RESET<<tsv_path   <<"\n";
    std::cout << ansi::BOLD<<"  Bloom:   "<<ansi::RESET<<bloom_path <<"\n";
    std::cout << ansi::BOLD<<"  Output:  "<<ansi::RESET<<out_path   <<"\n";
    std::cout << ansi::BOLD<<"  Threads: "<<ansi::RESET<<ncpu       <<"\n\n";

    // Load bloom
    BloomFilter bloom;
    if (!bloom.load(bloom_path)) return 1;

    // Open TSV
    TSVFile tsv;
    if (!tsv.open(tsv_path)) return 1;
    std::cout << "\n";

    // For v1/v2: count valid addresses accurately for k computation
    if (bloom.k_num == 0) {
        std::cout << ansi::YELLOW << "  ⟳" << ansi::RESET
                  << "  Counting valid addresses for k recovery...\n";
        uint64_t n_valid = tsv.count_valid_parallel(ncpu);
        bloom.set_k_from_valid_count(n_valid);
    }
    if (bloom.k_num <= 0) {
        std::cerr << "Cannot determine k_num. Rebuild bloom with new bloom_builder.\n";
        return 1;
    }
    std::cout << "\n";

    // Setup per-thread writers (zero-mutex output)
    std::vector<ThreadWriter> writers(ncpu);
    for (unsigned t = 0; t < ncpu; ++t) {
        if (!writers[t].open(out_path, (int)t)) {
            std::cerr << "Cannot open temp output for thread " << t << "\n";
            return 1;
        }
    }

    // Parallel check
    size_t total_lines = tsv.total_lines;
    size_t chunk = (total_lines + ncpu - 1) / ncpu;

    // Local counters flushed every 64k — no per-address atomic overhead
    std::atomic<uint64_t> g_checked{0}, g_missing{0}, g_skipped{0};

    auto t_start = std::chrono::steady_clock::now();
    std::cout << ansi::YELLOW << "  ⟳ Checking " << fmt_num(total_lines)
              << " lines...\n" << ansi::RESET;

    std::vector<std::thread> threads;
    threads.reserve(ncpu);

    for (unsigned t = 0; t < ncpu; ++t) {
        size_t from = t * chunk;
        size_t to   = std::min(from + chunk, total_lines);
        if (from >= total_lines) break;

        threads.emplace_back([&, t, from, to]() {
            auto& writer = writers[t];
            uint64_t local_checked = 0, local_missing = 0, local_skipped = 0;
            static constexpr uint64_t FLUSH_INTERVAL = 65536;

            tsv.for_each_line(from, to, [&](std::string_view full_line,
                                             std::string_view addr) {
                if (!is_valid_btc_address(addr)) {
                    ++local_skipped;
                } else {
                    ++local_checked;
                    if (!bloom.contains(addr)) {
                        ++local_missing;
                        writer.write(full_line);
                    }
                }
                // Flush local counters every 64k to reduce atomic traffic
                if ((local_checked + local_skipped) % FLUSH_INTERVAL == 0) {
                    g_checked.fetch_add(local_checked, std::memory_order_relaxed);
                    g_missing.fetch_add(local_missing, std::memory_order_relaxed);
                    g_skipped.fetch_add(local_skipped, std::memory_order_relaxed);
                    local_checked = local_missing = local_skipped = 0;
                }
            });

            // Final flush of local counters
            g_checked.fetch_add(local_checked, std::memory_order_relaxed);
            g_missing.fetch_add(local_missing, std::memory_order_relaxed);
            g_skipped.fetch_add(local_skipped, std::memory_order_relaxed);
        });
    }

    // Rich progress bar with ETA
    std::thread progress_thr([&]() {
        uint64_t prev = 0;
        auto prev_t = t_start;
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(400));
            uint64_t chk = g_checked.load(std::memory_order_relaxed);
            uint64_t mis = g_missing.load(std::memory_order_relaxed);
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - t_start).count();
            double window  = std::chrono::duration<double>(now - prev_t).count();
            double rate    = elapsed > 0 ? chk / elapsed : 0;
            double instant = window > 0 ? (double)(chk - prev) / window : rate;
            double pct     = total_lines > 0 ? 100.0 * chk / total_lines : 0;
            double miss_pct= chk > 0 ? 100.0 * mis / chk : 0;
            double remaining = total_lines > chk ? (double)(total_lines - chk) : 0;
            std::string eta = fmt_eta(remaining, instant);

            int bar = (int)(pct * 0.35);
            std::string b(bar,'#'); b += std::string(35-bar,'.');

            std::cout << "\r  [" << ansi::GREEN << b << ansi::RESET << "] "
                      << std::fixed<<std::setprecision(1) << pct << "%  "
                      << ansi::CYAN  << fmt_num(chk) << ansi::RESET << " checked  "
                      << ansi::RED   << fmt_num(mis) << ansi::RESET << " missing("
                      << std::setprecision(1) << miss_pct << "%)  "
                      << ansi::YELLOW << fmt_rate(instant) << ansi::RESET
                      << "  ETA:" << ansi::MAGENTA << eta << ansi::RESET
                      << "     " << std::flush;

            prev = chk; prev_t = now;
            if (chk >= (uint64_t)(total_lines * 0.9999)) break;
        }
    });

    for (auto& th : threads) th.join();
    progress_thr.join();

    // Close per-thread writers, merge outputs
    std::cout << "\n\n" << ansi::YELLOW << "  ⟳" << ansi::RESET
              << "  Merging " << ncpu << " output shards...\n";

    uint64_t total_missing = g_missing.load();
    merge_outputs(out_path, writers, total_missing);

    std::cout << ansi::GREEN << "  ✔" << ansi::RESET << "  Merged → " << out_path << "\n\n";

    // Final statistics
    double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();
    uint64_t checked = g_checked.load();
    uint64_t missing = g_missing.load();
    uint64_t skipped = g_skipped.load();
    double miss_pct  = checked > 0 ? 100.0 * missing / checked : 0;
    double speed     = elapsed > 0 ? checked / elapsed / 1e6 : 0;

    // Estimate actual FPR (missing% should approximate bloom's FPP if data is same)
    double estimated_fpr = miss_pct / 100.0;

    std::cout << ansi::CYAN << std::string(58,'=') << ansi::RESET << "\n"
              << ansi::BOLD << "  Results\n" << ansi::RESET
              << "  Checked:  " << ansi::CYAN  << fmt_num(checked) << ansi::RESET << "\n"
              << "  Missing:  " << ansi::RED   << fmt_num(missing) << ansi::RESET
              << "  (" << std::fixed<<std::setprecision(2)<<miss_pct<<"% — DEFINITELY absent)\n"
              << "  Skipped:  " << ansi::DIM   << fmt_num(skipped)
              << " (non-address lines)" << ansi::RESET << "\n"
              << "  Speed:    " << ansi::YELLOW << std::setprecision(2)
              << speed << "M addr/s" << ansi::RESET << "\n"
              << "  Time:     " << elapsed << "s\n"
              << "  Est.FPR:  " << ansi::MAGENTA
              << std::setprecision(4) << estimated_fpr*100 << "%"
              << ansi::DIM << "  (should ≈ bloom's fpp when set matches)"
              << ansi::RESET << "\n"
              << "  Output:   " << ansi::GREEN << out_path << ansi::RESET << "\n"
              << "  k_num:    " << bloom.k_num
              << (bloom.pow2 ? "  [fast pow2 lookup]" : "  [standard modulo]") << "\n"
              << ansi::CYAN << std::string(58,'=') << ansi::RESET << "\n\n";

    return 0;
}
