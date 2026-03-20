/*
 * scanner.cpp — Bitcoin Address Scanner (C++17, High-Performance)
 *
 * WHAT IT DOES (matching Python scanner.py):
 *  - Generates Bitcoin private keys (random / mnemonic BIP-39 / mix mode)
 *  - Derives all 5 address types per key:
 *      P2PKH   (1...)  — BIP-44
 *      P2SH    (3...)  — BIP-49 wrapped-segwit
 *      P2WPKH  (bc1q.) — BIP-84 native segwit v0
 *      P2WSH   (bc1q.) — BIP-84, single-key P2WSH script
 *      P2TR    (bc1p.) — BIP-86 Taproot (segwit v1)
 *  - Checks each address against a HybridFilter (Bloom + binary search)
 *  - Reports hits + live speed stats every second
 *  - Logs hits to TSV file
 *  - Worker threads (one per CPU core by default)
 *
 * IMPROVEMENTS vs Python version:
 *  - Pure C++ crypto (secp256k1 via libsecp256k1, SHA-256/RIPEMD160 via
 *    OpenSSL, PBKDF2 via OpenSSL).
 *  - No GIL — true parallel threads, not forked processes.
 *  - Binary search on memory-mapped TSV for O(log n) exact match.
 *  - SipHash-1-3 bloom check: same algorithm, ~5x faster.
 *  - Atomic counters replace IPC queues.
 *
 * Dependencies:
 *   apt install libsecp256k1-dev libssl-dev
 *
 * Build:
 *   g++ -O3 -std=c++17 -march=native -pthread \
 *       scanner.cpp -o scanner \
 *       -lsecp256k1 -lssl -lcrypto
 *
 * Usage:
 *   ./scanner [options]
 *   --tsv       addresses.tsv      (sorted TSV of target addresses)
 *   --bloom     addresses.bloom    (bloom filter built by bloom_builder)
 *   --output    hits.tsv           (output file for matches)
 *   --threads   N                  (default: nproc)
 *   --mode      random|mix         (key generation mode)
 *   --debug                        (verbose output)
 *
 * NOTE on Mnemonic/BIP-39:
 *   Full BIP-39 word list + PBKDF2 is included.  Mnemonic mode generates
 *   12-word mnemonics from the embedded English word list.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Standard headers
// ─────────────────────────────────────────────────────────────────────────────
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
#include <mutex>
#include <vector>
#include <array>
#include <string>
#include <string_view>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <random>
#include <ctime>
#include <signal.h>

// OpenSSL
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// secp256k1
#include <secp256k1.h>

// BIP-39 word list
#include "bip39_wordlist.hpp"

// PostgreSQL (optional — compile with -DWITH_PG -lpq to enable)
#ifdef WITH_PG
#  include <libpq-fe.h>
#endif

// ─────────────────────────────────────────────────────────────────────────────
// ANSI
// ─────────────────────────────────────────────────────────────────────────────
namespace ansi {
    constexpr const char* RESET   = "\x1b[0m";
    constexpr const char* CYAN    = "\x1b[96m";
    constexpr const char* YELLOW  = "\x1b[93m";
    constexpr const char* GREEN   = "\x1b[92m";
    constexpr const char* RED     = "\x1b[91m";
    constexpr const char* MAGENTA = "\x1b[95m";
    constexpr const char* BLUE    = "\x1b[94m";
    constexpr const char* DIM     = "\x1b[2m";
    constexpr const char* BOLD    = "\x1b[1m";
}

// ─────────────────────────────────────────────────────────────────────────────
// Global secp256k1 context (one per process, shared by all threads read-only)
// ─────────────────────────────────────────────────────────────────────────────
static secp256k1_context* g_secp = nullptr;

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256 / RIPEMD-160 / Hash160
// ─────────────────────────────────────────────────────────────────────────────
using Bytes20 = std::array<uint8_t,20>;
using Bytes32 = std::array<uint8_t,32>;
using Bytes33 = std::array<uint8_t,33>;

static Bytes32 sha256(const uint8_t* data, size_t len) {
    Bytes32 out;
    SHA256(data, len, out.data());
    return out;
}
static Bytes32 sha256(const Bytes32& in) {
    return sha256(in.data(), 32);
}

static Bytes20 ripemd160(const uint8_t* data, size_t len) {
    Bytes20 out;
    // Use EVP API (OpenSSL 3.x compatible, avoids deprecation warning)
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_ripemd160();
    unsigned int outlen = 20;
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out.data(), &outlen);
    EVP_MD_CTX_free(ctx);
    return out;
}

static Bytes20 hash160(const uint8_t* data, size_t len) {
    Bytes32 h = sha256(data, len);
    return ripemd160(h.data(), 32);
}
static Bytes20 hash160(const Bytes33& pub) {
    return hash160(pub.data(), 33);
}

// ─────────────────────────────────────────────────────────────────────────────
// Base58Check
// ─────────────────────────────────────────────────────────────────────────────
static const char B58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static std::string base58check_encode(const uint8_t* payload, size_t len) {
    // checksum = sha256(sha256(payload))[0:4]
    Bytes32 h1 = sha256(payload, len);
    Bytes32 h2 = sha256(h1);

    std::vector<uint8_t> buf(payload, payload + len);
    buf.push_back(h2[0]); buf.push_back(h2[1]);
    buf.push_back(h2[2]); buf.push_back(h2[3]);

    // Count leading zeros
    int leading = 0;
    for (uint8_t b : buf) { if (b == 0) ++leading; else break; }

    // Big-number base58 conversion
    std::vector<uint8_t> digits;
    for (uint8_t byte : buf) {
        int carry = byte;
        for (auto& d : digits) {
            carry += 256 * d;
            d = carry % 58;
            carry /= 58;
        }
        while (carry) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }

    std::string result(leading, '1');
    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
        result += B58_ALPHABET[*it];
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Bech32 / Bech32m (BIP-173 / BIP-350)
// ─────────────────────────────────────────────────────────────────────────────
static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const uint32_t BECH32_GEN[] = {
    0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
};
static const uint32_t BECH32_CONST  = 1;
static const uint32_t BECH32M_CONST = 0x2bc830a3;

static uint32_t bech32_polymod(const std::vector<uint8_t>& values) {
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; ++i)
            if ((top >> i) & 1) chk ^= BECH32_GEN[i];
    }
    return chk;
}

static std::vector<uint8_t> bech32_hrp_expand(const std::string& hrp) {
    std::vector<uint8_t> ret;
    for (char c : hrp) ret.push_back((uint8_t)c >> 5);
    ret.push_back(0);
    for (char c : hrp) ret.push_back((uint8_t)c & 31);
    return ret;
}

static std::vector<uint8_t> bech32_create_checksum(
    const std::string& hrp,
    const std::vector<uint8_t>& data,
    bool bech32m)
{
    auto values = bech32_hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    for (int i = 0; i < 6; ++i) values.push_back(0);
    uint32_t polymod = bech32_polymod(values) ^ (bech32m ? BECH32M_CONST : BECH32_CONST);
    std::vector<uint8_t> checksum(6);
    for (int i = 0; i < 6; ++i)
        checksum[i] = (polymod >> (5 * (5 - i))) & 31;
    return checksum;
}

// Convert 8-bit bytes -> 5-bit groups
static std::vector<uint8_t> convertbits_8to5(const uint8_t* data, size_t len) {
    int acc = 0, bits = 0;
    std::vector<uint8_t> ret;
    constexpr int maxv = (1 << 5) - 1;
    for (size_t i = 0; i < len; ++i) {
        acc = (acc << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            ret.push_back((acc >> bits) & maxv);
        }
    }
    if (bits) ret.push_back((acc << (5 - bits)) & maxv);
    return ret;
}

static std::string encode_segwit(const std::string& hrp, int witver,
                                  const uint8_t* witprog, size_t proglen) {
    bool bech32m = (witver >= 1);
    std::vector<uint8_t> data = {(uint8_t)witver};
    auto conv = convertbits_8to5(witprog, proglen);
    data.insert(data.end(), conv.begin(), conv.end());
    auto chk = bech32_create_checksum(hrp, data, bech32m);
    data.insert(data.end(), chk.begin(), chk.end());
    std::string result = hrp + "1";
    for (uint8_t d : data) result += BECH32_CHARSET[d];
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// secp256k1 helpers
// ─────────────────────────────────────────────────────────────────────────────
static bool privkey_to_pubkey_compressed(const uint8_t priv[32], Bytes33& out) {
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(g_secp, &pk, priv)) return false;
    size_t outlen = 33;
    secp256k1_ec_pubkey_serialize(g_secp, out.data(), &outlen, &pk,
                                   SECP256K1_EC_COMPRESSED);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// BIP-340 Tagged Hash (Taproot)
// ─────────────────────────────────────────────────────────────────────────────
static Bytes32 tagged_hash(const char* tag, const uint8_t* data, size_t dlen) {
    Bytes32 tag_hash = sha256((const uint8_t*)tag, strlen(tag));
    // sha256(tag_hash || tag_hash || data) using EVP (OpenSSL 3.x compatible)
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    unsigned int outlen = 32;
    Bytes32 out;
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, tag_hash.data(), 32);
    EVP_DigestUpdate(ctx, tag_hash.data(), 32);
    EVP_DigestUpdate(ctx, data, dlen);
    EVP_DigestFinal_ex(ctx, out.data(), &outlen);
    EVP_MD_CTX_free(ctx);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Address generation structures
// ─────────────────────────────────────────────────────────────────────────────
struct KeyData {
    uint8_t  priv[32];
    Bytes33  compressed_pub;    // 33 bytes, 02/03 prefix
    uint8_t  xonly_pub[32];     // 32 bytes, x-only for Taproot
    std::string wif;
    std::string priv_hex;
    std::string compressed_pub_hex;
    std::string xonly_pub_hex;
    // All 5 addresses
    std::string p2pkh;
    std::string p2sh_p2wpkh;
    std::string p2wpkh;
    std::string p2wsh;
    std::string p2tr;
};

static std::string to_hex(const uint8_t* d, size_t n) {
    static const char hex[] = "0123456789abcdef";
    std::string s(n*2, 0);
    for (size_t i=0;i<n;++i) {
        s[2*i]   = hex[d[i]>>4];
        s[2*i+1] = hex[d[i]&0xf];
    }
    return s;
}

static std::string privkey_to_wif(const uint8_t priv[32]) {
    uint8_t buf[34];
    buf[0] = 0x80;
    memcpy(buf+1, priv, 32);
    buf[33] = 0x01;  // compressed
    return base58check_encode(buf, 34);
}

static std::string pubkey_to_p2pkh(const Bytes33& pub) {
    Bytes20 h = hash160(pub);
    uint8_t buf[21]; buf[0] = 0x00;
    memcpy(buf+1, h.data(), 20);
    return base58check_encode(buf, 21);
}

static std::string pubkey_to_p2sh_p2wpkh(const Bytes33& pub) {
    Bytes20 h = hash160(pub);
    // redeemScript = OP_0 <20-byte-hash>
    uint8_t script[22]; script[0] = 0x00; script[1] = 0x14;
    memcpy(script+2, h.data(), 20);
    Bytes20 sh = hash160(script, 22);
    uint8_t buf[21]; buf[0] = 0x05;
    memcpy(buf+1, sh.data(), 20);
    return base58check_encode(buf, 21);
}

static std::string pubkey_to_p2wpkh(const Bytes33& pub) {
    Bytes20 h = hash160(pub);
    return encode_segwit("bc", 0, h.data(), 20);
}

static std::string pubkey_to_p2wsh(const Bytes33& pub) {
    // Script: <pubkey> OP_CHECKSIG
    std::vector<uint8_t> script;
    script.push_back((uint8_t)pub.size());  // push 33 bytes
    script.insert(script.end(), pub.begin(), pub.end());
    script.push_back(0xac);  // OP_CHECKSIG
    Bytes32 h = sha256(script.data(), script.size());
    return encode_segwit("bc", 0, h.data(), 32);
}

// Portable BIP-32 scalar tweak: avoids all deprecated/renamed secp256k1 API variants.
static bool sec_key_tweak_add(const secp256k1_context* ctx, uint8_t* key, const uint8_t* tweak) {
    // Portable modular addition: Result = (key + tweak) mod n  [secp256k1 curve order]
    static const uint8_t ORDER[32] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
        0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,
        0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
    };
    // Add tweak to key (big-endian 256-bit addition)
    uint8_t result[32];
    int carry = 0;
    for (int i = 31; i >= 0; --i) {
        int sum = (int)key[i] + (int)tweak[i] + carry;
        result[i] = (uint8_t)(sum & 0xff);
        carry = sum >> 8;
    }
    // Reduce mod n if result >= n
    // If carry==1, result overflowed 256 bits → definitely >= ORDER, must subtract
    bool ge = (carry != 0);
    if (!ge) {
        for (int i = 0; i < 32; ++i) {
            if (result[i] > ORDER[i]) { ge = true; break; }
            if (result[i] < ORDER[i]) break;
        }
    }
    if (ge) {
        // result -= ORDER
        int borrow = 0;
        for (int i = 31; i >= 0; --i) {
            int diff = (int)result[i] - (int)ORDER[i] - borrow;
            if (diff < 0) { diff += 256; borrow = 1; } else borrow = 0;
            result[i] = (uint8_t)diff;
        }
    }
    // Check result != 0
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) if (result[i]) { all_zero = false; break; }
    if (all_zero) return false;
    memcpy(key, result, 32);
    // Verify the result is a valid key
    return secp256k1_ec_seckey_verify(ctx, key);
}


// Taproot P2TR — BIP-340 + BIP-341
// Returns address and sets xonly_out[32]
// Implementation uses only the base secp256k1 API (no extrakeys module needed).
// x-only pubkey = first 32 bytes of a 33-byte compressed pubkey.
static std::string privkey_to_p2tr(const uint8_t priv[32], uint8_t xonly_out[32]) {
    // 1. Get compressed public key (33 bytes)
    uint8_t pub33[33];
    {
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_create(g_secp, &pk, priv)) return "";
        size_t outlen = 33;
        secp256k1_ec_pubkey_serialize(g_secp, pub33, &outlen, &pk, SECP256K1_EC_COMPRESSED);
    }

    // 2. Extract x-only internal key (bytes 1..32 of compressed pubkey)
    memcpy(xonly_out, pub33 + 1, 32);

    // 3. If odd parity (prefix == 0x03), negate private key so we work with
    //    the even-Y variant (BIP-340 requirement for internal key)
    uint8_t priv_even[32];
    memcpy(priv_even, priv, 32);
    if (pub33[0] == 0x03) {
        // Negate private key: secp256k1_ec_seckey_negate (old name: privkey_negate)
        // Both names exist depending on library version; use the pubkey_negate
        // workaround that's always available: negate = order - key
        // We do it manually: negated = n - key (mod n)
        // secp256k1 order n:
        static const uint8_t ORDER[32] = {
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
            0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,
            0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
        };
        // Compute n - key using big-endian subtraction
        int borrow = 0;
        for (int i = 31; i >= 0; --i) {
            int diff = (int)ORDER[i] - (int)priv_even[i] - borrow;
            if (diff < 0) { diff += 256; borrow = 1; } else borrow = 0;
            priv_even[i] = (uint8_t)diff;
        }
        // Recompute xonly from negated key (x-coord is the same, but confirm)
        secp256k1_pubkey pk2;
        if (!secp256k1_ec_pubkey_create(g_secp, &pk2, priv_even)) return "";
        uint8_t pub2[33]; size_t l2 = 33;
        secp256k1_ec_pubkey_serialize(g_secp, pub2, &l2, &pk2, SECP256K1_EC_COMPRESSED);
        memcpy(xonly_out, pub2 + 1, 32);
    }

    // 4. TapTweak: t = tagged_hash("TapTweak", xonly_internal)
    Bytes32 tweak = tagged_hash("TapTweak", xonly_out, 32);

    // 5. Compute tweaked private key: d' = (d + t) mod n
    //    secp256k1_ec_seckey_tweak_add is the modern name; older = privkey_tweak_add
    uint8_t tweaked_priv[32];
    memcpy(tweaked_priv, priv_even, 32);
    if (!sec_key_tweak_add(g_secp, tweaked_priv, tweak.data())) {
        return "";
    }

    // 6. Derive tweaked public key and extract x-coordinate
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_ec_pubkey_create(g_secp, &tweaked_pk, tweaked_priv)) return "";
    uint8_t tweaked_pub33[33]; size_t tlen = 33;
    secp256k1_ec_pubkey_serialize(g_secp, tweaked_pub33, &tlen, &tweaked_pk,
                                   SECP256K1_EC_COMPRESSED);

    // 7. x-only tweaked OUTPUT key = bytes 1..32
    //    This is also stored as xonly_out — it's the key that corresponds
    //    to the P2TR address and is needed to verify the address.
    //    (Previously this stored the INTERNAL key, which is wrong.)
    memcpy(xonly_out, tweaked_pub33 + 1, 32);

    return encode_segwit("bc", 1, xonly_out, 32);
}

static bool fill_key_data(const uint8_t priv[32], KeyData& kd) {
    memcpy(kd.priv, priv, 32);

    if (!privkey_to_pubkey_compressed(priv, kd.compressed_pub)) return false;

    kd.wif            = privkey_to_wif(priv);
    kd.priv_hex       = to_hex(priv, 32);
    kd.compressed_pub_hex = to_hex(kd.compressed_pub.data(), 33);

    kd.p2tr = privkey_to_p2tr(priv, kd.xonly_pub);
    kd.xonly_pub_hex = to_hex(kd.xonly_pub, 32);

    kd.p2pkh        = pubkey_to_p2pkh(kd.compressed_pub);
    kd.p2sh_p2wpkh  = pubkey_to_p2sh_p2wpkh(kd.compressed_pub);
    kd.p2wpkh       = pubkey_to_p2wpkh(kd.compressed_pub);
    kd.p2wsh        = pubkey_to_p2wsh(kd.compressed_pub);

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// BIP-32 key derivation (for mnemonic mode)
// ─────────────────────────────────────────────────────────────────────────────
struct XKey { uint8_t key[32]; uint8_t chain[32]; };

static XKey derive_master_key(const uint8_t* seed, size_t seedlen) {
    // HMAC-SHA512("Bitcoin seed", seed)
    uint8_t out[64];
    unsigned outlen = 64;
    HMAC(EVP_sha512(), "Bitcoin seed", 12, seed, seedlen, out, &outlen);
    XKey xk;
    memcpy(xk.key,   out,    32);
    memcpy(xk.chain, out+32, 32);
    return xk;
}



static XKey derive_child_key(const XKey& parent, uint32_t index) {
    // BIP-32 child key derivation
    uint8_t data[37];
    bool hardened = (index >= 0x80000000u);
    if (hardened) {
        data[0] = 0x00;
        memcpy(data+1, parent.key, 32);
    } else {
        // Serialize compressed public key
        Bytes33 pub;
        if (!privkey_to_pubkey_compressed(parent.key, pub)) {
            return parent; // error fallback
        }
        memcpy(data, pub.data(), 33);
    }
    data[33] = (index >> 24) & 0xff;
    data[34] = (index >> 16) & 0xff;
    data[35] = (index >>  8) & 0xff;
    data[36] =  index        & 0xff;

    uint8_t out[64];
    unsigned outlen = 64;
    HMAC(EVP_sha512(), parent.chain, 32, data, 37, out, &outlen);

    XKey child;
    memcpy(child.key, parent.key, 32);
    // child_key = (IL + parent_key) mod n — uses our portable helper
    if (!sec_key_tweak_add(g_secp, child.key, out)) {
        return parent; // IL >= n or result == 0: extremely rare, skip index
    }
    memcpy(child.chain, out+32, 32);
    return child;
}

// ─────────────────────────────────────────────────────────────────────────────
// BIP-39 Mnemonic (minimal inline word list — first 2048 BIP-39 English words)
// ─────────────────────────────────────────────────────────────────────────────
// We embed just enough to generate random 12-word mnemonics for mnemonic mode.
// Full word list: https://github.com/trezor/python-mnemonic/blob/master/src/mnemonic/wordlist/english.txt


// Generate a BIP-39 mnemonic with either 12 or 24 words.
//
// BIP-39 entropy sizes:
//   12 words = 128 bits entropy + 4-bit checksum  = 132 bits = 12 × 11
//   24 words = 256 bits entropy + 8-bit checksum  = 264 bits = 24 × 11
//
// Algorithm:
//   1. Generate ENT bits of random entropy
//   2. Compute CS = SHA256(entropy)[0 : ENT/32] bits
//   3. Concatenate entropy || checksum bits → (ENT + CS) bits
//   4. Split into groups of 11 bits → word indices
static std::string generate_mnemonic(std::mt19937_64& rng, int word_count = 12) {
    // word_count must be 12 or 24
    const int ENT_BYTES  = (word_count == 24) ? 32 : 16;  // 256 or 128 bits
    // Total bits: ENT_BYTES*8 + CS_BITS = word_count*11 (264 or 132)

    // Step 1: generate entropy using cryptographically secure RNG
    // Using RAND_bytes (OpenSSL CSPRNG) instead of mt19937_64 to ensure
    // the generated mnemonics have proper cryptographic entropy.
    // Note: rng parameter is kept for API compatibility but not used here.
    (void)rng;
    uint8_t entropy[32] = {};
    RAND_bytes(entropy, ENT_BYTES);

    // Step 2: checksum = first CS_BITS of SHA256(entropy)
    Bytes32 h = sha256(entropy, (size_t)ENT_BYTES);

    // Step 3: build bit buffer = entropy bytes + checksum byte(s)
    // Max size: 32 entropy + 1 checksum byte = 33 bytes
    uint8_t bits[33] = {};
    memcpy(bits, entropy, (size_t)ENT_BYTES);
    // Append checksum bits into the next byte(s)
    // For 12 words: 4 checksum bits → top nibble of bits[16]
    // For 24 words: 8 checksum bits → bits[32]
    bits[ENT_BYTES] = h[0];  // for 12w: top 4 bits used; for 24w: full byte used

    // Step 4: extract word_count × 11-bit indices
    std::string result;
    for (int i = 0; i < word_count; ++i) {
        int bit_offset  = i * 11;
        int byte_offset = bit_offset / 8;
        int bit_in_byte = bit_offset % 8;

        // Read 3 bytes covering the 11-bit window
        uint32_t word_bits = 0;
        for (int b = 0; b < 3; ++b) {
            int idx = byte_offset + b;
            word_bits = (word_bits << 8) | ((idx < 33) ? bits[idx] : 0u);
        }

        // Shift so the 11-bit field is at the LSB
        int shift    = 24 - bit_in_byte - 11;
        uint32_t idx = ((word_bits >> shift) & 0x7ffu) % BIP39_WORD_COUNT;

        if (i > 0) result += ' ';
        result += BIP39_WORDLIST[idx];
    }
    return result;
}

static std::vector<uint8_t> mnemonic_to_seed(const std::string& phrase) {
    // BIP-39: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048)
    std::vector<uint8_t> seed(64);
    PKCS5_PBKDF2_HMAC(
        phrase.c_str(), (int)phrase.size(),
        (const uint8_t*)"mnemonic", 8,
        2048, EVP_sha512(),
        64, seed.data()
    );
    return seed;
}

// Generate addresses from mnemonic (BIP-44/49/84/86), depth=5
struct MnemonicRecord {
    std::string addr_type;
    std::string address;
    std::string wif, priv_hex, compressed_pub_hex, xonly_pub_hex;
    std::string derivation_path;
    std::string mnemonic;
};

static std::vector<MnemonicRecord>
generate_mnemonic_addresses(const std::string& phrase, int depth = 5) {
    auto seed = mnemonic_to_seed(phrase);
    XKey master = derive_master_key(seed.data(), seed.size());

    // BIP paths: purpose → address_type
    struct PurposeInfo { uint32_t purpose; const char* type; bool also_wsh; };
    static const PurposeInfo purposes[] = {
        {44, "P2PKH",      false},
        {49, "P2SH-P2WPKH",false},
        {84, "P2WPKH",     true },  // also generates P2WSH
        {86, "P2TR",       false},
    };

    std::vector<MnemonicRecord> records;

    for (auto& pi : purposes) {
        // m/purpose'/0'/0'/0
        XKey k = derive_child_key(master,  pi.purpose | 0x80000000);
        k       = derive_child_key(k,       0x80000000);
        k       = derive_child_key(k,       0x80000000);
        k       = derive_child_key(k,       0);

        for (int i = 0; i < depth; ++i) {
            XKey ck = derive_child_key(k, (uint32_t)i);
            KeyData kd;
            if (!fill_key_data(ck.key, kd)) continue;

            char path[64];
            snprintf(path, sizeof(path), "m/%u'/0'/0'/0/%d", pi.purpose, i);

            auto push = [&](const char* type, const std::string& addr) {
                MnemonicRecord r;
                r.addr_type         = type;
                r.address           = addr;
                r.wif               = kd.wif;
                r.priv_hex          = kd.priv_hex;
                r.compressed_pub_hex= kd.compressed_pub_hex;
                r.xonly_pub_hex     = kd.xonly_pub_hex;
                r.derivation_path   = path;
                r.mnemonic          = phrase;
                records.push_back(std::move(r));
            };

            if (strcmp(pi.type,"P2PKH")==0)       push("P2PKH",       kd.p2pkh);
            else if (strcmp(pi.type,"P2SH-P2WPKH")==0) push("P2SH-P2WPKH", kd.p2sh_p2wpkh);
            else if (strcmp(pi.type,"P2WPKH")==0) {
                push("P2WPKH", kd.p2wpkh);
                if (pi.also_wsh) push("P2WSH", kd.p2wsh);
            }
            else if (strcmp(pi.type,"P2TR")==0)   push("P2TR",        kd.p2tr);
        }
    }
    return records;
}

// ─────────────────────────────────────────────────────────────────────────────
// SipHash-1-3 (double output) — same as bloom_builder
// ─────────────────────────────────────────────────────────────────────────────
static inline uint64_t rotl64(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}

#define SIPROUND(v0,v1,v2,v3) \
    v0+=v1; v1=rotl64(v1,13); v1^=v0; v0=rotl64(v0,32); \
    v2+=v3; v3=rotl64(v3,16); v3^=v2; \
    v0+=v3; v3=rotl64(v3,21); v3^=v0; \
    v2+=v1; v1=rotl64(v1,17); v1^=v2; v2=rotl64(v2,32);

struct SipPair { uint64_t h1, h2; };

static SipPair siphash13_double(const uint8_t* data, size_t len,
                                 uint64_t k0=0, uint64_t k1=0) {
    uint64_t v0=k0^0x736f6d6570736575ULL, v1=k1^0x646f72616e646f6dULL;
    uint64_t v2=k0^0x6c7967656e657261ULL, v3=k1^0x7465646279746573ULL;
    size_t end=(len/8)*8;
    for (size_t i=0;i<end;i+=8) {
        uint64_t m; memcpy(&m,data+i,8);
        v3^=m; SIPROUND(v0,v1,v2,v3) v0^=m;
    }
    uint64_t last=((uint64_t)(len&0xff))<<56;
    for (size_t j=0;j<(len&7);++j) last|=(uint64_t)data[end+j]<<(j*8);
    v3^=last; SIPROUND(v0,v1,v2,v3) v0^=last;
    v2^=0xff;
    SIPROUND(v0,v1,v2,v3) SIPROUND(v0,v1,v2,v3) SIPROUND(v0,v1,v2,v3)
    uint64_t h1=v0^v1^v2^v3;
    v1^=0xee;
    SIPROUND(v0,v1,v2,v3) SIPROUND(v0,v1,v2,v3) SIPROUND(v0,v1,v2,v3)
    return {h1, v0^v1^v2^v3};
}

// ─────────────────────────────────────────────────────────────────────────────
// HybridFilter — Smart filter with 3 automatic modes:
//
//   BLOOM_ONLY  bloom given, no TSV  → bloom_check() only (fast, probabilistic)
//   HYBRID      both given           → bloom_check() → binary_search() (exact)
//   TSV_ONLY    TSV given, no bloom  → binary_search() only (exact, no pre-filter)
//
// Mode is detected automatically in load() and shown in the startup banner.
// ─────────────────────────────────────────────────────────────────────────────
enum class FilterMode { BLOOM_ONLY, HYBRID, TSV_ONLY };

struct HybridFilter {
    FilterMode  mode        = FilterMode::HYBRID;   // set by load()

    // Bloom state
    std::vector<uint8_t> bitmap;
    uint64_t bitmap_bits = 0;
    uint64_t bitmap_mask = 0;      // bitmap_bits-1 if pow2 (v3), else 0
    bool     bitmap_pow2 = false;  // true → use & instead of % (fast path)
    int      k_num       = 0;      // 0 until set by load_bloom/finalize_k
    uint64_t sip_k0      = 0;
    uint64_t sip_k1      = 0;

    // TSV mmap state
    const char*         tsv_data       = nullptr;
    size_t              tsv_size       = 0;
    size_t              tsv_data_start = 0;   // byte offset past any header line
    uint64_t            tsv_mtime      = 0;   // for cache invalidation
    int                 tsv_fd         = -1;
    std::vector<size_t> offsets;
    size_t              total_lines    = 0;

    HybridFilter() = default;
    ~HybridFilter() {
        if (tsv_data && tsv_data != MAP_FAILED) munmap((void*)tsv_data, tsv_size);
        if (tsv_fd >= 0) close(tsv_fd);
    }

    // ── Smart load: detects mode from which paths are provided / exist ────────
    // bloom_path / tsv_path may be empty string to signal "not provided".
    bool load(const std::string& bloom_path, const std::string& tsv_path) {
        bool has_bloom = !bloom_path.empty();
        bool has_tsv   = !tsv_path.empty();

        // Determine mode
        if (has_bloom && has_tsv) {
            mode = FilterMode::HYBRID;
        } else if (has_bloom && !has_tsv) {
            mode = FilterMode::BLOOM_ONLY;
        } else if (!has_bloom && has_tsv) {
            mode = FilterMode::TSV_ONLY;
        } else {
            std::cerr << "Error: must provide at least --bloom or --tsv.\n";
            return false;
        }

        // Print mode banner
        switch (mode) {
            case FilterMode::BLOOM_ONLY:
                std::cout << ansi::CYAN << ansi::BOLD
                          << "  Filter mode: BLOOM ONLY"
                          << ansi::RESET << ansi::DIM
                          << "  (fast · probabilistic · no exact confirm)\n"
                          << ansi::RESET;
                break;
            case FilterMode::HYBRID:
                std::cout << ansi::GREEN << ansi::BOLD
                          << "  Filter mode: HYBRID"
                          << ansi::RESET << ansi::DIM
                          << "  (bloom pre-filter + binary search exact confirm)\n"
                          << ansi::RESET;
                break;
            case FilterMode::TSV_ONLY:
                std::cout << ansi::YELLOW << ansi::BOLD
                          << "  Filter mode: TSV ONLY"
                          << ansi::RESET << ansi::DIM
                          << "  (exact · no bloom pre-filter · slower)\n"
                          << ansi::RESET;
                break;
        }

        // Load components according to mode
        if (has_bloom && !load_bloom(bloom_path)) return false;
        if (has_tsv   && !load_tsv(tsv_path))    return false;
        // For v1/v2 bloom files: compute k from bitmap size + TSV line count.
        // For v3 files (or bloom-only mode): finalize_k() is a no-op.
        if (has_bloom) finalize_k(total_lines);
        return true;
    }

    // ── Name of current mode (for banner/stats) ────────────────────────────
    const char* mode_name() const {
        switch (mode) {
            case FilterMode::BLOOM_ONLY: return "BLOOM_ONLY";
            case FilterMode::HYBRID:     return "HYBRID";
            case FilterMode::TSV_ONLY:   return "TSV_ONLY";
        }
        return "UNKNOWN";
    }

    // ── Main lookup — dispatches based on detected mode ───────────────────────
    bool contains(std::string_view address) const {
        switch (mode) {
            case FilterMode::BLOOM_ONLY:
                // Bloom only: fast, but may have false positives
                return bloom_check(address);

            case FilterMode::HYBRID:
                // Bloom pre-filter eliminates ~99.9% misses instantly,
                // then exact binary search confirms true positives only.
                if (!bloom_check(address)) return false;
                return binary_search_check(address);

            case FilterMode::TSV_ONLY:
                // No bloom: directly binary-search the mmap'd TSV.
                return binary_search_check(address);
        }
        return false;
    }

    bool bloom_check(std::string_view addr) const {
        if (bitmap.empty()) return false;
        auto [h1,h2] = siphash13_double((const uint8_t*)addr.data(), addr.size(),
                                         sip_k0, sip_k1);
        if (bitmap_pow2) {
            // Fast path: & instead of 64-bit division (v3 bloom, pow2 bitmap)
            for (int i = 0; i < k_num; ++i) {
                uint64_t bit = (h1 + (uint64_t)i * h2) & bitmap_mask;
                if (!(bitmap[bit >> 3] & (uint8_t)(1u << (bit & 7)))) return false;
            }
        } else {
            // Legacy path: general modulo (v1/v2 bloom)
            for (int i = 0; i < k_num; ++i) {
                uint64_t bit = (h1 + (uint64_t)i * h2) % bitmap_bits;
                if (!(bitmap[bit >> 3] & (uint8_t)(1u << (bit & 7)))) return false;
            }
        }
        return true;
    }

    bool binary_search_check(std::string_view target) const {
        if (tsv_data == nullptr || total_lines == 0) return false;
        size_t left = 0, right = total_lines;
        while (left < right) {
            size_t mid   = (left + right) / 2;
            size_t start = offsets[mid];
            size_t end   = (mid+1 < total_lines) ? offsets[mid+1] : tsv_size;
            std::string_view line(tsv_data + start, end - start);
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                line.remove_suffix(1);
            auto tab  = line.find('\t');
            auto addr = (tab != std::string_view::npos) ? line.substr(0, tab) : line;
            if (addr == target) return true;
            if (addr < target)  left  = mid + 1;
            else                right = mid;
        }
        return false;
    }

private:
    bool load_bloom(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::cerr << "Cannot open bloom: " << path << "\n"; return false; }

        uint8_t ver;
        f.read(reinterpret_cast<char*>(&ver), 1);
        if (!f) { std::cerr << "Empty bloom file\n"; return false; }

        bool k_stored = false;
        if (ver == 3) {
            // v3: k0(8) + k1(8) + k_num(4) + bitmap_len(8) + bitmap
            f.read(reinterpret_cast<char*>(&sip_k0), 8);
            f.read(reinterpret_cast<char*>(&sip_k1), 8);
            uint32_t k32 = 0;
            f.read(reinterpret_cast<char*>(&k32), 4);
            k_num    = (int)k32;
            k_stored = true;
        } else if (ver == 2) {
            // v2: k0(8) + k1(8) + bitmap_len(8) + bitmap  (k_num NOT stored)
            f.read(reinterpret_cast<char*>(&sip_k0), 8);
            f.read(reinterpret_cast<char*>(&sip_k1), 8);
        } else if (ver == 1) {
            sip_k0 = sip_k1 = 0;
        } else {
            std::cerr << "Unknown bloom version: " << (int)ver
                      << " (expected 1, 2, or 3)\n";
            return false;
        }

        uint64_t blen;
        f.read(reinterpret_cast<char*>(&blen), 8);
        bitmap.resize(blen);
        f.read(reinterpret_cast<char*>(bitmap.data()), (std::streamsize)blen);
        if (!f) { std::cerr << "Short read in bloom file\n"; return false; }
        bitmap_bits = blen * 8;

        // For v1/v2: k_num was not stored. Compute from bitmap size + TSV line count.
        // This is deferred to after TSV is loaded — see load() below.
        // For now mark k_num=0 to trigger the deferred computation.
        if (!k_stored) k_num = 0;

        // Check if bitmap is power-of-2 bytes (v3 builder guarantees this).
        // If so, enable fast & modulo path in bloom_check().
        {
            uint64_t b2 = blen;
            if (b2 && (b2 & (b2 - 1)) == 0) {   // is power of 2?
                bitmap_pow2 = true;
                bitmap_mask = bitmap_bits - 1;
            }
        }

        std::cout << ansi::GREEN << "  ✔ Bloom v" << (int)ver << ": "
                  << blen/1024/1024 << " MB"
                  << (k_stored ? ", k=" + std::to_string(k_num) + " (stored)"
                               : ", k=? (computed after TSV load)")
                  << (bitmap_pow2 ? ", pow2[fast]" : "")
                  << ansi::RESET << "\n";
        return true;
    }

    // Called after both bloom and TSV are loaded.
    // For v3 bloom files this is a no-op (k_num already set from file).
    // For v1/v2: compute k = floor((bitmap_bits / n_items) * ln2)
    void finalize_k(size_t n_items) {
        if (k_num > 0) return;   // v3: already set from file
        if (bitmap_bits == 0)  { k_num = 10; return; }
        if (n_items == 0) {
            // BLOOM_ONLY mode: no TSV to count lines from.
            // Default to 10 — most common value for fpp=0.001.
            // If wrong, rebuild bloom with new bloom_builder (v3 stores k).
            k_num = 10;
            std::cout << ansi::YELLOW
                      << "  ! k defaulted to 10 (bloom-only mode, no TSV to compute from)\n"
                      << "    Rebuild bloom with new bloom_builder for exact k (v3 format)\n"
                      << ansi::RESET;
            return;
        }
        // Mirror bloom_builder formula exactly: k = floor((m/n) * ln2)
        double k = ((double)bitmap_bits / (double)n_items) * 0.6931471805599453;
        k_num = (int)std::max(1.0, std::floor(k));
        std::cout << ansi::CYAN
                  << "  ✔ k computed: k=" << k_num
                  << " (bitmap=" << bitmap_bits/1024/1024 << " Mb"
                  << ", n=" << n_items << ")"
                  << ansi::RESET << "\n";
    }

    // ── TSV index cache ───────────────────────────────────────────────────────
    // The offset index (58M × 8 bytes = ~464 MB) is expensive to rebuild from
    // a 2+ GB file every run. We save it as path + ".idx" and reload it if the
    // TSV has not changed (mtime check). This reduces startup from ~10s to <1s.
    static std::string idx_path_for(const std::string& tsv) { return tsv + ".idx"; }

    bool save_idx(const std::string& path) const {
        // Binary format (all little-endian 64-bit):
        //   [0]  magic     = 0x5458564944585801  ("TXVIDXX" + version byte 0x01)
        //   [1]  tsv_size  = file size in bytes   (cache invalidation)
        //   [2]  tsv_mtime = file mtime            (cache invalidation)
        //   [3]  data_start= tsv_data_start (header skip offset)
        //   [4]  n_lines   = total_lines
        //   [5+] offsets   = n_lines × uint64_t
        FILE* f = fopen(path.c_str(), "wb");
        if (!f) return false;
        const uint64_t magic = 0x5458564944585801ULL; // v1
        uint64_t n  = (uint64_t)total_lines;
        uint64_t ds = (uint64_t)tsv_data_start;
        fwrite(&magic,    8, 1, f);
        fwrite(&tsv_size, 8, 1, f);
        fwrite(&tsv_mtime,8, 1, f);
        fwrite(&ds,       8, 1, f);
        fwrite(&n,        8, 1, f);
        fwrite(offsets.data(), 8, offsets.size(), f);
        fclose(f);
        return true;
    }

    bool load_idx(const std::string& path, uint64_t expected_size, uint64_t expected_mtime) {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) return false;
        uint64_t magic, sz, mt, ds, n;
        if (fread(&magic, 8, 1, f) != 1 || magic != 0x5458564944585801ULL) { fclose(f); return false; }
        if (fread(&sz,    8, 1, f) != 1 || sz != expected_size)             { fclose(f); return false; }
        if (fread(&mt,    8, 1, f) != 1 || mt != expected_mtime)            { fclose(f); return false; }
        if (fread(&ds,    8, 1, f) != 1)                                     { fclose(f); return false; }
        if (fread(&n,     8, 1, f) != 1)                                     { fclose(f); return false; }
        offsets.resize((size_t)n);
        if (fread(offsets.data(), 8, (size_t)n, f) != (size_t)n)            { fclose(f); return false; }
        fclose(f);
        total_lines    = (size_t)n;
        tsv_data_start = (size_t)ds;
        return true;
    }

    bool load_tsv(const std::string& path) {
        tsv_fd = open(path.c_str(), O_RDONLY);
        if (tsv_fd < 0) { perror("open tsv"); return false; }

        struct stat st;
        fstat(tsv_fd, &st);
        tsv_size  = (size_t)st.st_size;
        tsv_mtime = (uint64_t)st.st_mtime;
        if (tsv_size == 0) { std::cerr << "TSV empty\n"; return false; }

        // MAP_POPULATE: kernel pre-faults pages into page cache in the background
        // while we load/build the index — effectively free prefetch.
        tsv_data = reinterpret_cast<const char*>(
            mmap(nullptr, tsv_size, PROT_READ, MAP_SHARED | MAP_POPULATE, tsv_fd, 0));
        if (tsv_data == MAP_FAILED) {
            tsv_data = reinterpret_cast<const char*>(
                mmap(nullptr, tsv_size, PROT_READ, MAP_SHARED, tsv_fd, 0));
            if (tsv_data == MAP_FAILED) { perror("mmap tsv"); return false; }
        }

        // ── Detect and skip header line ───────────────────────────────────────
        // Blockchair TSV files begin with a header like "address\tbalance\t..."
        // Bitcoin addresses start with '1', '3', or 'b' (ASCII 49,51,98).
        // The word "address" starts with 'a' (ASCII 97), which sorts BETWEEN
        // '3...' and 'bc1...' addresses. If included in the index it would
        // corrupt binary search for all bc1... (bech32) addresses.
        // Fix: if the first non-empty line does not start with a valid address
        // character, treat it as a header and exclude it from the index.
        tsv_data_start = 0;   // byte offset where real data starts (after header)
        {
            const char* first_nl = reinterpret_cast<const char*>(
                memchr(tsv_data, '\n', tsv_size));
            if (first_nl) {
                // Use the same validation as bloom_builder and bloom_checker:
                // reject anything whose first char is outside '1'..'z'
                // This correctly skips "address\tbalance" headers and
                // matches exactly what the builder inserted.
                char fc = tsv_data[0];
                bool is_header = (fc < '1' || fc > 'z');
                if (is_header) {
                    tsv_data_start = (size_t)(first_nl - tsv_data) + 1;
                    std::cout << ansi::DIM
                              << "  ✔ Header line detected and skipped\n"
                              << ansi::RESET;
                }
            }
        }

        // ── Try loading cached index ──────────────────────────────────────────
        std::string idx_path = idx_path_for(path);
        auto t0 = std::chrono::steady_clock::now();

        if (load_idx(idx_path, tsv_size, tsv_mtime)) {
            double secs = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - t0).count();
            std::cout << ansi::GREEN
                      << "  ✔ TSV index loaded from cache: "
                      << total_lines/1000000.0 << "M lines"
                      << " (" << std::fixed << std::setprecision(2) << secs << "s)"
                      << ansi::RESET << "\n";
            madvise(const_cast<char*>(tsv_data), tsv_size, MADV_RANDOM);
            return true;
        }

        // ── Build index: parallel multi-threaded scan for newlines ────────────
        // MADV_SEQUENTIAL during the build: kernel prefetches pages linearly
        // → ~2x faster for a sequential scan than MADV_RANDOM.
        madvise(const_cast<char*>(tsv_data), tsv_size, MADV_SEQUENTIAL);

        unsigned ncpu = std::max(1u, std::thread::hardware_concurrency());
        std::cout << ansi::YELLOW
                  << "  ⟳ Building TSV index (" << ncpu << " threads)..."
                  << ansi::RESET << "\n";

        // Each thread scans its own chunk and writes to its own private vector.
        // No locks, no contention. Merge is trivial because chunks are in order.
        std::vector<std::vector<size_t>> thread_offsets(ncpu);
        std::vector<std::thread>         threads;
        threads.reserve(ncpu);

        size_t data_size = tsv_size - tsv_data_start;
        size_t chunk     = data_size / ncpu;

        for (unsigned t = 0; t < ncpu; ++t) {
            size_t start = tsv_data_start + t * chunk;

            if (t > 0) {
                // Align chunk start to the byte after the next newline
                const char* nl = reinterpret_cast<const char*>(
                    memchr(tsv_data + start, '\n', tsv_size - start));
                if (!nl) continue;
                start = (size_t)(nl - tsv_data) + 1;
            }
            size_t end_pos = (t + 1 < ncpu)
                             ? tsv_data_start + (t + 1) * chunk
                             : tsv_size;

            threads.emplace_back([this, t, start, end_pos, &thread_offsets]() {
                auto& vec = thread_offsets[t];
                vec.reserve((end_pos - start) / 38 + 1);
                if (t == 0) vec.push_back(tsv_data_start);  // first real data line

                const char* p   = tsv_data + start;
                const char* end = tsv_data + end_pos;
                while (p < end) {
                    const char* nl = reinterpret_cast<const char*>(
                        memchr(p, '\n', end - p));
                    if (!nl) break;
                    size_t next = (size_t)(nl - tsv_data) + 1;
                    if (next < tsv_size) vec.push_back(next);
                    p = nl + 1;
                }
            });
        }
        for (auto& th : threads) th.join();

        // Merge in file order (no sort needed — chunks are already sequential)
        size_t total = 0;
        for (auto& v : thread_offsets) total += v.size();
        offsets.reserve(total);
        for (auto& v : thread_offsets)
            offsets.insert(offsets.end(), v.begin(), v.end());
        total_lines = offsets.size();

        double secs = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - t0).count();
        std::cout << ansi::GREEN
                  << "  ✔ TSV: " << total_lines/1000000.0 << "M lines"
                  << " (" << std::fixed << std::setprecision(2) << secs << "s)"
                  << ansi::RESET << "\n";

        madvise(const_cast<char*>(tsv_data), tsv_size, MADV_RANDOM);

        // Save index for next run
        if (save_idx(idx_path)) {
            std::cout << ansi::DIM
                      << "  ✔ Index cached → " << idx_path << "\n"
                      << ansi::RESET;
        }
        return true;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Hit storage — abstract base + TSV + PostgreSQL backends
// ─────────────────────────────────────────────────────────────────────────────

// Abstract interface (same signature for both backends)
struct HitLogger {
    virtual ~HitLogger() = default;
    virtual bool log(const std::string& addr, const std::string& type,
                     const std::string& wif,  const std::string& phex,
                     const std::string& cpub, const std::string& xpub,
                     const std::string& mnemonic,
                     const std::string& path) = 0;
};

// ── TSV file backend ──────────────────────────────────────────────────────────
struct TSVLogger : HitLogger {
    std::ofstream file;
    std::mutex    mtx;

    bool open(const std::string& fpath) {
        bool is_new = !std::ifstream(fpath).good();
        file.open(fpath, std::ios::app);
        if (!file) return false;
        if (is_new)
            file << "timestamp\taddress\taddress_type\tprivate_key_wif\t"
                    "private_key_hex\tcompressed_pubkey\txonly_pubkey\t"
                    "mnemonic\tderivation_path\n";
        return true;
    }

    bool log(const std::string& addr, const std::string& type,
             const std::string& wif,  const std::string& phex,
             const std::string& cpub, const std::string& xpub,
             const std::string& mnemonic,
             const std::string& path) override {
        std::lock_guard<std::mutex> lk(mtx);
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        char ts[32]; strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", gmtime(&t));
        file << ts << '\t' << addr << '\t' << type << '\t'
             << wif << '\t' << phex << '\t' << cpub << '\t' << xpub << '\t'
             << mnemonic << '\t' << path << '\n';
        file.flush();
        return file.good();
    }
};

// ── PostgreSQL backend ────────────────────────────────────────────────────────
// Activated with --pg "connection-string"
// Requires: apt install libpq-dev  +  compile flag: -DWITH_PG -lpq
// Schema matches the Python version's found_addresses table exactly.
// ─────────────────────────────────────────────────────────────────────────────
// PostgreSQL connection string normalizer
//
// Accepts ALL of these formats and converts to what libpq expects:
//
//   URL formats (both are accepted by libpq natively since PG 9.2):
//     postgresql://user:pass@host:5432/dbname
//     postgres://user:pass@host/dbname
//     postgresql://user@host/dbname         (no password)
//     postgresql://host/dbname              (no user)
//     postgresql://host:5432/dbname?sslmode=require&connect_timeout=10
//
//   SQLAlchemy / psycopg2 dialect URLs (stripped to base URL):
//     postgresql+asyncpg://user:pass@host/db  → postgresql://user:pass@host/db
//     postgresql+psycopg2://user:pass@host/db → postgresql://user:pass@host/db
//
//   Key=value format (passed through unchanged):
//     host=localhost dbname=btc user=postgres password=secret port=5432
//     host=localhost dbname=btc user=postgres
//
// ─────────────────────────────────────────────────────────────────────────────
static std::string normalize_pg_conn(const std::string& s) {
    // Check if it looks like a URL: starts with "postgres"
    if (s.size() >= 8 && s.substr(0, 8) == "postgres") {
        // Find the "://" separator
        size_t scheme_end = s.find("://");
        if (scheme_end != std::string::npos) {
            // Extract the scheme part (before "://")
            std::string scheme = s.substr(0, scheme_end);

            // Strip SQLAlchemy dialect suffix: "postgresql+asyncpg" → "postgresql"
            // Everything after a '+' in the scheme is a driver/dialect specifier.
            size_t plus = scheme.find('+');
            if (plus != std::string::npos) {
                scheme = scheme.substr(0, plus);
            }

            // Normalise "postgres" → "postgresql" (libpq accepts both, but be explicit)
            if (scheme == "postgres") scheme = "postgresql";

            // Reconstruct: scheme + "://" + rest
            std::string rest = s.substr(scheme_end + 3);  // everything after "://"
            return scheme + "://" + rest;
        }
    }
    // Not a URL — assume key=value format, pass through unchanged
    return s;
}

#ifdef WITH_PG
struct PGLogger : HitLogger {
    PGconn*    conn = nullptr;
    std::mutex mtx;

    // open() accepts both URL and key=value formats (see normalize_pg_conn above).
    bool open(const std::string& raw_connstr) {
        std::string connstr = normalize_pg_conn(raw_connstr);

        // Show what we're connecting to (mask password for display)
        std::string display = connstr;
        // Simple password masking for URL format: replace :pass@ with :***@
        {
            size_t at = display.rfind('@');
            size_t colon = (at != std::string::npos)
                           ? display.rfind(':', at) : std::string::npos;
            size_t scheme_colon = display.find("://");
            // Make sure the colon is after :// (i.e. it's user:pass, not scheme:)
            if (colon != std::string::npos && scheme_colon != std::string::npos
                && colon > scheme_colon + 2) {
                display = display.substr(0, colon + 1) + "***" + display.substr(at);
            }
        }
        std::cout << ansi::DIM << "  Connecting: " << display << ansi::RESET << "\n";

        conn = PQconnectdb(connstr.c_str());
        if (PQstatus(conn) != CONNECTION_OK) {
            std::cerr << ansi::RED
                      << "  PostgreSQL connect failed: " << PQerrorMessage(conn)
                      << ansi::RESET << "\n"
                      << "  Accepted formats:\n"
                      << "    postgresql://user:pass@host:5432/dbname\n"
                      << "    postgres://user:pass@host/dbname\n"
                      << "    postgresql+asyncpg://user:pass@host/dbname\n"
                      << "    host=localhost dbname=btc user=postgres password=secret\n";
            PQfinish(conn); conn = nullptr; return false;
        }

        // Create table if absent — same schema as Python version
        const char* ddl = R"SQL(
            CREATE TABLE IF NOT EXISTS found_addresses (
                id                SERIAL PRIMARY KEY,
                address           TEXT NOT NULL UNIQUE,
                address_type      TEXT NOT NULL,
                private_key_wif   TEXT NOT NULL,
                private_key_hex   TEXT NOT NULL,
                compressed_pubkey TEXT,
                xonly_pubkey      TEXT,
                mnemonic          TEXT,
                derivation_path   TEXT,
                created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        )SQL";
        PGresult* r = PQexec(conn, ddl);
        bool ok = (PQresultStatus(r) == PGRES_COMMAND_OK);
        if (!ok) std::cerr << ansi::YELLOW
                           << "  DDL warning: " << PQerrorMessage(conn)
                           << ansi::RESET;
        PQclear(r);
        PQexec(conn, "COMMIT");

        // Show server version for confirmation
        PGresult* ver = PQexec(conn, "SELECT version()");
        if (PQresultStatus(ver) == PGRES_TUPLES_OK && PQntuples(ver) > 0) {
            std::string v = PQgetvalue(ver, 0, 0);
            // Trim to first line only
            auto nl = v.find('\n'); if (nl != std::string::npos) v = v.substr(0, nl);
            std::cout << ansi::GREEN << "  ✔ PostgreSQL connected: "
                      << ansi::DIM << v << ansi::RESET << "\n";
        } else {
            std::cout << ansi::GREEN << "  ✔ PostgreSQL connected\n" << ansi::RESET;
        }
        PQclear(ver);
        return true;
    }

    ~PGLogger() { if (conn) PQfinish(conn); }

    bool log(const std::string& addr, const std::string& type,
             const std::string& wif,  const std::string& phex,
             const std::string& cpub, const std::string& xpub,
             const std::string& mnemonic,
             const std::string& path) override {
        std::lock_guard<std::mutex> lk(mtx);
        if (!conn) return false;
        const char* params[8] = {
            addr.c_str(), type.c_str(), wif.c_str(), phex.c_str(),
            cpub.c_str(), xpub.c_str(), mnemonic.c_str(), path.c_str()
        };
        const char* sql =
            "INSERT INTO found_addresses "
            "(address,address_type,private_key_wif,private_key_hex,"
            " compressed_pubkey,xonly_pubkey,mnemonic,derivation_path) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (address) DO NOTHING";
        PGresult* r = PQexecParams(conn, sql, 8, nullptr, params, nullptr, nullptr, 0);
        bool ok = (PQresultStatus(r) == PGRES_COMMAND_OK);
        if (!ok) {
            std::cerr << ansi::RED << "  PG insert error: "
                      << PQerrorMessage(conn) << ansi::RESET << "\n";
            // Attempt reconnect on next call if connection dropped
            if (PQstatus(conn) != CONNECTION_OK) PQreset(conn);
        }
        PQclear(r);
        PQexec(conn, "COMMIT");
        return ok;
    }
};
#else
// Stub when compiled without -DWITH_PG
struct PGLogger : HitLogger {
    bool open(const std::string&) {
        std::cerr << "PostgreSQL support not compiled in.\n"
                     "Rebuild with: g++ ... -DWITH_PG -lpq\n";
        return false;
    }
    bool log(const std::string&, const std::string&, const std::string&,
             const std::string&, const std::string&, const std::string&,
             const std::string&, const std::string&) override { return false; }
};
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Worker thread
// ─────────────────────────────────────────────────────────────────────────────
static std::atomic<uint64_t> g_scanned{0};
static std::atomic<uint64_t> g_hits{0};
static std::atomic<bool>     g_stop{false};

// ─────────────────────────────────────────────────────────────────────────────
// Milestone display  (--show N  flag)
// Only worker 0 prints milestones, guarded by a mutex to avoid interleaving.
// ─────────────────────────────────────────────────────────────────────────────
static std::atomic<uint64_t> g_show_interval{0};  // 0 = disabled
static std::mutex            g_show_mtx;

// Colour per address type (matches Python ADDRESS_COLORS)
static const char* addr_color(const std::string& t) {
    if (t == "P2PKH")       return ansi::BLUE;
    if (t == "P2SH-P2WPKH") return ansi::MAGENTA;
    if (t == "P2WPKH")      return ansi::GREEN;
    if (t == "P2WSH")       return ansi::YELLOW;
    if (t == "P2TR")        return ansi::CYAN;
    return ansi::RESET;
}

// ─────────────────────────────────────────────────────────────────────────────
// print_milestone_random:
//   Shows one full random-key panel every N addresses (--show mode).
//   Random mode: single private key → 5 address types (shared key).
//
//   ╔══════════════ 📊 MILESTONE — 100,000 ADDRESSES SCANNED ═══════════════╗
//   ║ 🔑 PRIVATE KEY (shared — all 5 address types from one key)           ║
//   ║   WIF  : Kxxx...                                                     ║
//   ║   HEX  : aabbcc...                                                   ║
//   ║ 🗝 PUBLIC KEYS                                                        ║
//   ║   Compressed 33B : 02aabbcc...   → P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH║
//   ║   X-Only 32B     : aabbcc...     → P2TR (BIP-340)                   ║
//   ║ 📬 ALL 5 ADDRESS TYPES                                                ║
//   ║   P2PKH       : 1Axxx...                                             ║
//   ║   P2SH-P2WPKH : 3Bxxx...                                             ║
//   ║   P2WPKH      : bc1qxxx...                                           ║
//   ║   P2WSH       : bc1qxxx...                                           ║
//   ║   P2TR        : bc1pxxx...                                           ║
//   ╚══════════════════════════════════════════════════════════════════════╝
// ─────────────────────────────────────────────────────────────────────────────
static void print_milestone_random(uint64_t milestone, const KeyData& kd) {
    std::lock_guard<std::mutex> lk(g_show_mtx);
    // Clear the stats line first
    std::cout << "\r" << std::string(80, ' ') << "\r";

    const std::string sep(72, '=');
    const std::string sep2(72, '-');

    // ── Header ────────────────────────────────────────────────────────────
    std::cout << "\n" << ansi::BLUE << ansi::BOLD
              << "+" << sep << "+\n"
              << "| " << ansi::CYAN << "📊 MILESTONE — " << milestone << " ADDRESSES SCANNED"
              << ansi::BLUE << std::string(72 - 26 - std::to_string(milestone).size(), ' ') << "|\n"
              << "+" << sep << "+" << ansi::RESET << "\n";

    // ── Private key ───────────────────────────────────────────────────────
    std::cout << ansi::YELLOW << ansi::BOLD
              << "  🔑 PRIVATE KEY  (shared — all 5 address types from one key)\n"
              << ansi::RESET
              << ansi::DIM << "  " << sep2 << "\n" << ansi::RESET;
    std::cout << "  " << ansi::DIM << "WIF : " << ansi::RESET
              << ansi::RED  << kd.wif       << ansi::RESET << "\n";
    std::cout << "  " << ansi::DIM << "HEX : " << ansi::RESET
              << ansi::RED  << kd.priv_hex  << ansi::RESET << "\n";

    // ── Public keys ───────────────────────────────────────────────────────
    std::cout << "\n" << ansi::YELLOW << ansi::BOLD
              << "  🗝  PUBLIC KEYS\n" << ansi::RESET
              << ansi::DIM << "  " << sep2 << "\n" << ansi::RESET;
    std::cout << "  " << ansi::DIM << "Compressed 33B : " << ansi::RESET
              << ansi::MAGENTA << kd.compressed_pub_hex << ansi::RESET
              << ansi::DIM    << "  → P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH" << ansi::RESET << "\n";
    std::cout << "  " << ansi::DIM << "X-Only    32B  : " << ansi::RESET
              << ansi::MAGENTA << kd.xonly_pub_hex    << ansi::RESET
              << ansi::DIM    << "  → P2TR (BIP-340)" << ansi::RESET << "\n";

    // ── All 5 addresses ───────────────────────────────────────────────────
    std::cout << "\n" << ansi::YELLOW << ansi::BOLD
              << "  📬 ALL 5 ADDRESS TYPES\n" << ansi::RESET
              << ansi::DIM << "  " << sep2 << "\n" << ansi::RESET;

    struct { const char* label; const std::string* addr; } rows[] = {
        {"P2PKH      ", &kd.p2pkh},
        {"P2SH-P2WPKH", &kd.p2sh_p2wpkh},
        {"P2WPKH     ", &kd.p2wpkh},
        {"P2WSH      ", &kd.p2wsh},
        {"P2TR       ", &kd.p2tr},
    };
    for (auto& row : rows) {
        std::string t(row.label);
        t.erase(t.find_last_not_of(' ') + 1);  // rtrim
        std::cout << "  " << addr_color(t) << ansi::BOLD
                  << std::left << std::setw(13) << row.label
                  << ansi::RESET << " : "
                  << addr_color(t) << *row.addr << ansi::RESET << "\n";
    }

    std::cout << ansi::BLUE
              << "+" << sep << "+" << ansi::RESET << "\n\n";
    std::cout.flush();
}

// ─────────────────────────────────────────────────────────────────────────────
// print_milestone_mnemonic:
//   Mnemonic mode: each address type has its OWN BIP-derived private key.
//   Shows: mnemonic phrase + per-type table (addr | path | WIF | HEX | pubkey).
// ─────────────────────────────────────────────────────────────────────────────
static void print_milestone_mnemonic(
        uint64_t milestone,
        const std::string& mnemonic,
        const std::vector<MnemonicRecord>& records) {
    std::lock_guard<std::mutex> lk(g_show_mtx);
    std::cout << "\r" << std::string(80, ' ') << "\r";

    const std::string sep(72, '=');
    const std::string sep2(72, '-');

    // ── Header ────────────────────────────────────────────────────────────
    std::cout << "\n" << ansi::BLUE << ansi::BOLD
              << "+" << sep << "+\n"
              << "| " << ansi::CYAN << "📊 MILESTONE — " << milestone << " ADDRESSES SCANNED"
              << ansi::BLUE << std::string(72 - 26 - std::to_string(milestone).size(), ' ') << "|\n"
              << "+" << sep << "+" << ansi::RESET << "\n";

    // ── Mnemonic phrase ───────────────────────────────────────────────────
    std::cout << "\n" << ansi::YELLOW << ansi::BOLD
              << "  📝 MNEMONIC PHRASE\n" << ansi::RESET
              << ansi::DIM << "  " << sep2 << "\n" << ansi::RESET;
    std::cout << "  " << ansi::MAGENTA << mnemonic << ansi::RESET << "\n";

    // ── Per-type keys & addresses table ──────────────────────────────────
    std::cout << "\n" << ansi::YELLOW << ansi::BOLD
              << "  🔑 PER-TYPE KEYS & ADDRESSES  (each BIP path → different private key)\n"
              << ansi::RESET
              << ansi::DIM << "  " << sep2 << "\n" << ansi::RESET;

    // Column header
    std::cout << ansi::DIM
              << "  " << std::left
              << std::setw(13) << "Type"
              << std::setw(36) << "Address"
              << std::setw(16) << "Path"
              << "\n";
    std::cout << "  " << std::string(70, '-') << ansi::RESET << "\n";

    // De-duplicate by addr_type, keeping first occurrence
    std::vector<const MnemonicRecord*> seen;
    for (auto& r : records) {
        bool dup = false;
        for (auto* p : seen) if (p->addr_type == r.addr_type) { dup = true; break; }
        if (!dup) seen.push_back(&r);
    }

    for (auto* rp : seen) {
        const auto& r = *rp;
        const char* col = addr_color(r.addr_type);
        std::cout << "  "
                  << col << ansi::BOLD << std::left << std::setw(13) << r.addr_type << ansi::RESET
                  << col            << std::setw(36) << r.address     << ansi::RESET
                  << ansi::DIM      << std::setw(16) << r.derivation_path << ansi::RESET
                  << "\n";
        // WIF + HEX on next indented line
        std::cout << "  "
                  << ansi::DIM << "  WIF: " << ansi::RESET
                  << ansi::RED << r.wif << ansi::RESET << "\n";
        std::cout << "  "
                  << ansi::DIM << "  HEX: " << ansi::RESET
                  << ansi::RED << r.priv_hex << ansi::RESET << "\n";
        std::cout << "  "
                  << ansi::DIM << "  PUB: " << ansi::RESET
                  << ansi::MAGENTA << r.compressed_pub_hex << ansi::RESET << "\n";
        if (r.addr_type == "P2TR") {
            std::cout << "  "
                      << ansi::DIM << "  X-Only: " << ansi::RESET
                      << ansi::MAGENTA << r.xonly_pub_hex << ansi::RESET << "\n";
        }
        std::cout << "\n";
    }

    std::cout << ansi::BLUE
              << "+" << sep << "+" << ansi::RESET << "\n\n";
    std::cout.flush();
}

struct WorkerConfig {
    int         worker_id;
    int         mode;           // 0=random, 1=mnemonic, 2=mix
    int         depth;          // BIP-32 derivation depth
    int         words;          // 0=random 12/24, 12, or 24
    uint64_t    show_interval;  // print milestone every N addresses (0=off)
    const HybridFilter* filter;
    HitLogger*  logger;
};

// mode values
static constexpr int MODE_RANDOM   = 0;
static constexpr int MODE_MNEMONIC = 1;
static constexpr int MODE_MIX      = 2;

static void worker_func(WorkerConfig cfg) {
    std::mt19937_64 rng(
        std::chrono::high_resolution_clock::now().time_since_epoch().count()
        ^ (uint64_t)cfg.worker_id * 0xdeadbeefULL
    );

    while (!g_stop.load(std::memory_order_relaxed)) {
        bool do_mnemonic = false;
        std::string mnemonic_str;

        if (cfg.mode == MODE_RANDOM) {
            do_mnemonic = false;
        } else if (cfg.mode == MODE_MNEMONIC) {
            do_mnemonic = true;
        } else {
            do_mnemonic = (rng() & 1);
        }

        if (!do_mnemonic) {
            // --- Random mode: one random key → 5 addresses ---
            uint8_t priv[32];
            RAND_bytes(priv, 32);
            // Ensure valid secp256k1 key
            while (!secp256k1_ec_seckey_verify(g_secp, priv))
                RAND_bytes(priv, 32);

            KeyData kd;
            if (!fill_key_data(priv, kd)) continue;

            struct { const char* type; const std::string* addr; } addrs[] = {
                {"P2PKH",      &kd.p2pkh},
                {"P2SH-P2WPKH",&kd.p2sh_p2wpkh},
                {"P2WPKH",     &kd.p2wpkh},
                {"P2WSH",      &kd.p2wsh},
                {"P2TR",       &kd.p2tr},
            };
            for (auto& a : addrs) {
                if (cfg.filter->contains(*a.addr)) {
                    ++g_hits;
                    if (cfg.logger)
                        cfg.logger->log(*a.addr, a.type,
                                        kd.wif, kd.priv_hex,
                                        kd.compressed_pub_hex, kd.xonly_pub_hex,
                                        "", "random");
                    std::cout << "\n" << ansi::GREEN << ansi::BOLD
                              << "🎯 HIT! " << a.type << " " << *a.addr
                              << ansi::RESET
                              << "\n  WIF:  " << kd.wif
                              << "\n  HEX:  " << kd.priv_hex << "\n";
                }
            }
            g_scanned.fetch_add(5, std::memory_order_relaxed);

            // ── Milestone display (--show, random mode, worker 0 only) ──
            if (cfg.worker_id == 0 && cfg.show_interval > 0) {
                uint64_t sc = g_scanned.load(std::memory_order_relaxed);
                uint64_t ms = (sc / cfg.show_interval) * cfg.show_interval;
                static thread_local uint64_t last_ms_r = 0;
                if (ms > 0 && ms != last_ms_r) {
                    last_ms_r = ms;
                    print_milestone_random(ms, kd);
                }
            }

        } else {
            // --- Mnemonic mode: BIP-39 / BIP-32 / BIP-44/49/84/86 ---
            // Randomly generate either 12-word (128-bit) or 24-word (256-bit) mnemonic
            int wc = cfg.words;
            if (wc == 0) wc = (rng() & 1) ? 24 : 12;
            mnemonic_str = generate_mnemonic(rng, wc);
            auto records = generate_mnemonic_addresses(mnemonic_str, cfg.depth);

            for (auto& r : records) {
                if (cfg.filter->contains(r.address)) {
                    ++g_hits;
                    if (cfg.logger)
                        cfg.logger->log(r.address, r.addr_type,
                                        r.wif, r.priv_hex,
                                        r.compressed_pub_hex, r.xonly_pub_hex,
                                        r.mnemonic, r.derivation_path);
                    std::cout << "\n" << ansi::GREEN << ansi::BOLD
                              << "🎯 HIT! " << r.addr_type << " " << r.address
                              << ansi::RESET
                              << "\n  WIF:  " << r.wif
                              << "\n  PATH: " << r.derivation_path
                              << "\n  MNEM: " << r.mnemonic << "\n";
                }
            }
            g_scanned.fetch_add(records.size(), std::memory_order_relaxed);

            // ── Milestone display (--show, mnemonic mode, worker 0 only) ─
            if (cfg.worker_id == 0 && cfg.show_interval > 0 && !mnemonic_str.empty()) {
                uint64_t sc = g_scanned.load(std::memory_order_relaxed);
                uint64_t ms = (sc / cfg.show_interval) * cfg.show_interval;
                static thread_local uint64_t last_ms_m = 0;
                if (ms > 0 && ms != last_ms_m) {
                    last_ms_m = ms;
                    print_milestone_mnemonic(ms, mnemonic_str, records);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats display
// ─────────────────────────────────────────────────────────────────────────────
static void print_banner() {
    std::cout << ansi::CYAN << R"(
  ██████╗ ████████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗  ██╗
  ██╔══██╗╚══██╔══╝██╔════╝     ██╔════╝██╔════╝██╔══██╗████╗ ██║
  ██████╔╝   ██║   ██║          ███████╗██║     ███████║██╔██╗██║
  ██╔══██╗   ██║   ██║          ╚════██║██║     ██╔══██║██║╚████║
  ██████╔╝   ██║   ╚██████╗     ███████║╚██████╗██║  ██║██║ ╚███║
  ╚═════╝    ╚═╝    ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
)" << ansi::RESET
              << ansi::DIM << "  Bitcoin Address Scanner · C++17 · Multi-Thread · Fast\n\n"
              << ansi::RESET;
}

static void stats_loop(int nthreads, const std::string& mode_str, const std::string& filter_mode_str) {
    (void)mode_str;  // shown in banner, not needed in the stats line
    auto t_start = std::chrono::steady_clock::now();
    uint64_t prev_scanned = 0;

    while (!g_stop.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        uint64_t scanned = g_scanned.load(std::memory_order_relaxed);
        uint64_t hits    = g_hits.load(std::memory_order_relaxed);
        double elapsed   = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - t_start).count();

        uint64_t delta = scanned - prev_scanned;
        prev_scanned   = scanned;
        double rate    = (double)delta;

        // Progress bar (within 10k milestone)
        int progress_pct = (int)(((scanned % 10000) * 30) / 10000);
        std::string bar = std::string(progress_pct, '|') + std::string(30-progress_pct, '.');

        std::string speed_str;
        {
            std::ostringstream ss;
            if (rate >= 1e6)      ss << std::fixed << std::setprecision(2) << rate/1e6 << "M/s";
            else if (rate >= 1e3) ss << std::fixed << std::setprecision(1) << rate/1e3 << "k/s";
            else                  ss << (int)rate << "/s";
            speed_str = ss.str();
        }

        std::cout << "\r" << ansi::CYAN << "[" << bar << "]" << ansi::RESET
                  << "  Scanned: " << ansi::CYAN << scanned << ansi::RESET
                  << "  Hits: " << ansi::GREEN << hits << ansi::RESET
                  << "  Speed: " << ansi::YELLOW << speed_str << ansi::RESET
                  << "  Time: " << ansi::BLUE << (int)elapsed << "s" << ansi::RESET
                  << "  Filter: " << ansi::DIM << filter_mode_str << ansi::RESET
                  << "  Thr: " << nthreads
                  << "     " << std::flush;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// main()
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    // Default args
    std::string tsv_path    = "";   // empty = not provided
    std::string bloom_path  = "";   // empty = not provided
    std::string output_tsv  = "";
    std::string pg_conn     = "";        // PostgreSQL connection string
    int         nthreads    = (int)std::thread::hardware_concurrency();
    int         mode        = MODE_RANDOM;
    int         depth       = 5;        // BIP-32 derivation depth
    int         words       = 0;        // 0=random 12/24, 12, or 24
    uint64_t    show_interval = 0;   // --show N: print panel every N addresses

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--tsv"   || a == "-t") && i+1<argc) tsv_path   = argv[++i];
        else if ((a == "--bloom"   || a == "-b") && i+1<argc) bloom_path = argv[++i];
        else if ((a == "--output"  || a == "-o") && i+1<argc) output_tsv = argv[++i];
        else if ((a == "--pg")                   && i+1<argc) pg_conn    = argv[++i];
        else if ((a == "--threads" || a == "-j") && i+1<argc) nthreads   = std::stoi(argv[++i]);
        else if ((a == "--depth")                && i+1<argc) depth      = std::stoi(argv[++i]);
        else if ((a == "--words")                && i+1<argc) words      = std::stoi(argv[++i]);
        else if (a == "--mode" && i+1<argc) {
            std::string m = argv[++i];
            if (m == "mnemonic") mode = MODE_MNEMONIC;
            else if (m == "mix") mode = MODE_MIX;
            else mode = MODE_RANDOM;
        }
        else if ((a == "--show") && i+1<argc) show_interval = (uint64_t)std::stoull(argv[++i]);
        else if (a == "--help" || a == "-h") {
            std::cout <<
                "Usage: scanner [options]\n"
                "  --tsv     <file>       Sorted TSV of target addresses\n"
                "  --bloom   <file>       Bloom filter file\n"
                "\n"
                "  Filter mode is auto-detected from which files you provide:\n"
                "    --bloom --tsv  →  HYBRID     (bloom pre-filter + exact TSV confirm)\n"
                "    --bloom only   →  BLOOM ONLY (fast, probabilistic, may have false positives)\n"
                "    --tsv only     →  TSV ONLY   (exact match, no bloom, slower)\n"
                "  At least one of --bloom or --tsv must be given.\n"
                "  --output  <file>       Output TSV file for hits\n"
                "  --pg    <connstr>      PostgreSQL connection string — accepts:\n"
                "                         URL:     postgresql://user:pass@host:5432/dbname\n"
                "                         URL:     postgres://user:pass@host/dbname\n"
                "                         Dialect: postgresql+asyncpg://user:pass@host/db\n"
                "                         KV:      host=localhost dbname=btc user=postgres\n"
                "                         (rebuild with -DWITH_PG -lpq to enable)\n"
                "  --threads <N>          Worker threads (default: nproc)\n"
                "  --mode    random|mnemonic|mix  (default: random)\n"
                "              random   = pure random private keys\n"
                "              mnemonic = BIP-39 mnemonic only (12 or 24 words)\n"
                "              mix      = 50%% random keys + 50%% mnemonics\n"
                "  --depth   <N>          BIP-32 derivation depth per path (default: 5)\n"
                "  --words   <0|12|24>    Mnemonic word count, 0=random (default: 0)\n"
                "  --show    <N>          Print full key/address panel every N addresses\n"
                "                         e.g. --show 100000  (every 100k addresses)\n"
                "                         Random mode: shows private key + pubkeys + 5 addrs\n"
                "                         Mnemonic mode: shows phrase + per-type key table\n";
            return 0;
        }
    }
    if (!output_tsv.empty() && !pg_conn.empty()) {
        std::cerr << "Error: specify --output OR --pg, not both.\n";
        return 1;
    }

    if (nthreads < 1) nthreads = 1;

    // Init globals
    g_show_interval.store(show_interval);

    // Init secp256k1
    g_secp = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    print_banner();

    // Validate --words
    if (words != 0 && words != 12 && words != 24) {
        std::cerr << "Error: --words must be 0, 12, or 24.\n"; return 1;
    }

    std::string mode_str = (mode==MODE_RANDOM) ? "RANDOM" :
                           (mode==MODE_MNEMONIC) ? "MNEMONIC" : "MIX";

    // Words string shown in banner
    std::string words_str;
    if (mode == MODE_RANDOM) {
        words_str = "N/A (random key mode)";
    } else if (words == 0) {
        words_str = "random (12 or 24)";
    } else {
        words_str = std::to_string(words) + "-word mnemonics";
    }

    std::cout << ansi::BOLD << "  Mode:    " << ansi::RESET << mode_str << "\n";
    std::cout << ansi::BOLD << "  Threads: " << ansi::RESET << nthreads << "\n";
    if (mode != MODE_RANDOM) {
        std::cout << ansi::BOLD << "  Words:   " << ansi::RESET << words_str << "\n";
        std::cout << ansi::BOLD << "  Depth:   " << ansi::RESET << depth
                  << " addresses per BIP path\n";
    }
    if (!tsv_path.empty())
        std::cout << ansi::BOLD << "  TSV:     " << ansi::RESET << tsv_path << "\n";
    if (!bloom_path.empty())
        std::cout << ansi::BOLD << "  Bloom:   " << ansi::RESET << bloom_path << "\n";
    {
        const char* fmode =
            (!bloom_path.empty() && !tsv_path.empty()) ? "HYBRID (bloom + exact TSV)" :
            (!bloom_path.empty())                       ? "BLOOM ONLY (probabilistic)" :
                                                          "TSV ONLY (exact, no bloom)";
        std::cout << ansi::BOLD << "  Filter:  " << ansi::RESET << fmode << "\n";
    }
    if (!output_tsv.empty())
        std::cout << ansi::BOLD << "  Output:  " << ansi::RESET << output_tsv << "\n";
    if (!pg_conn.empty()) {
        // Mask password in startup banner for security
        std::string pg_display = normalize_pg_conn(pg_conn);
        {
            size_t at = pg_display.rfind('@');
            size_t colon = (at != std::string::npos)
                           ? pg_display.rfind(':', at) : std::string::npos;
            size_t sc = pg_display.find("://");
            if (colon != std::string::npos && sc != std::string::npos && colon > sc + 2)
                pg_display = pg_display.substr(0, colon+1) + "***" + pg_display.substr(at);
        }
        std::cout << ansi::BOLD << "  PG:      " << ansi::RESET << pg_display << "\n";
    }
    if (output_tsv.empty() && pg_conn.empty())
        std::cout << ansi::YELLOW << "  Note: no --output or --pg — hits to stdout only\n"
                  << ansi::RESET;
    if (show_interval > 0)
        std::cout << ansi::BOLD << "  Show:    " << ansi::RESET
                  << "every " << show_interval << " addresses\n";
    std::cout << "\n";

    // Load filter — mode is auto-detected inside load():
    //   bloom + tsv  → HYBRID     (bloom pre-filter + exact binary search)
    //   bloom only   → BLOOM_ONLY (fast, probabilistic)
    //   tsv only     → TSV_ONLY   (exact, no pre-filter)
    auto filter = std::make_unique<HybridFilter>();
    if (!filter->load(bloom_path, tsv_path)) {
        std::cerr << "Failed to load filter.\n";
        return 1;
    }
    std::cout << "\n";

    // Hit storage (TSV or PostgreSQL)
    std::unique_ptr<HitLogger> logger;
    if (!output_tsv.empty()) {
        auto tsv = std::make_unique<TSVLogger>();
        if (!tsv->open(output_tsv)) {
            std::cerr << "Cannot open output: " << output_tsv << "\n";
            return 1;
        }
        logger = std::move(tsv);
    } else if (!pg_conn.empty()) {
        auto pg = std::make_unique<PGLogger>();
        if (!pg->open(pg_conn)) {
            std::cerr << "Cannot connect to PostgreSQL.\n";
            return 1;
        }
        logger = std::move(pg);
    }

    // Launch workers
    std::vector<std::thread> workers;
    workers.reserve(nthreads);
    for (int i = 0; i < nthreads; ++i) {
        WorkerConfig cfg;
        cfg.worker_id = i;
        cfg.mode      = mode;
        cfg.depth          = depth;
        cfg.words          = words;
        cfg.show_interval  = show_interval;
        cfg.filter         = filter.get();
        cfg.logger         = logger.get();
        workers.emplace_back(worker_func, cfg);
    }

    // Stats thread
    std::thread stats_thread(stats_loop, nthreads, mode_str, std::string(filter->mode_name()));

    // Wait for CTRL+C
    std::cout << ansi::DIM << "  Press CTRL+C to stop.\n" << ansi::RESET;

    // Block until interrupted
    for (auto& w : workers) w.join();

    g_stop = true;
    stats_thread.join();

    uint64_t total = g_scanned.load();
    uint64_t hits  = g_hits.load();
    std::cout << "\n\n" << ansi::CYAN << std::string(60,'=') << ansi::RESET << "\n";
    std::cout << ansi::BOLD << "  Session Complete\n" << ansi::RESET;
    std::cout << "  Total Scanned: " << ansi::CYAN << total << ansi::RESET << "\n";
    std::cout << "  Total Hits:    " << ansi::GREEN << hits  << ansi::RESET << "\n";
    std::cout << ansi::CYAN << std::string(60,'=') << ansi::RESET << "\n";

    secp256k1_context_destroy(g_secp);
    return 0;
}
