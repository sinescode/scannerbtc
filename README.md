# Bitcoin Address Scanner

A high-performance C++17 tool for scanning Bitcoin addresses at speed. Generates private keys using multiple strategies, derives all five Bitcoin address types per key, and checks them against a target list using a hybrid Bloom filter + binary search pipeline.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Address Types](#address-types)
- [Filter Modes](#filter-modes)
- [Prerequisites](#prerequisites)
- [Building](#building)
  - [Linux](#linux)
  - [macOS](#macos)
  - [From Source (manual)](#from-source-manual)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [bloom\_builder](#bloom_builder)
  - [scanner](#scanner)
  - [scanner-pg](#scanner-pg-postgresql-variant)
- [Scanning Modes](#scanning-modes)
- [Examples](#examples)
- [Output Format](#output-format)
- [PostgreSQL Integration](#postgresql-integration)
- [Performance](#performance)
- [Project Structure](#project-structure)
- [BIP Standards](#bip-standards)
- [Building from Source (Advanced)](#building-from-source-advanced)


---

## Overview

Bitcoin Address Scanner is a two-binary pipeline:

1. **`bloom_builder`** — reads a sorted TSV of Bitcoin addresses and compiles it into a compact Bloom filter (`.bloom` file).
2. **`scanner`** — generates Bitcoin key material continuously across multiple threads and checks each derived address against the filter.

The scanner supports three key-generation strategies (random, BIP-39 mnemonic, or a mix), derives all five standard address types per key, and can write hits to a TSV file or a PostgreSQL database in real time.

---

## Features

- Derives **all 5 Bitcoin address types** from every private key
- Three **key generation modes**: random, BIP-39 mnemonic (12 or 24 words), or mixed
- Full **BIP-32 HD wallet derivation** (BIP-44 / 49 / 84 / 86 paths)
- **Hybrid filter**: Bloom pre-filter eliminates ~99.9% of misses instantly; exact binary search confirms true positives
- **Memory-mapped TSV** with parallel index build — handles 1B+ address files
- **SipHash-1-3** Bloom filter (same algorithm as the Python reference, bit-for-bit identical)
- **Auto-detected filter mode**: HYBRID, BLOOM_ONLY, or TSV_ONLY based on which files you supply
- **TSV index cache** — second run loads from `.idx` file in milliseconds
- **Blockchair TSV compatible** — automatic header detection and skipping
- Live **ANSI stats display** (keys/sec, hits, elapsed) updated every second
- Optional **PostgreSQL** hit storage (`-DWITH_PG`)
- **Cross-platform**: Linux x86\_64, Linux ARM64, macOS Apple Silicon

---

## How It Works

```
Private Key (random / BIP-39 seed / HD path)
        │
        ▼
  secp256k1 key pair
        │
        ├─► P2PKH   (BIP-44)  →  1...
        ├─► P2SH    (BIP-49)  →  3...
        ├─► P2WPKH  (BIP-84)  →  bc1q...
        ├─► P2WSH   (BIP-84)  →  bc1q...
        └─► P2TR    (BIP-86)  →  bc1p...
                │
                ▼
        HybridFilter.contains(address)
                │
        ┌───────┴────────┐
   Bloom miss          Bloom hit
   (skip — fast)       │
                 Binary search on
                 memory-mapped TSV
                        │
                   Exact match?
                        │
                      HIT → log to TSV / PostgreSQL
```

---

## Address Types

| Type | Prefix | BIP Path | Standard |
|------|--------|----------|----------|
| P2PKH | `1...` | `m/44'/0'/0'/0/i` | BIP-44 |
| P2SH-P2WPKH | `3...` | `m/49'/0'/0'/0/i` | BIP-49 |
| P2WPKH | `bc1q...` | `m/84'/0'/0'/0/i` | BIP-84 |
| P2WSH | `bc1q...` | `m/84'/0'/0'/0/i` | BIP-84 |
| P2TR (Taproot) | `bc1p...` | `m/86'/0'/0'/0/i` | BIP-86 |

Each key generates up to 5 addresses. In mnemonic mode, all paths are derived to the configured depth (default: 5 child keys per path).

---

## Filter Modes

The filter mode is **auto-detected** based on which files you provide at startup:

| Flags passed | Mode | Behaviour |
|---|---|---|
| `--bloom` + `--tsv` | **HYBRID** | Bloom pre-filter → exact binary search confirm. Best accuracy and speed. |
| `--bloom` only | **BLOOM ONLY** | Bloom check only. Fast, but may have rare false positives. |
| `--tsv` only | **TSV ONLY** | Direct binary search on the TSV. Exact but slower without a bloom pre-filter. |

At least one of `--bloom` or `--tsv` must be supplied.

---

## Prerequisites

### Linux (Ubuntu / Debian)

```bash
sudo apt-get install -y libsecp256k1-dev libssl-dev
# For PostgreSQL variant:
sudo apt-get install -y libpq-dev
```

### macOS

```bash
brew install secp256k1 openssl libpq pkg-config
```

---

## Building

### Linux

```bash
git clone https://github.com/yourname/scannerbtc.git
cd scannerbtc

# Build both binaries
make all

# Or individually
make bloom_builder
make scanner

# PostgreSQL variant
make scanner-pg
```

### macOS

```bash
git clone https://github.com/yourname/scannerbtc.git
cd scannerbtc

export BREW_OPENSSL=$(brew --prefix openssl)
export BREW_SECP=$(brew --prefix secp256k1)

make scanner \
  CXXFLAGS="-O3 -std=c++17 -pthread -I${BREW_OPENSSL}/include -I${BREW_SECP}/include" \
  LDFLAGS="-L${BREW_OPENSSL}/lib -L${BREW_SECP}/lib -lsecp256k1 -lssl -lcrypto"
```

### From Source (manual)

```bash
# bloom_builder
g++ -O3 -std=c++17 -march=native -pthread \
    bloom_builder.cpp -o bloom_builder

# scanner
g++ -O3 -std=c++17 -march=native -pthread \
    scanner.cpp -o scanner \
    -lsecp256k1 -lssl -lcrypto

# scanner with PostgreSQL support
g++ -O3 -std=c++17 -march=native -pthread -DWITH_PG \
    scanner.cpp -o scanner-pg \
    -lsecp256k1 -lssl -lcrypto -lpq
```

---

## Quick Start

```bash
# 1. Get a sorted address list (e.g. from Blockchair)
#    https://gz.blockchair.com/bitcoin/addresses/
#    The TSV has a header line — the scanner skips it automatically.

# 2. Build the Bloom filter
./bloom_builder addresses.tsv addresses.bloom

# 3. Run the scanner (hybrid mode — fastest + exact)
./scanner --tsv addresses.tsv --bloom addresses.bloom --output hits.tsv

# 4. Check hits
cat hits.tsv
```

---

## Usage

### bloom\_builder

```
./bloom_builder <input.tsv> <output.bloom> [expected_items] [fpp]
```

| Argument | Default | Description |
|---|---|---|
| `input.tsv` | required | Sorted TSV of Bitcoin addresses (Blockchair format supported) |
| `output.bloom` | required | Output path for the compiled Bloom filter |
| `expected_items` | `0` (auto-count) | Number of addresses. `0` = count automatically |
| `fpp` | `0.001` | Target false-positive probability (e.g. `0.001` = 0.1%) |

**Examples:**

```bash
# Auto-count addresses, 0.1% false positive rate
./bloom_builder addresses.tsv addresses.bloom

# Explicit count, tighter false positive rate
./bloom_builder addresses.tsv addresses.bloom 50000000 0.0001
```

The builder outputs progress, insertion rate (M/s), and runs a self-test on the first 5 addresses after saving.

---

### scanner

```
./scanner [options]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--tsv <file>` | `-t` | — | Sorted TSV of target addresses |
| `--bloom <file>` | `-b` | — | Bloom filter built by `bloom_builder` |
| `--output <file>` | `-o` | stdout | Output TSV for hits |
| `--threads <N>` | `-j` | `nproc` | Number of worker threads |
| `--mode <mode>` | — | `random` | Key generation mode: `random`, `mnemonic`, `mix` |
| `--words <N>` | — | `0` | Mnemonic word count: `0` (random 12/24), `12`, or `24` |
| `--depth <N>` | — | `5` | BIP-32 child keys derived per path (mnemonic mode) |
| `--show <N>` | — | off | Print full key/address panel every N addresses scanned |
| `--pg <connstr>` | — | — | PostgreSQL connection string (requires `scanner-pg`) |
| `--debug` | — | off | Verbose output |
| `--help` | `-h` | — | Show help |

> **Note:** `--output` and `--pg` are mutually exclusive.

---

### scanner-pg (PostgreSQL variant)

Identical to `scanner` but compiled with `-DWITH_PG`. Accepts `--pg` with any of these connection string formats:

```bash
# URL format
./scanner-pg --bloom addresses.bloom --pg "postgresql://user:pass@host:5432/dbname"

# Keyword-value format
./scanner-pg --bloom addresses.bloom --pg "host=localhost dbname=btc user=postgres"
```

---

## Scanning Modes

### `random` (default)

Generates cryptographically random 256-bit private keys using OpenSSL `RAND_bytes`. Each key is independently seeded. This is the fastest mode in terms of keys/second.

```bash
./scanner --bloom addresses.bloom --mode random --threads 8
```

### `mnemonic`

Generates BIP-39 mnemonics (12 or 24 words) and derives addresses through the full HD wallet path for each of the 4 BIP purposes (44, 49, 84, 86), to `--depth` child indices. Each mnemonic yields up to `depth × 5` addresses.

```bash
# 24-word mnemonics, 10 child keys per path
./scanner --bloom addresses.bloom --mode mnemonic --words 24 --depth 10
```

### `mix`

50% random keys, 50% mnemonic-derived. Good for broad coverage.

```bash
./scanner --bloom addresses.bloom --mode mix --threads 4
```

---

## Examples

```bash
# Hybrid mode — recommended for production
./scanner \
  --tsv addresses.tsv \
  --bloom addresses.bloom \
  --output hits.tsv \
  --threads 16 \
  --mode random

# Mnemonic-only scan, 12-word phrases, 5 depth
./scanner \
  --tsv addresses.tsv \
  --bloom addresses.bloom \
  --mode mnemonic \
  --words 12 \
  --depth 5 \
  --threads 8

# Show full key panels every 1M addresses scanned
./scanner \
  --bloom addresses.bloom \
  --mode random \
  --show 1000000

# TSV-only mode (no bloom filter, smaller dataset)
./scanner \
  --tsv small_list.tsv \
  --output hits.tsv \
  --threads 4

# Bloom-only mode (fast, allow rare false positives)
./scanner \
  --bloom addresses.bloom \
  --output hits.tsv

# PostgreSQL output
./scanner-pg \
  --tsv addresses.tsv \
  --bloom addresses.bloom \
  --pg "host=localhost dbname=btc user=postgres password=secret" \
  --threads 16
```

---

## Output Format

### TSV hits file (`--output hits.tsv`)

Each match writes one line:

```
address    wif    priv_hex    compressed_pub_hex    addr_type    derivation_path    mnemonic
```

| Column | Description |
|---|---|
| `address` | The matched Bitcoin address |
| `wif` | Private key in Wallet Import Format |
| `priv_hex` | Raw private key as hex |
| `compressed_pub_hex` | Compressed public key (33 bytes hex) |
| `addr_type` | `P2PKH`, `P2SH-P2WPKH`, `P2WPKH`, `P2WSH`, or `P2TR` |
| `derivation_path` | BIP-32 path (mnemonic mode only, e.g. `m/44'/0'/0'/0/3`) |
| `mnemonic` | BIP-39 phrase (mnemonic mode only) |

### Live stats display

```
  ══════════════════════════════════════════════════════════
   Bitcoin Address Scanner  v1.0
  ══════════════════════════════════════════════════════════
  Mode:     RANDOM
  Threads:  16
  Filter:   HYBRID (bloom + exact TSV)
  Output:   hits.tsv
  ──────────────────────────────────────────────────────────
  Speed:    4,821,033 keys/sec
  Scanned:  1,284,729,041
  Hits:     0
  Elapsed:  04:26:38
```

---

## PostgreSQL Integration

The `scanner-pg` binary (built with `make scanner-pg`) writes hits directly to a PostgreSQL table.

### Table schema

```sql
CREATE TABLE IF NOT EXISTS btc_hits (
    id            SERIAL PRIMARY KEY,
    address       TEXT NOT NULL,
    wif           TEXT NOT NULL,
    priv_hex      TEXT NOT NULL,
    pub_hex       TEXT NOT NULL,
    addr_type     TEXT NOT NULL,
    deriv_path    TEXT,
    mnemonic      TEXT,
    found_at      TIMESTAMPTZ DEFAULT now()
);
```

### Connection string formats accepted

```
postgresql://user:pass@host:5432/dbname
postgres://user:pass@host/dbname
postgresql+asyncpg://user:pass@host/db
host=localhost dbname=btc user=postgres password=secret
```

Passwords are masked in the startup banner for security.

---

## Performance

Performance depends heavily on CPU core count and filter mode. Typical benchmarks on a modern x86\_64 server:

| Mode | Threads | Keys/sec |
|---|---|---|
| Random, HYBRID | 16 | ~5M / sec |
| Random, BLOOM ONLY | 16 | ~6M / sec |
| Mnemonic (depth=5) | 16 | ~800K / sec |
| Mix | 16 | ~2.5M / sec |

**Performance tips:**

- Use `--mode random` for maximum throughput; mnemonic derivation is ~6× slower due to PBKDF2.
- HYBRID mode (bloom + TSV) is recommended — the Bloom pre-filter eliminates ~99.9% of lookups before they hit the binary search, so real-world throughput is very close to BLOOM ONLY.
- Build the Bloom filter with a low false-positive rate (`0.0001`) to minimize false binary-search lookups.
- The TSV index is cached to a `.idx` file beside the TSV on first load. Subsequent runs skip the multi-threaded index build entirely.
- On Linux, `MAP_POPULATE` and `madvise` hints are used automatically to prefetch TSV pages into page cache.

---

## Project Structure

```
scannerbtc/
├── scanner.cpp          # Main scanner binary
├── bloom_builder.cpp    # Bloom filter builder binary
├── bip39_wordlist.hpp   # Embedded BIP-39 English word list (2048 words)
├── Makefile             # Build system
└── .github/
    └── workflows/
        └── release.yml  # CI: Linux x86_64 + ARM64, macOS ARM64
```

---

## BIP Standards

| Standard | Description | Implementation |
|---|---|---|
| BIP-32 | HD wallet key derivation | `derive_master_key()`, `derive_child_key()` |
| BIP-39 | Mnemonic code for keys | `generate_mnemonic()`, `mnemonic_to_seed()` (PBKDF2-HMAC-SHA512, 2048 rounds) |
| BIP-44 | Multi-account HD wallets (P2PKH) | path `m/44'/0'/0'/0/i` |
| BIP-49 | P2SH-P2WPKH HD wallets | path `m/49'/0'/0'/0/i` |
| BIP-84 | Native segwit HD wallets (P2WPKH, P2WSH) | path `m/84'/0'/0'/0/i` |
| BIP-86 | Taproot HD wallets (P2TR) | path `m/86'/0'/0'/0/i` |
| BIP-173 | Bech32 encoding | `bech32_encode()` |
| BIP-350 | Bech32m encoding (Taproot) | `bech32m_encode()` |

---

## Building from Source (Advanced)

### Cross-compiling for Linux ARM64 on x86\_64

```bash
sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libssl-dev:arm64

# Build secp256k1 for ARM64
git clone https://github.com/bitcoin-core/secp256k1.git /tmp/secp256k1
cd /tmp/secp256k1
cmake -B build \
  -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
  -DCMAKE_INSTALL_PREFIX=/usr/aarch64-linux-gnu \
  -DCMAKE_BUILD_TYPE=Release \
  -DSECP256K1_BUILD_TESTS=OFF
cmake --build build -j$(nproc)
sudo cmake --install build

# Build scanner
make scanner \
  CC=aarch64-linux-gnu-gcc \
  CXX=aarch64-linux-gnu-g++ \
  CXXFLAGS="-O3 -std=c++17 -pthread -march=armv8-a -I/usr/aarch64-linux-gnu/include" \
  LDFLAGS="-L/usr/aarch64-linux-gnu/lib -lsecp256k1 -lssl -lcrypto"
```

### Makefile variables

All build variables use `?=` and can be overridden on the command line:

| Variable | Default | Description |
|---|---|---|
| `CXX` | `g++` | C++ compiler |
| `CXXFLAGS` | `-O3 -std=c++17 -pthread -Wall -Wextra -Wshadow` | Compiler flags |
| `LDFLAGS` | _(empty)_ | Linker flags including `-L` paths and `-l` libs |

---

## CI / Release

The GitHub Actions workflow (`.github/workflows/release.yml`) builds release artifacts automatically when you push a version tag.

### Platforms built

| Platform | Binary |
|---|---|
| Linux x86\_64 | `bloom_builder`, `scanner`, `scanner-pg` |
| Linux ARM64 (native runner) | `bloom_builder`, `scanner`, `scanner-pg` |
| Linux ARM64 (cross-compiled) | `bloom_builder`, `scanner` |
| macOS ARM64 (Apple Silicon) | `bloom_builder`, `scanner`, `scanner-pg` |



> **Disclaimer:** This tool is provided for research and educational purposes. Use responsibly and only against address sets you are authorised to work with.
