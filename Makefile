
# Bitcoin Address Scanner - C++17 Build
# Requires: libsecp256k1-dev libssl-dev

# Targets:
#   make all           - build bloom_builder and scanner (TSV output only)
#   make scanner-pg    - build scanner with PostgreSQL support (-DWITH_PG)
#   make test          - quick smoke test with 5 known addresses
#   make install-deps  - install required apt packages
#   make clean         - remove built binaries and test files
#   make help          - show this message

CXX      ?= g++
CXXFLAGS ?= -O3 -std=c++17 -pthread -Wall -Wextra -Wshadow
LDFLAGS  ?=

# Libraries for each binary
LIBS_BLOOM  =
LIBS_SCAN   = -lsecp256k1 -lssl -lcrypto
LIBS_PG     = -lsecp256k1 -lssl -lcrypto -lpq

.PHONY: all scanner-pg bloom_builder scanner clean install-deps install-deps-pg test help

# ── Default target ───────────────────────────────────────────────────────────
all: bloom_builder scanner

# ── Dependency installation ──────────────────────────────────────────────────
install-deps:
	sudo apt install -y libsecp256k1-dev libssl-dev

install-deps-pg:
	sudo apt install -y libsecp256k1-dev libssl-dev libpq-dev

# ── Build targets ────────────────────────────────────────────────────────────

bloom_builder: bloom_builder.cpp
	$(CXX) $(CXXFLAGS) bloom_builder.cpp -o bloom_builder $(LDFLAGS) $(LIBS_BLOOM)
	@echo "  ✔ bloom_builder built"

scanner: scanner.cpp bip39_wordlist.hpp
	$(CXX) $(CXXFLAGS) scanner.cpp -o scanner $(LDFLAGS) $(LIBS_SCAN)
	@echo "  ✔ scanner built (TSV mode)"

scanner-pg: scanner.cpp bip39_wordlist.hpp
	$(CXX) $(CXXFLAGS) -DWITH_PG `pkg-config --cflags libpq` scanner.cpp -o scanner-pg $(LDFLAGS) $(LIBS_PG)
	@echo "  ✔ scanner built (PostgreSQL mode)"

# ── Smoke test ───────────────────────────────────────────────────────────────
test: bloom_builder scanner
	@echo "  Building test data..."
	@printf '%s\n' \
		'12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S' \
		'1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf' \
		'1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF' \
		'3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy' \
		'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' \
		| sort > test.tsv
	@echo "  Building bloom filter..."
	@./bloom_builder test.tsv test.bloom 5 0.0001
	@echo "  Running scanner (10 seconds, 2 threads, random mode)..."
	@timeout 10 ./scanner \
		--tsv test.tsv \
		--bloom test.bloom \
		--mode random \
		--threads 2 \
		|| true
	@echo "  ✔ Test complete"

# ── Help ─────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "Bitcoin Address Scanner - Build System"
	@echo "======================================"
	@echo ""
	@echo "Build targets:"
	@echo "  make all          Build bloom_builder + scanner (TSV output)"
	@echo "  make bloom_builder  Build only the bloom filter builder"
	@echo "  make scanner      Build scanner with TSV output only"
	@echo "  make scanner-pg   Build scanner with PostgreSQL support"
	@echo ""
	@echo "Setup targets:"
	@echo "  make install-deps    Install: libsecp256k1-dev libssl-dev"
	@echo "  make install-deps-pg Install above + libpq-dev (for PostgreSQL)"
	@echo ""
	@echo "Other targets:"
	@echo "  make test         Run a 10-second smoke test"
	@echo "  make clean        Remove compiled binaries and test files"
	@echo ""
	@echo "Usage examples:"
	@echo "  ./bloom_builder addresses.tsv addresses.bloom 0 0.001"
	@echo "  ./scanner --tsv addresses.tsv --bloom addresses.bloom --mode random"
	@echo "  ./scanner --mode mnemonic --words 24 --depth 10 --threads 8"
	@echo "  ./scanner --mode mix --output hits.tsv --threads \$(nproc)"
	@echo "  ./scanner --pg \"host=localhost dbname=btc user=postgres\""
	@echo ""

# ── Cleanup ──────────────────────────────────────────────────────────────────
clean:
	rm -f bloom_builder scanner scanner-pg test.tsv test.bloom hits.tsv
	@echo "  Cleaned."
