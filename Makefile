# Bitcoin Address Scanner - C++17 Build
# Requires: libsecp256k1-dev libssl-dev
#
# Targets:
#   make all             build bloom_builder + scanner (TSV output only)
#   make bloom_checker   build the bloom filter checker tool
#   make scanner-pg      build scanner with PostgreSQL support (-DWITH_PG)
#   make test            quick smoke test with 5 known addresses
#   make install-deps    install required apt packages
#   make clean           remove built binaries and test files
#   make help            show this message

CXX      = g++
CXXFLAGS = -O3 -std=c++17 -march=native -pthread -Wall -Wextra -Wshadow

# Libraries
LIBS_BLOOM   =
LIBS_CHECKER =
LIBS_SCAN    = -lsecp256k1 -lssl -lcrypto
LIBS_PG      = -lsecp256k1 -lssl -lcrypto -lpq

HAS_LIBPQ := $(shell pg_config --libdir 2>/dev/null && echo yes || echo no)

.PHONY: all scanner-pg bloom_builder bloom_checker scanner clean install-deps install-deps-pg test help check-libpq

# ── Default target ───────────────────────────────────────────────────────────
all: bloom_builder scanner

# ── Dependency installation ──────────────────────────────────────────────────
install-deps:
	sudo apt install -y libsecp256k1-dev libssl-dev

install-deps-pg:
	sudo apt install -y libsecp256k1-dev libssl-dev libpq-dev

# ── PostgreSQL pre-flight check ──────────────────────────────────────────────
check-libpq:
	@if [ "$(HAS_LIBPQ)" != "yes" ]; then \
		echo ""; \
		echo "  â  ERROR: libpq-dev is not installed."; \
		echo ""; \
		echo "      sudo apt install libpq-dev"; \
		echo "  or: make install-deps-pg"; \
		echo ""; \
		echo "  To build without PostgreSQL: make scanner"; \
		echo ""; \
		exit 1; \
	fi
	@echo "  â libpq-dev found ($(shell pg_config --version))"

# ── Build targets ────────────────────────────────────────────────────────────

bloom_builder: bloom_builder.cpp
	$(CXX) $(CXXFLAGS) bloom_builder.cpp -o bloom_builder $(LIBS_BLOOM)
	@echo "  â bloom_builder built"

# Bloom checker: verify which addresses are missing from a bloom filter
bloom_checker: bloom_checker.cpp
	$(CXX) $(CXXFLAGS) bloom_checker.cpp -o bloom_checker $(LIBS_CHECKER)
	@echo "  â bloom_checker built"

# Scanner — TSV output only (no PostgreSQL dependency)
scanner: scanner.cpp bip39_wordlist.hpp
	$(CXX) $(CXXFLAGS) scanner.cpp -o scanner $(LIBS_SCAN)
	@echo "  â scanner built (TSV mode)"

# Scanner — with PostgreSQL support
scanner-pg: check-libpq scanner.cpp bip39_wordlist.hpp
	$(CXX) $(CXXFLAGS) -DWITH_PG scanner.cpp -o scanner $(LIBS_PG)
	@echo "  â scanner built (PostgreSQL + TSV mode)"

# ── Smoke test ───────────────────────────────────────────────────────────────
test: bloom_builder scanner bloom_checker
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
	@echo "  Running bloom checker..."
	@./bloom_checker test.tsv test.bloom test_missing.tsv
	@echo "  Running scanner (10 seconds, 2 threads, random mode)..."
	@timeout 10 ./scanner \
		--tsv test.tsv \
		--bloom test.bloom \
		--mode random \
		--threads 2 \
		|| true
	@echo "  â Test complete"

# ── Help ─────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "Bitcoin Address Scanner - Build System"
	@echo "======================================"
	@echo ""
	@echo "Build targets:"
	@echo "  make all             Build bloom_builder + scanner (TSV)"
	@echo "  make bloom_builder   Build bloom filter builder"
	@echo "  make bloom_checker   Build bloom checker (find missing addresses)"
	@echo "  make scanner         Build scanner (TSV hits, no PostgreSQL)"
	@echo "  make scanner-pg      Build scanner with PostgreSQL support"
	@echo ""
	@echo "Setup targets:"
	@echo "  make install-deps      Install: libsecp256k1-dev libssl-dev"
	@echo "  make install-deps-pg   Install above + libpq-dev"
	@echo ""
	@echo "Usage examples:"
	@echo "  ./bloom_builder addresses.tsv addresses.bloom 0 0.001"
	@echo "  ./bloom_checker addresses.tsv addresses.bloom missing.tsv"
	@echo "  ./scanner --bloom addresses.bloom --tsv addresses.tsv --mode random"
	@echo "  ./scanner --bloom addresses.bloom --mode mnemonic --words 24 --depth 10"
	@echo "  ./scanner --tsv addresses.tsv --mode mix --output hits.tsv --threads \$(nproc)"
	@echo ""

# ── Cleanup ──────────────────────────────────────────────────────────────────
clean:
	rm -f bloom_builder bloom_checker scanner
	rm -f test.tsv test.bloom test_missing.tsv hits.tsv *.idx
	@echo "  Cleaned."
