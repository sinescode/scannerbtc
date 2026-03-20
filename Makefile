# Bitcoin Address Scanner - C++17 Build
CXX      ?= g++
CXXFLAGS ?= -O3 -std=c++17 -pthread -Wall -Wextra -Wshadow
LDFLAGS  ?=

.PHONY: all scanner-pg bloom_builder scanner clean install-deps install-deps-pg test help

all: bloom_builder scanner

install-deps:
	sudo apt install -y libsecp256k1-dev libssl-dev

install-deps-pg:
	sudo apt install -y libsecp256k1-dev libssl-dev libpq-dev

bloom_builder: bloom_builder.cpp
	$(CXX) $(CXXFLAGS) bloom_builder.cpp -o bloom_builder $(LDFLAGS)
	@echo "  ✔ bloom_builder built"

scanner: scanner.cpp bip39_wordlist.hpp
	$(CXX) $(CXXFLAGS) scanner.cpp -o scanner $(LDFLAGS)
	@echo "  ✔ scanner built (TSV mode)"

scanner-pg: scanner.cpp bip39_wordlist.hpp
	$(CXX) $(CXXFLAGS) -DWITH_PG `pkg-config --cflags libpq` scanner.cpp -o scanner-pg $(LDFLAGS)
	@echo "  ✔ scanner built (PostgreSQL mode)"

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

help:
	@echo "Bitcoin Address Scanner - Build System"
	@echo "  make all            Build bloom_builder + scanner"
	@echo "  make scanner-pg     Build scanner with PostgreSQL support"
	@echo "  make test           Run smoke test"
	@echo "  make install-deps   Install apt dependencies"
	@echo "  make clean          Remove built binaries"

clean:
	rm -f bloom_builder scanner scanner-pg test.tsv test.bloom hits.tsv
	@echo "  Cleaned."