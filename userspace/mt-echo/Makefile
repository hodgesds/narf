# mt-echo — multithreaded SO_REUSEPORT TCP echo server (guest, musl-static)
#           + host-side load generator.
#
# Targets:
#   make server   -> mt_echo_server_x86_64  (static musl ELF for NARF)
#   make loadgen  -> loadgen                 (host dynamic build)
#   make          -> both
#   make verify   -> build server + assert it's a static ELF
#   make clean
#
# The server MUST be built static against musl and placed in NARF's
# user VA range. Mirrors verification/data/musl-demo/REGEN_musl.sh.

MUSL_GCC ?= musl-gcc
HOST_CC  ?= cc

SERVER_SRC := mt_echo_server.c
SERVER_BIN := mt_echo_server_x86_64
LOADGEN_SRC := loadgen.c
LOADGEN_BIN := loadgen

# NARF placement: keep PT_LOAD in PML4[1] (user range), at the same
# text address hello_musl_x86_64 uses. This host's GCC defaults to PIE
# and musl-gcc.specs hardcodes the PIE crt, which cannot link at the
# high VA; we drive the non-PIE crt explicitly. See build.sh for the
# full rationale. To keep this in one place the Makefile just calls
# build.sh for the server.
MUSL_LIB ?= /usr/local/musl/lib
TEXT_ADDR ?= 0x8000001000

LOADGEN_FLAGS := -O2 -pthread

.PHONY: all server loadgen verify clean

all: server loadgen

server: $(SERVER_BIN)

$(SERVER_BIN): $(SERVER_SRC) build.sh
	./build.sh

loadgen: $(LOADGEN_BIN)

$(LOADGEN_BIN): $(LOADGEN_SRC)
	$(HOST_CC) $(LOADGEN_FLAGS) -o $@ $<

verify: server
	@echo "== file =="; file $(SERVER_BIN)
	@echo "== ldd  =="; ldd $(SERVER_BIN) 2>&1 || true
	@file $(SERVER_BIN) | grep -q "statically linked" \
		&& echo "OK: statically linked" \
		|| (echo "FAIL: not static"; exit 1)
	@ldd $(SERVER_BIN) 2>&1 | grep -q "not a dynamic executable" \
		&& echo "OK: ldd says not a dynamic executable" \
		|| (echo "FAIL: ldd reports dynamic deps"; exit 1)

clean:
	rm -f $(SERVER_BIN) $(LOADGEN_BIN)
