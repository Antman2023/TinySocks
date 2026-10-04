ZIG ?= zig

# Keep Zig's cache writable when building from a restricted Windows account.
ZIG_GLOBAL_CACHE_DIR ?= $(CURDIR)/.zig-cache-global
ZIG_LOCAL_CACHE_DIR ?= $(CURDIR)/.zig-cache-local
export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR

MIPS_FLAGS := -std=c11 -Oz -flto -Wall -Wextra \
              -ffunction-sections -fdata-sections \
              -fno-unwind-tables -fno-asynchronous-unwind-tables \
              -Wl,--gc-sections -s

ifeq ($(OS),Windows_NT)
HOST_OUTPUT := tinysocks.exe
TEST_OUTPUT := tinysocks-test.exe
FAULT_TEST_OUTPUT := tinysocks-fault-test.exe
PYTHON ?= python
HOST_LIBS := -lws2_32
else
HOST_OUTPUT := tinysocks
TEST_OUTPUT := tinysocks-test
FAULT_TEST_OUTPUT := tinysocks-fault-test
PYTHON ?= python3
HOST_LIBS := -pthread
endif

.PHONY: all mipsel mips host test

all: mipsel

mipsel: tinysocks-mipsel

mips: tinysocks-mips

host: $(HOST_OUTPUT)

test: $(TEST_OUTPUT) $(FAULT_TEST_OUTPUT)
	$(PYTHON) tests/test_proxy.py ./$(TEST_OUTPUT) -v
	./$(FAULT_TEST_OUTPUT) --test-internals
	$(PYTHON) tests/test_proxy.py ./$(FAULT_TEST_OUTPUT) --faults FaultProxyTests \
		ProxyTests.test_domain_connect_and_pipelined_payload \
		ProxyTests.test_udp_domain_and_empty_payload IPv6ProxyTests -v

$(FAULT_TEST_OUTPUT): tests/test_faults.c tinysocks.c Makefile
	$(ZIG) cc -std=c11 -O2 -Wall -Wextra -Werror -DMAX_CLIENTS=2 \
		-DHANDSHAKE_TIMEOUT_SECONDS=1 -DIDLE_TIMEOUT_SECONDS=3 tests/test_faults.c -o $@ $(HOST_LIBS)

$(TEST_OUTPUT): tinysocks.c Makefile
	$(ZIG) cc -std=c11 -O2 -Wall -Wextra -Werror -DMAX_CLIENTS=2 \
		-DHANDSHAKE_TIMEOUT_SECONDS=1 -DIDLE_TIMEOUT_SECONDS=3 tinysocks.c -o $@ $(HOST_LIBS)

tinysocks-mipsel: tinysocks.c Makefile
	$(ZIG) cc -target mipsel-linux-musleabi $(MIPS_FLAGS) tinysocks.c -o $@ -pthread -static

tinysocks-mips: tinysocks.c Makefile
	$(ZIG) cc -target mips-linux-musleabi $(MIPS_FLAGS) tinysocks.c -o $@ -pthread -static

$(HOST_OUTPUT): tinysocks.c Makefile
	$(ZIG) cc -std=c11 -O2 -Wall -Wextra tinysocks.c -o $@ $(HOST_LIBS)
