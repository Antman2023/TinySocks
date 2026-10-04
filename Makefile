ZIG ?= zig

# Keep Zig's cache writable when building from a restricted Windows account.
ZIG_GLOBAL_CACHE_DIR ?= $(CURDIR)/.zig-cache-global
ZIG_LOCAL_CACHE_DIR ?= $(CURDIR)/.zig-cache-local
export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR

COMMON_FLAGS := -std=c11 -O2 -Wall -Wextra -Werror
# musl uses GNU_STACK to size pthread stacks; Zig's default hint becomes 8 MiB.
LINUX_FLAGS := $(COMMON_FLAGS) -flto -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,-z,stack-size=1048576 -s
# Zig 0.16's Windows and macOS linkers do not support this Linux LTO setup.
WINDOWS_FLAGS := $(COMMON_FLAGS) -ffunction-sections -fdata-sections -Wl,--gc-sections -s
MACOS_FLAGS := $(COMMON_FLAGS) -Wl,-dead_strip -s

MIPS_FLAGS := -std=c11 -Oz -flto -Wall -Wextra \
              -ffunction-sections -fdata-sections \
              -fno-unwind-tables -fno-asynchronous-unwind-tables \
              -Wl,--gc-sections -Wl,-z,stack-size=1048576 -s

ifeq ($(OS),Windows_NT)
HOST_OUTPUT := tinysocks.exe
TEST_OUTPUT := tinysocks-test.exe
FAULT_TEST_OUTPUT := tinysocks-fault-test.exe
PYTHON ?= python
HOST_LIBS := -lws2_32
HOST_FLAGS := $(WINDOWS_FLAGS)
else
HOST_OUTPUT := tinysocks
TEST_OUTPUT := tinysocks-test
FAULT_TEST_OUTPUT := tinysocks-fault-test
PYTHON ?= python3
HOST_LIBS := -pthread
ifeq ($(shell uname -s),Darwin)
HOST_FLAGS := $(MACOS_FLAGS)
else
HOST_FLAGS := $(LINUX_FLAGS)
endif
endif

RELEASE_OUTPUTS := dist/tinysocks-linux-x86_64 dist/tinysocks-linux-arm64 \
                   dist/tinysocks-linux-armv7 dist/tinysocks-linux-mipsel \
                   dist/tinysocks-linux-mips dist/tinysocks-windows-x86_64.exe \
                   dist/tinysocks-windows-arm64.exe dist/tinysocks-macos-x86_64 \
                   dist/tinysocks-macos-arm64

.PHONY: all mipsel mips host test release test-release

all: mipsel

mipsel: tinysocks-mipsel

mips: tinysocks-mips

host: $(HOST_OUTPUT)

release: $(RELEASE_OUTPUTS)

test-release: $(HOST_OUTPUT)
	$(PYTHON) tests/test_proxy.py ./$(HOST_OUTPUT) --release -v

test: $(TEST_OUTPUT) $(FAULT_TEST_OUTPUT)
	$(PYTHON) tests/test_proxy.py ./$(TEST_OUTPUT) -v
	./$(FAULT_TEST_OUTPUT) --test-internals
	$(PYTHON) tests/test_proxy.py ./$(FAULT_TEST_OUTPUT) --faults FaultProxyTests \
		FaultClientSetupTests FaultTCPIOTests \
		ProxyTests.test_domain_connect_and_pipelined_payload \
		ProxyTests.test_udp_domain_and_empty_payload IPv6ProxyTests \
		ProxyTests.test_udp_numeric_payload_sizes \
		WildcardListenerTests WildcardIPv6ListenerTests \
		WindowsUDPBindingTests WindowsUDPIPv6BindingTests -v

$(FAULT_TEST_OUTPUT): tests/test_faults.c tinysocks.c Makefile
	$(ZIG) cc $(HOST_FLAGS) -DMAX_CLIENTS=2 \
		-DHANDSHAKE_TIMEOUT_SECONDS=1 -DIDLE_TIMEOUT_SECONDS=3 tests/test_faults.c -o $@ $(HOST_LIBS)

$(TEST_OUTPUT): tinysocks.c Makefile
	$(ZIG) cc $(HOST_FLAGS) -DMAX_CLIENTS=2 \
		-DHANDSHAKE_TIMEOUT_SECONDS=1 -DIDLE_TIMEOUT_SECONDS=3 tinysocks.c -o $@ $(HOST_LIBS)

tinysocks-mipsel: tinysocks.c Makefile
	$(ZIG) cc -target mipsel-linux-musleabi $(MIPS_FLAGS) tinysocks.c -o $@ -pthread -static

tinysocks-mips: tinysocks.c Makefile
	$(ZIG) cc -target mips-linux-musleabi $(MIPS_FLAGS) tinysocks.c -o $@ -pthread -static

$(HOST_OUTPUT): tinysocks.c Makefile
	$(ZIG) cc $(HOST_FLAGS) tinysocks.c -o $@ $(HOST_LIBS)

dist:
	mkdir dist

$(RELEASE_OUTPUTS): tinysocks.c Makefile | dist

dist/tinysocks-linux-x86_64:
	$(ZIG) cc -target x86_64-linux-musl $(LINUX_FLAGS) tinysocks.c -o $@ -pthread -static

dist/tinysocks-linux-arm64:
	$(ZIG) cc -target aarch64-linux-musl $(LINUX_FLAGS) tinysocks.c -o $@ -pthread -static

dist/tinysocks-linux-armv7:
	$(ZIG) cc -target arm-linux-musleabihf $(LINUX_FLAGS) tinysocks.c -o $@ -pthread -static

dist/tinysocks-linux-mipsel:
	$(ZIG) cc -target mipsel-linux-musleabi $(MIPS_FLAGS) tinysocks.c -o $@ -pthread -static

dist/tinysocks-linux-mips:
	$(ZIG) cc -target mips-linux-musleabi $(MIPS_FLAGS) tinysocks.c -o $@ -pthread -static

dist/tinysocks-windows-x86_64.exe:
	$(ZIG) cc -target x86_64-windows-gnu $(WINDOWS_FLAGS) tinysocks.c -o $@ -lws2_32

dist/tinysocks-windows-arm64.exe:
	$(ZIG) cc -target aarch64-windows-gnu $(WINDOWS_FLAGS) tinysocks.c -o $@ -lws2_32

dist/tinysocks-macos-x86_64:
	$(ZIG) cc -target x86_64-macos $(MACOS_FLAGS) tinysocks.c -o $@ -pthread

dist/tinysocks-macos-arm64:
	$(ZIG) cc -target aarch64-macos $(MACOS_FLAGS) tinysocks.c -o $@ -pthread
