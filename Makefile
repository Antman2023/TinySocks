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
HOST_LIBS := -lws2_32
else
HOST_OUTPUT := tinysocks
HOST_LIBS := -pthread
endif

.PHONY: all mipsel mips host

all: mipsel

mipsel: tinysocks-mipsel

mips: tinysocks-mips

host: $(HOST_OUTPUT)

tinysocks-mipsel: tinysocks.c Makefile
	$(ZIG) cc -target mipsel-linux-musleabi $(MIPS_FLAGS) tinysocks.c -o $@ -pthread -static

tinysocks-mips: tinysocks.c Makefile
	$(ZIG) cc -target mips-linux-musleabi $(MIPS_FLAGS) tinysocks.c -o $@ -pthread -static

$(HOST_OUTPUT): tinysocks.c Makefile
	$(ZIG) cc -std=c11 -O2 -Wall -Wextra tinysocks.c -o $@ $(HOST_LIBS)
