# lanternet - LAN trust-failure toolkit
#
#   make                 build the Linux binary (lanternet-linux)
#   make android         build the Android arm64 binary (lanternet)
#   make all             both
#   make check           compile with a stricter warning set
#   make clean
#
# Override anything on the command line, e.g.
#   make CC=clang CFLAGS='-O2 -g'
#   make NDKBIN=/path/to/ndk/toolchains/llvm/prebuilt/<host>/bin android

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wshadow
LDFLAGS ?=

# ---- Android NDK (only needed for `make android`) ----
# Probed in this order, first hit wins. Override with ANDROID_NDK_ROOT / NDKBIN.
NDK_ROOT ?= $(lastword $(sort $(wildcard \
    $(ANDROID_NDK_ROOT) $(ANDROID_NDK_HOME) \
    $(addsuffix /*,$(ANDROID_HOME)/ndk $(ANDROID_SDK_ROOT)/ndk) \
    $(addsuffix /*,$(HOME)/Android/Sdk/ndk $(HOME)/Library/Android/sdk/ndk) \
    $(addsuffix /*,/opt/android-sdk/ndk /usr/lib/android-sdk/ndk))))
NDKBIN     ?= $(firstword $(wildcard $(NDK_ROOT)/toolchains/llvm/prebuilt/*/bin))
ANDROID_API ?= 24
ANDROIDCC  ?= $(NDKBIN)/aarch64-linux-android$(ANDROID_API)-clang

SRC     := $(wildcard src/*.c)
HDR     := $(wildcard src/*.h)
OBJ     := $(SRC:.c=.o)

LINUX   := lanternet-linux
ANDROID := lanternet

.PHONY: all linux android clean check

all: linux android

linux: $(LINUX)

$(LINUX): $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)

android: $(ANDROID)

$(ANDROID): $(SRC) $(HDR)
	@command -v $(ANDROIDCC) >/dev/null 2>&1 || { \
	  echo "android: no NDK toolchain found"; \
	  echo "  looked in: ANDROID_NDK_ROOT, ANDROID_NDK_HOME, \$$ANDROID_HOME/ndk,"; \
	  echo "            ~/Android/Sdk/ndk, ~/Library/Android/sdk/ndk, /opt/android-sdk/ndk"; \
	  echo "  override:  make NDKBIN=/path/to/ndk/toolchains/llvm/prebuilt/<host>/bin android"; \
	  exit 1; }
	$(ANDROIDCC) $(CFLAGS) -o $@ $(SRC)

# Objdump-style target: the object list, handy for dependency debugging
%.o: %.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

check: $(HDR)
	@echo "compiling with extra warnings..."
	@$(CC) -O2 -Wall -Wextra -Wshadow -Wformat=2 -Wcast-align -Wstrict-prototypes \
		-o /dev/null $(SRC) && echo "clean"

clean:
	rm -f $(OBJ) $(LINUX) $(ANDROID)
