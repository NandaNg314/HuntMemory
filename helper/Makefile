# Makefile for hmkpm_cli (arm64 ELF)
# Supports:
#   1. Local compilation on Android / Termux (clang)
#   2. Cross-compilation using Android NDK (set NDK_HOME or ANDROID_NDK_HOME)
#   3. Push to Android device via adb
#   4. Remote build on device via Termux clang through adb

TARGET := hmkpm_cli
SRC := hmkpm_cli.c
DEVICE_DIR := /data/local/tmp

# Lua is vendored and compiled in, so a script needs no interpreter on the
# device and the CLI stays a single self-contained static binary.
LUA_DIR := vendor/lua
LUA_SRCS := $(sort $(wildcard $(LUA_DIR)/*.c))
INCLUDES := -I $(LUA_DIR)
# loslib's tmpnam use is deprecated upstream and unreachable here: run_lua
# never opens the os library.
WARN_OK := -Wno-deprecated-declarations

# Check if compiling directly on arm64 device (Termux)
UNAME_M := $(shell uname -m 2>/dev/null)
ifeq ($(UNAME_M),aarch64)
    CC := clang
    CFLAGS := -O2 -Wall -Wextra $(WARN_OK)
    LDFLAGS := -static -lm
else
    # Cross-compiling with NDK if available
    NDK ?= $(if $(ANDROID_NDK_HOME),$(ANDROID_NDK_HOME),$(NDK_HOME))
    ifneq ($(NDK),)
        HOST_OS ?= $(shell uname -s 2>/dev/null | tr A-Z a-z)
        ifeq ($(findstring darwin,$(HOST_OS)),darwin)
            HOST_TAG := darwin-x86_64
        else ifeq ($(findstring linux,$(HOST_OS)),linux)
            HOST_TAG := linux-x86_64
        else
            HOST_TAG := windows-x86_64
        endif
        TOOLCHAIN := $(NDK)/toolchains/llvm/prebuilt/$(HOST_TAG)
        CC := $(TOOLCHAIN)/bin/aarch64-linux-android31-clang
    else
        CC ?= aarch64-linux-android-clang
    endif
    # -static: the helper must run under su / magisk context straight from
    # /data/local/tmp, where loading the system libc and bionic allocator is
    # fragile; a static ELF only needs the kernel.
    CFLAGS ?= -O2 -Wall -Wextra $(WARN_OK)
    LDFLAGS ?= -static
endif

all: $(TARGET)

$(TARGET): $(SRC) $(LUA_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC) $(LUA_SRCS) -o $(TARGET) $(LDFLAGS) -lm

push: $(TARGET)
	adb push $(TARGET) $(DEVICE_DIR)/$(TARGET)
	adb shell "su -c 'chmod 755 $(DEVICE_DIR)/$(TARGET)'"

# Build remotely on tablet using Termux clang via adb and pull binary back
# (the vendored Lua sources are pushed too).
remote-build:
	adb push $(SRC) $(DEVICE_DIR)/$(SRC)
	adb push $(LUA_DIR) $(DEVICE_DIR)/vendor/lua
	adb shell "su -c 'export PATH=/data/data/com.termux/files/usr/bin:\$$PATH; export PREFIX=/data/data/com.termux/files/usr; clang -O2 -Wall -Wextra $(WARN_OK) -I $(DEVICE_DIR)/vendor/lua $(DEVICE_DIR)/$(SRC) $(foreach f,$(LUA_SRCS),$(DEVICE_DIR)/$(f)) -o $(DEVICE_DIR)/$(TARGET) -lm && chmod 755 $(DEVICE_DIR)/$(TARGET)'"
	adb pull $(DEVICE_DIR)/$(TARGET) $(TARGET)

test:
	adb shell "su -c '$(DEVICE_DIR)/$(TARGET) probe'"

clean:
	rm -f $(TARGET)

.PHONY: all push remote-build test clean