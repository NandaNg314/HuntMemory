# Makefile for hmkpm_cli (arm64 ELF)
# Supports:
#   1. Local compilation on Android / Termux (clang)
#   2. Cross-compilation using Android NDK (set NDK_HOME or ANDROID_NDK_HOME)
#   3. Push to Android device via adb
#   4. Remote build on device via Termux clang through adb

TARGET := hmkpm_cli
SRC := hmkpm_cli.c
DEVICE_DIR := /data/local/tmp

# Check if compiling directly on arm64 device (Termux)
UNAME_M := $(shell uname -m 2>/dev/null)
ifeq ($(UNAME_M),aarch64)
    CC := clang
    CFLAGS := -O3 -Wall -Wextra
    LDFLAGS :=
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
    CFLAGS ?= -O3 -Wall -Wextra
    LDFLAGS ?=
endif

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

push: $(TARGET)
	adb push $(TARGET) $(DEVICE_DIR)/$(TARGET)
	adb shell "su -c 'chmod 755 $(DEVICE_DIR)/$(TARGET)'"

# Build remotely on tablet using Termux clang via adb and pull binary back
remote-build:
	adb push $(SRC) $(DEVICE_DIR)/$(SRC)
	adb shell "su -c 'export PATH=/data/data/com.termux/files/usr/bin:\$$PATH; export PREFIX=/data/data/com.termux/files/usr; clang -O3 -Wall -Wextra $(DEVICE_DIR)/$(SRC) -o $(DEVICE_DIR)/$(TARGET) && chmod 755 $(DEVICE_DIR)/$(TARGET)'"
	adb pull $(DEVICE_DIR)/$(TARGET) $(TARGET)

test:
	adb shell "su -c '$(DEVICE_DIR)/$(TARGET) probe'"

clean:
	rm -f $(TARGET)

.PHONY: all push remote-build test clean
