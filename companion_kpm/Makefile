TARGET := hm_hwbp.kpm
SRC := hm_hwbp.c
OBJS := hm_hwbp.o

NDK_PATH ?= D:/AndroidSdk/ndk/30.0.14904198
KP_DIR ?= D:/ai/KernelPatch

ifeq ($(OS), Windows_NT)
    PLATFORM := windows-x86_64
else
    PLATFORM := linux-x86_64
endif

CC := $(NDK_PATH)/toolchains/llvm/prebuilt/$(PLATFORM)/bin/aarch64-linux-android31-clang
STRIP := $(NDK_PATH)/toolchains/llvm/prebuilt/$(PLATFORM)/bin/llvm-strip

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS := $(INCLUDE_FLAGS) -Wall -Ofast -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-semantic-interposition -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden

LDFLAGS := -s

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -r -o $@ $^
	$(STRIP) -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack --remove-section=.eh_frame $@

%.o: %.c
	$(CC) $(CFLAGS) -Thm_hwbp.lds -c -O2 -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
