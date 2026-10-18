TARGET := hm_hwbp.kpm
SRC := hm_hwbp.c

CC ?= clang
CFLAGS := --target=aarch64-linux-android34 -O2 -fno-builtin -fno-stack-protector -fomit-frame-pointer -Wall -Wextra

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET)
