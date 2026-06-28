# Makefile for Krakken-Disk CLI
# Command-line only build of the Krakken-2048 Encrypted Disk Manager.
# No GTK / no GUI dependencies.
#
# Usage:
#   make                  # build krakken-disk-cli
#   sudo make install     # install globally to /usr/local/bin
#   sudo make uninstall   # remove the global install
#   make clean            # remove build artifacts

# Compiler and flags
CC = gcc

# Detect skylake support, fallback to native
HAS_SKYLAKE := $(shell $(CC) -march=skylake -E - < /dev/null >/dev/null 2>&1 && echo yes || echo no)

ifeq ($(HAS_SKYLAKE),yes)
    ARCH_FLAGS = -march=skylake -mtune=skylake
else
    ARCH_FLAGS = -march=native -mtune=native
endif

CFLAGS = -Wall -Wextra -O3 -mavx2 $(ARCH_FLAGS) \
          -funroll-loops -fomit-frame-pointer -std=gnu11
LDFLAGS = -pthread

# Library flags
SODIUM_CFLAGS = $(shell pkg-config --cflags libsodium)
SODIUM_LIBS = $(shell pkg-config --libs libsodium)
ARGON2_CFLAGS = $(shell pkg-config --cflags libargon2 2>/dev/null || echo "")
ARGON2_LIBS = $(shell pkg-config --libs libargon2 2>/dev/null || echo "-largon2")
FUSE_CFLAGS = $(shell pkg-config --cflags fuse3)
FUSE_LIBS = $(shell pkg-config --libs fuse3)
LIBCRYPTO_CFLAGS = $(shell pkg-config --cflags libcrypto)
LIBCRYPTO_LIBS = $(shell pkg-config --libs libcrypto)

# Combined flags
ALL_CFLAGS = $(CFLAGS) $(SODIUM_CFLAGS) $(ARGON2_CFLAGS) $(FUSE_CFLAGS) $(LIBCRYPTO_CFLAGS) -I. -Ikyber -DKYBER_K=4
ALL_LDFLAGS = $(LDFLAGS) $(SODIUM_LIBS) $(ARGON2_LIBS) $(FUSE_LIBS) $(LIBCRYPTO_LIBS) -lm

# Source files
SRCS = cli.c \
       utils.c \
       krakken_multi.c \
       permut2048.c \
       hybrid_kem.c \
       vfs.c \
       volume.c \
       sector_cache.c \
       fuse_mount.c \
       kyber/kem.c \
       kyber/indcpa.c \
       kyber/poly.c \
       kyber/polyvec.c \
       kyber/ntt.c \
       kyber/reduce.c \
       kyber/cbd.c \
       kyber/fips202.c \
       kyber/verify.c \
       kyber/symmetric-shake.c

# Object files
OBJS = $(SRCS:.c=.o)

# Target executable
TARGET = krakken-disk-cli

# Install prefix
PREFIX ?= /usr/local

# Default target
all: $(TARGET)

# Link executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(ALL_LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile source files
%.o: %.c
	$(CC) $(ALL_CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Clean complete"

# Install globally (requires sudo)
install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/
	@echo "Installed to $(DESTDIR)$(PREFIX)/bin/$(TARGET)"

# Uninstall globally (requires sudo)
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	@echo "Uninstalled from $(DESTDIR)$(PREFIX)/bin/$(TARGET)"

# Build and run
run: $(TARGET)
	./$(TARGET)

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists libsodium && echo "OK libsodium" || echo "MISSING libsodium"
	@pkg-config --exists libcrypto && echo "OK libcrypto (OpenSSL)" || echo "MISSING libcrypto"
	@pkg-config --exists fuse3 && echo "OK fuse3" || echo "MISSING fuse3"
	@pkg-config --exists libargon2 && echo "OK libargon2" || echo "MISSING libargon2 (may use bundled)"

# Help
help:
	@echo "Krakken-Disk CLI Makefile"
	@echo "========================="
	@echo "Targets:"
	@echo "  all          - Build the CLI (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install krakken-disk-cli to $(PREFIX)/bin (requires sudo)"
	@echo "  uninstall    - Remove krakken-disk-cli from $(PREFIX)/bin (requires sudo)"
	@echo "  run          - Build and run the CLI"
	@echo "  check-deps   - Check for required dependencies"
	@echo "  help         - Show this help message"

.PHONY: all clean install uninstall run check-deps help
