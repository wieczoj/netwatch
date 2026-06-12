# NetWatch - Makefile
# Copyright (c) 2026 Janusz Wieczorek
# License: MIT (userspace) / GPL-2.0 (eBPF)

CC = gcc
CLANG = clang

# Userspace C flags
CFLAGS = -O2 -Wall -Wextra -g
GTK_CFLAGS = $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS = $(shell pkg-config --libs gtk+-3.0)
BPF_LIBS = -lbpf -lelf -lz

# eBPF compilation flags
# -Wno-missing-declarations: suppress harmless warnings from vmlinux.h
# -Wno-compare-distinct-pointer-types: suppress BPF helper warnings
# -Wno-pointer-sign: suppress char* vs unsigned char* in BPF helpers
BPF_CFLAGS = -O2 -g -target bpf \
             -D__TARGET_ARCH_x86 \
             -I. \
             -I/usr/include/x86_64-linux-gnu \
             -Wno-missing-declarations \
             -Wno-compare-distinct-pointer-types \
             -Wno-pointer-sign \
             -Wno-unused-value \
             -Wno-unused-variable

# Output binaries
TARGET = netwatch
BPF_OBJECT = netwatch.bpf.o
VMLINUX = vmlinux.h

# Source files
USERSPACE_SRC = netwatch.c
BPF_SRC = netwatch.bpf.c

# Default target
all: $(VMLINUX) $(TARGET) $(BPF_OBJECT)

# Generate vmlinux.h from kernel BTF
$(VMLINUX):
	@echo "Generating vmlinux.h from kernel BTF..."
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "ERROR: /sys/kernel/btf/vmlinux not found!"; \
		echo "Your kernel does not have BTF support enabled."; \
		echo "Minimum required: Linux kernel 5.8 with CONFIG_DEBUG_INFO_BTF=y"; \
		exit 1; \
	fi
	@sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "Done: $@ ($(shell ls -lh $@ 2>/dev/null | awk '{print $$5}'))"

# Compile eBPF program
$(BPF_OBJECT): $(BPF_SRC) $(VMLINUX)
	@echo "Compiling eBPF program..."
	@$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@ 2>&1 | grep -v "warning: declaration does not declare anything" || true
	@echo "Done: $@"

# Compile userspace program
$(TARGET): $(USERSPACE_SRC)
	@echo "Compiling userspace program..."
	@$(CC) $(CFLAGS) $(GTK_CFLAGS) -o $@ $< $(GTK_LIBS) $(BPF_LIBS) -lpthread
	@echo "Done: $@"

# Clean build artifacts (keeps vmlinux.h)
clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(TARGET) $(BPF_OBJECT)
	@echo "Done."

# Full clean (removes vmlinux.h too)
clean-all: clean
	@echo "Removing vmlinux.h..."
	@rm -f $(VMLINUX)
	@echo "Done."

# Run the program
run: all
	sudo ./$(TARGET)

# Show help
help:
	@echo "NetWatch Makefile targets:"
	@echo "  all         - Build everything (default)"
	@echo "  clean       - Remove build artifacts"
	@echo "  clean-all   - Remove all generated files including vmlinux.h"
	@echo "  run         - Build and run (requires sudo)"
	@echo "  help        - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make                # Build the project"
	@echo "  make clean && make  # Clean rebuild"
	@echo "  sudo ./netwatch     # Run NetWatch"

# Declare phony targets
.PHONY: all clean clean-all run help
