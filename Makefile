CC = gcc
CLANG = clang

CFLAGS = -O2 -Wall -g
GTK_CFLAGS = $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS = $(shell pkg-config --libs gtk+-3.0)
BPF_LIBS = -lbpf -lelf -lz

BPF_CFLAGS = -O2 -g -target bpf \
             -D__TARGET_ARCH_x86 \
             -I. \
             -I/usr/include/x86_64-linux-gnu

all: vmlinux.h netwatch netwatch.bpf.o

vmlinux.h:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

netwatch.bpf.o: netwatch.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c netwatch.bpf.c -o $@

netwatch: netwatch.c
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -o $@ $< $(GTK_LIBS) $(BPF_LIBS) -lpthread

clean:
	rm -f netwatch netwatch.bpf.o

clean-all: clean
	rm -f vmlinux.h

install: all
	sudo install -m 755 netwatch /usr/local/bin/
	sudo install -m 644 netwatch.bpf.o /usr/local/lib/

run: all
	sudo ./netwatch

.PHONY: all clean clean-all install run
