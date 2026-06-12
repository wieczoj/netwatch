/*
 * NetWatch - eBPF kernel-side monitoring code
 *
 * Copyright (c) 2026 Janusz Wieczorek
 *
 * This file is part of NetWatch.
 * Licensed under GNU General Public License v2.0 (GPL-2.0).
 *
 * GPL v2 is required because this code uses GPL-only kernel helpers
 * (such as bpf_perf_event_output).
 *
 * Repository: https://github.com/wieczoj/netwatch
 *
 * SPDX-License-Identifier: GPL-2.0
 */
// netwatch.bpf.c - Kod eBPF z śledzeniem statusu połączeń
// Wersja: 1.2 - dodane statusy SUCCESS/FAILED

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef bpf_ntohs
#define bpf_ntohs(x)  __builtin_bswap16(x)
#define bpf_htons(x)  __builtin_bswap16(x)
#define bpf_ntohl(x)  __builtin_bswap32(x)
#define bpf_htonl(x)  __builtin_bswap32(x)
#endif

#define MAX_COMM_LEN 16
#define AF_INET 2

// Statusy połączenia
#define STATUS_PENDING  0
#define STATUS_SUCCESS  1
#define STATUS_FAILED   2

// TCP states (z include/net/tcp_states.h)
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3
#define TCP_FIN_WAIT1   4
#define TCP_FIN_WAIT2   5
#define TCP_TIME_WAIT   6
#define TCP_CLOSE       7
#define TCP_CLOSE_WAIT  8
#define TCP_LAST_ACK    9
#define TCP_LISTEN      10
#define TCP_CLOSING     11

struct conn_event {
    __u32 pid;
    __u32 uid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  direction;   // 0=in, 1=out
    __u8  severity;
    __u8  status;       // NOWE: 0=pending, 1=success, 2=failed
    char  comm[MAX_COMM_LEN];
    __u64 ts;
} __attribute__((packed));

// Mapa zdarzeń do userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// Mapa "pending" - przechowuje sockety w trakcie nawiązywania
// klucz = adres struct sock*, wartość = conn_event
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct conn_event);
} pending_conns SEC(".maps");

// ===== Połączenia wychodzące - faza początkowa =====
SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_outbound_connect, struct sock *sk)
{
    struct conn_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.protocol = 6;
    evt.direction = 1;
    evt.status = STATUS_PENDING;
    evt.ts = bpf_ktime_get_ns();

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (family == AF_INET) {
        evt.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        evt.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        evt.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        evt.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

        if (evt.dport < 1024) evt.severity = 2;
        else if (evt.dport < 49152) evt.severity = 1;
        else evt.severity = 0;

        // Zapisz w pending_conns - klucz to adres socketu
        __u64 sock_key = (__u64)sk;
        bpf_map_update_elem(&pending_conns, &sock_key, &evt, BPF_ANY);

        // Wyślij od razu eventcie PENDING (żeby userspace wiedział o próbie)
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}

// ===== Wykrywanie sukcesu - zmiana stanu socketu =====
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(trace_tcp_set_state, struct sock *sk, int state)
{
    __u64 sock_key = (__u64)sk;
    struct conn_event *pending = bpf_map_lookup_elem(&pending_conns, &sock_key);
    
    if (!pending) {
        return 0;  // Nie nasze połączenie
    }

    // ESTABLISHED = sukces!
    if (state == TCP_ESTABLISHED) {
        struct conn_event evt = *pending;
        evt.status = STATUS_SUCCESS;
        evt.ts = bpf_ktime_get_ns();
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
        
        // Usuń z pending - mamy wynik
        bpf_map_delete_elem(&pending_conns, &sock_key);
    }
    // CLOSE bez ESTABLISHED = porażka (np. RST, timeout, blocked)
    else if (state == TCP_CLOSE) {
        struct conn_event evt = *pending;
        evt.status = STATUS_FAILED;
        evt.ts = bpf_ktime_get_ns();
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
        
        bpf_map_delete_elem(&pending_conns, &sock_key);
    }

    return 0;
}

// ===== Połączenia przychodzące =====
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(trace_inbound_accept, struct sock *newsk)
{
    if (!newsk) return 0;

    struct conn_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.protocol = 6;
    evt.direction = 0;
    evt.status = STATUS_SUCCESS;  // accept zwrócił socket = sukces
    evt.ts = bpf_ktime_get_ns();

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    __u16 family = BPF_CORE_READ(newsk, __sk_common.skc_family);

    if (family == AF_INET) {
        evt.saddr = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
        evt.daddr = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr);
        evt.sport = bpf_ntohs(BPF_CORE_READ(newsk, __sk_common.skc_dport));
        evt.dport = BPF_CORE_READ(newsk, __sk_common.skc_num);

        if (evt.dport < 1024) evt.severity = 2;
        else if (evt.dport < 49152) evt.severity = 1;
        else evt.severity = 0;

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
