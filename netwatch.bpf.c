#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Definicje endian (gdy brak bpf_endian.h)
#ifndef bpf_ntohs
#define bpf_ntohs(x)  __builtin_bswap16(x)
#define bpf_htons(x)  __builtin_bswap16(x)
#define bpf_ntohl(x)  __builtin_bswap32(x)
#define bpf_htonl(x)  __builtin_bswap32(x)
#endif

#define MAX_COMM_LEN 16
#define AF_INET 2

struct conn_event {
    __u32 pid;
    __u32 uid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  direction;
    __u8  severity;
    char  comm[MAX_COMM_LEN];
    __u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_outbound_connect, struct sock *sk)
{
    struct conn_event evt = {};
    
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.protocol = 6;
    evt.direction = 1;
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
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
    
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(trace_inbound_accept, struct sock *newsk)
{
    if (!newsk) return 0;
    
    struct conn_event evt = {};
    
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.protocol = 6;
    evt.direction = 0;
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
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
