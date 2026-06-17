// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define EVENT_HTTP_500 1
#define EVENT_TCP_CONN 2

struct event_hdr {
    __u32 type;
};

struct http_event {
    struct event_hdr hdr;
    __u32 pid;
    __u32 tgid;
    __u8 snippet[32];
};

struct conn_event {
    struct event_hdr hdr;
    __u32 pid;
    __u32 tgid;
    __u32 daddr;
    __u16 dport;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} events SEC(".maps");

// Force struct to be kept in the eBPF object
struct http_event *unused1 __attribute__((unused));
struct conn_event *unused2 __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 pid = id;

    const char *buf = (const char *)ctx->args[1];
    size_t count = (size_t)ctx->args[2];

    if (count < 12) {
        return 0;
    }

    char prefix[12];
    if (bpf_probe_read_user(&prefix, sizeof(prefix), buf) != 0) {
        return 0;
    }

    if (prefix[0] == 'H' && prefix[1] == 'T' && prefix[2] == 'T' && prefix[3] == 'P' &&
        prefix[4] == '/' && prefix[5] == '1' && prefix[6] == '.' &&
        prefix[8] == ' ' && prefix[9] == '5' && prefix[10] == '0' && prefix[11] == '0') {
        
        struct http_event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            return 0;
        }

        e->hdr.type = EVENT_HTTP_500;
        e->pid = pid;
        e->tgid = tgid;
        
        bpf_probe_read_user(&e->snippet, sizeof(e->snippet), buf);
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 pid = id;

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    int addrlen = (int)ctx->args[2];

    if (addrlen != 16) { // sizeof(struct sockaddr_in)
        return 0;
    }

    short family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family) != 0) {
        return 0;
    }

    if (family != 2) { // AF_INET
        return 0;
    }

    struct conn_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->hdr.type = EVENT_TCP_CONN;
    e->pid = pid;
    e->tgid = tgid;
    
    // Read IP (offset 4) and Port (offset 2)
    bpf_probe_read_user(&e->dport, 2, ((char *)addr) + 2);
    bpf_probe_read_user(&e->daddr, 4, ((char *)addr) + 4);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
