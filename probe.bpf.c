#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

struct event_t {
    __u64 timestamp_start;
    __u64 timestamp_end;
    __u32 pid;
    char comm[16];
};

static __always_inline void submit_enter_event(struct pt_regs *ctx) {
    struct event_t event = {};
    
    event.timestamp_start = bpf_ktime_get_ns();
    event.timestamp_end = 0;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    void *ringbuf_event = bpf_ringbuf_reserve(&events, sizeof(event), 0);
    if (!ringbuf_event)
        return;
    
    __builtin_memcpy(ringbuf_event, &event, sizeof(event));
    bpf_ringbuf_submit(ringbuf_event, 0);
}

static __always_inline void submit_exit_event(struct pt_regs *ctx) {
    struct event_t event = {};
    
    event.timestamp_start = 0;
    event.timestamp_end = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    void *ringbuf_event = bpf_ringbuf_reserve(&events, sizeof(event), 0);
    if (!ringbuf_event)
        return;
    
    __builtin_memcpy(ringbuf_event, &event, sizeof(event));
    bpf_ringbuf_submit(ringbuf_event, 0);
}

SEC("uprobe/trace_enter")
int trace_enter(struct pt_regs *ctx) {
    bpf_printk("Enter probe triggered\n"); 
    //submit_enter_event(ctx);
    return 0;
}

SEC("uretprobe/trace_exit")
int trace_exit(struct pt_regs *ctx) {
    bpf_printk("Exit probe triggered\n");

    //submit_exit_event(ctx);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";