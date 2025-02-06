#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <sys/types.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);  // ✅ Use Ring Buffer
    __uint(max_entries, 4096);           // ✅ Set the buffer size (adjust as needed)
} events SEC(".maps");

struct event_t {
    u_int64_t timestamp_start;
    u_int64_t timestamp_end;
    u_int32_t pid;
    char comm[16];
};

// Function to send event using ring buffer
static __always_inline void send_event(struct event_t *event) {
    void *ringbuf_event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!ringbuf_event)
        return;
    
    __builtin_memcpy(ringbuf_event, event, sizeof(*event));
    bpf_ringbuf_submit(ringbuf_event, 0);
}

// Function entry
SEC("uprobe/target_function")
int trace_function_entry(struct pt_regs *ctx) {
    struct event_t event = {};
    event.timestamp_start = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    send_event(&event);  // ✅ Send event to ring buffer
    return 0;
}

// Function exit
SEC("uretprobe/target_function")
int trace_function_exit(struct pt_regs *ctx) {
    struct event_t event = {};
    event.timestamp_end = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    
    send_event(&event);  // ✅ Send event to ring buffer
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
