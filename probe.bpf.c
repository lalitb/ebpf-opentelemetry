#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <sys/types.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} events SEC(".maps");

struct event_t {
    u_int64_t timestamp_start;
    u_int64_t timestamp_end;
    u_int32_t pid;
    char comm[16];
};

// Function entry
SEC("uprobe/target_function")
int trace_function_entry(struct pt_regs *ctx) {
    struct event_t event = {};
    event.timestamp_start = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// Function exit
SEC("uretprobe/target_function")
int trace_function_exit(struct pt_regs *ctx) {
    struct event_t event = {};
    event.timestamp_end = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
