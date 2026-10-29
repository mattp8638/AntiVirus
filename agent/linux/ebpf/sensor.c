// SPDX-License-Identifier: GPL-2.0-only OR MIT
// +build ignore

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256
#define MAX_ARGS 16

// Event Types matching EventKind in our schema
#define EVENT_PROCESS_START 4
#define EVENT_NETWORK_CONNECT 6
#define EVENT_FILE_WRITE 2

struct process_start_event {
    __u32 event_type;
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

struct network_connect_event {
    __u32 event_type;
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u32 daddr;
    __u16 dport;
};

struct file_write_event {
    __u32 event_type;
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

// Map to send events to user space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Kprobe for sys_execve to catch process starts
SEC("kprobe/sys_execve")
int kprobe_sys_execve(struct pt_regs *ctx) {
    struct process_start_event event = {};
    event.event_type = EVENT_PROCESS_START;
    
    __u64 id = bpf_get_current_pid_tgid();
    event.pid = id >> 32;
    event.uid = bpf_get_current_uid_gid();
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    const char *filename_ptr = (const char *)PT_REGS_PARM1(ctx);
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename_ptr);
    
    // Example Enforcement: Prevent execution of a known bad binary name
    // (This is rudimentary, real engine will use YARA/Sigma from user space, but this shows capability)
    // if (event.filename[0] == '/' && event.filename[1] == 'b' && event.filename[2] == 'a' && event.filename[3] == 'd') {
    //    bpf_send_signal(9); // SIGKILL
    // }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// Kprobe for tcp_v4_connect to catch outbound network connections
SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx) {
    struct network_connect_event event = {};
    event.event_type = EVENT_NETWORK_CONNECT;
    
    __u64 id = bpf_get_current_pid_tgid();
    event.pid = id >> 32;
    event.uid = bpf_get_current_uid_gid();
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&event.dport, sizeof(event.dport), &sk->__sk_common.skc_dport);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// Kprobe for vfs_write to catch file writes (e.g. ransomware encryption)
SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx) {
    struct file_write_event event = {};
    event.event_type = EVENT_FILE_WRITE;
    
    __u64 id = bpf_get_current_pid_tgid();
    event.pid = id >> 32;
    event.uid = bpf_get_current_uid_gid();
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    struct dentry *dentry;
    struct qstr d_name;
    
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
    
    // Just read the file name part for simplicity in this example
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), d_name.name);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// The kernel only allows GPL-compatible programs to use these helpers; "Dual MIT/GPL" means MIT or GPL-2.0.
char _license[] SEC("license") = "Dual MIT/GPL";
