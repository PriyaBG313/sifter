#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <bpf_helpers.h>
#include <linux/errno.h>
#include <sys/types.h>
#include "tracer_id.h"

struct syscall_info {
    uint8_t id;
    uint64_t fd;
};

struct kbase_ioctl_mem_query {
    uint64_t gpu_addr; //gpu_addr
    uint64_t query; //kbase_ioctl_mem_query_flags
    uint64_t value; //int64
};

DEFINE_BPF_MAP(syscall_info_map, HASH, uint64_t, struct syscall_info, 512);
#define bpf_printk(fmt, ...)                                   \
({                                                             \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

SEC("seccomp")
int __always_inline filter_ioctl_KBASE_IOCTL_MEM_QUERY(struct seccomp_data *ctx) {
    int ret = SECCOMP_RET_ALLOW;
    char dev [] = "/dev/bifrost";

    if (ctx->nr == 29 && ctx->args[1] == 0xc0108006 && bpf_check_fd(dev, ctx->args[0])) {
        struct syscall_info info = {};
        info.fd = ctx->args[0];

    //arg ptr[inout, kbase_ioctl_mem_query] ptr 0xf8ffa0 8
    //arg kbase_ioctl_mem_query kbase_ioctl_mem_query 0xf8ffa0 16
    struct kbase_ioctl_mem_query v74;
    if (bpf_probe_read_sleepable(&v74, sizeof(v74), (void *)ctx->args[2]+0) < 0)
        return SECCOMP_RET_ERRNO | EINVAL;
    //arg kbase_ioctl_mem_query_flags kbase_ioctl_mem_query_flags 0xf8ffa0 8
    //arg int64 int64 0xf8ffa0 8

        if (v74.query == 3) {
            info.id = 25;
        } else if (v74.query == 1) {
            info.id = 48;
        }

        if (ret == SECCOMP_RET_ALLOW) {
            uint64_t pid_tgid = bpf_get_current_pid_tgid();
            bpf_syscall_info_map_update_elem(&pid_tgid, &info, BPF_ANY);
        }
    }
    if (ret != SECCOMP_RET_ALLOW) {;
        bpf_printk("ioctl_KBASE_IOCTL_MEM_QUERY reject\n");
    }
    return ret;
}

char _license[] SEC("license") = "GPL";
