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

struct kbase_ioctl_get_context_id {
    uint32_t id; //int32
};

DEFINE_BPF_MAP(syscall_info_map, HASH, uint64_t, struct syscall_info, 512);
#define bpf_printk(fmt, ...)                                   \
({                                                             \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

SEC("seccomp")
int __always_inline filter_ioctl_KBASE_IOCTL_GET_CONTEXT_ID(struct seccomp_data *ctx) {
    int ret = SECCOMP_RET_ALLOW;
    char dev [] = "/dev/bifrost";

    if (ctx->nr == 29 && ctx->args[1] == 0x80048011 && bpf_check_fd(dev, ctx->args[0])) {
        struct syscall_info info = {};
        info.fd = ctx->args[0];

    //arg ptr[out, kbase_ioctl_get_context_id] ptr 0xf8ffa0 8
    //arg kbase_ioctl_get_context_id kbase_ioctl_get_context_id 0xf8ffa0 4
    struct kbase_ioctl_get_context_id v66;
    if (bpf_probe_read_sleepable(&v66, sizeof(v66), (void *)ctx->args[2]+0) < 0)
        return SECCOMP_RET_ERRNO | EINVAL;
    //arg int32 int32 0xf8ffa0 4

        info.id = 7;

        if (ret == SECCOMP_RET_ALLOW) {
            uint64_t pid_tgid = bpf_get_current_pid_tgid();
            bpf_syscall_info_map_update_elem(&pid_tgid, &info, BPF_ANY);
        }
    }
    if (ret != SECCOMP_RET_ALLOW) {;
        bpf_printk("ioctl_KBASE_IOCTL_GET_CONTEXT_ID reject\n");
    }
    return ret;
}

char _license[] SEC("license") = "GPL";
