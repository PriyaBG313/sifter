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

struct kbase_ioctl_sticky_resource_unmap {
    uint64_t count; //len
    uint64_t address; //ptr64
};

DEFINE_BPF_MAP(syscall_info_map, HASH, uint64_t, struct syscall_info, 512);
#define bpf_printk(fmt, ...)                                   \
({                                                             \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

SEC("seccomp")
int __always_inline filter_ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP(struct seccomp_data *ctx) {
    int ret = SECCOMP_RET_ALLOW;
    char dev [] = "/dev/bifrost";

    if (ctx->nr == 29 && ctx->args[1] == 0x4010801e && bpf_check_fd(dev, ctx->args[0])) {
        struct syscall_info info = {};
        info.fd = ctx->args[0];

    //arg ptr[in, kbase_ioctl_sticky_resource_unmap] ptr 0xf8ffa0 8
    //arg kbase_ioctl_sticky_resource_unmap kbase_ioctl_sticky_resource_unmap 0xf8ffa0 16
    struct kbase_ioctl_sticky_resource_unmap v79;
    if (bpf_probe_read_sleepable(&v79, sizeof(v79), (void *)ctx->args[2]+0) < 0)
        return SECCOMP_RET_ERRNO | EINVAL;
    //arg len len 0xf8ffa0 8
    if (v79.count != 0x1) {
        ret = SECCOMP_RET_ERRNO | EINVAL;
    }
    //arg ptr[in, array[int64]] ptr64 0xf8ffa0 8
    //arg array[int64] array 0xf8ffa0 varlen
    Unhandled array v80;
    int array_v80_offset = 0;
    int array_v80_end = v79.0xf8ffa0 * sizeof(v80);
    if (array_v80_offset + sizeof(v80) >= array_v80_end) {
        goto array_v80_end;
    }
    if (bpf_probe_read_sleepable(&v80, sizeof(v80), (void *)v79.address+array_v80_offset) < 0)
        return SECCOMP_RET_ERRNO | EINVAL;

    array_v80_offset += sizeof(v80);
array_v80_end:

        info.id = 33;

        if (ret == SECCOMP_RET_ALLOW) {
            uint64_t pid_tgid = bpf_get_current_pid_tgid();
            bpf_syscall_info_map_update_elem(&pid_tgid, &info, BPF_ANY);
        }
    }
    if (ret != SECCOMP_RET_ALLOW) {;
        bpf_printk("ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP reject\n");
    }
    return ret;
}

char _license[] SEC("license") = "GPL";
