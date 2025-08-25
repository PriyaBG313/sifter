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

struct kbase_ioctl_mem_import {
    uint64_t flags; //base_mem_alloc_flags
    uint64_t phandle; //int64
    uint32_t type; //base_mem_import_type
    uint32_t padding; //const
    uint64_t out_flags; //int64
    uint64_t gpu_va; //gpu_addr
    uint64_t va_pages; //int64
};

DEFINE_BPF_MAP(syscall_info_map, HASH, uint64_t, struct syscall_info, 512);
#define bpf_printk(fmt, ...)                                   \
({                                                             \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

SEC("seccomp")
int __always_inline filter_ioctl_KBASE_IOCTL_MEM_IMPORT(struct seccomp_data *ctx) {
    int ret = SECCOMP_RET_ALLOW;
    char dev [] = "/dev/bifrost";

    if (ctx->nr == 29 && ctx->args[1] == 0xc0188016 && bpf_check_fd(dev, ctx->args[0])) {
        struct syscall_info info = {};
        info.fd = ctx->args[0];

    //arg ptr[inout, kbase_ioctl_mem_import] ptr 0xf8ffa0 8
    //arg kbase_ioctl_mem_import kbase_ioctl_mem_import 0xf8ffa0 24
    struct kbase_ioctl_mem_import v73;
    if (bpf_probe_read_sleepable(&v73, sizeof(v73), (void *)ctx->args[2]+0) < 0)
        return SECCOMP_RET_ERRNO | EINVAL;
    //arg base_mem_alloc_flags base_mem_alloc_flags 0xf8ffa0 8
    //arg int64 int64 0xf8ffa0 8
    //arg base_mem_import_type base_mem_import_type 0xf8ffa0 4
    //arg const[0, const] const 0xf8ffa0 4
    //arg int64 int64 0xf8ffa0 8
    //arg int64 int64 0xf8ffa0 8

        info.id = 24;

        if (ret == SECCOMP_RET_ALLOW) {
            uint64_t pid_tgid = bpf_get_current_pid_tgid();
            bpf_syscall_info_map_update_elem(&pid_tgid, &info, BPF_ANY);
        }
    }
    if (ret != SECCOMP_RET_ALLOW) {;
        bpf_printk("ioctl_KBASE_IOCTL_MEM_IMPORT reject\n");
    }
    return ret;
}

char _license[] SEC("license") = "GPL";
