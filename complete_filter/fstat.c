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

struct stat {
    uint64_t st_dev; //intptr
    uint64_t st_ino; //intptr
    uint32_t st_mode; //int32
    uint32_t st_nlink; //int32
    uint32_t st_uid; //uid
    uint32_t st_gid; //gid
    uint64_t st_rdev; //intptr
    uint64_t __pad1; //const
    uint64_t st_size; //intptr
    uint32_t st_blksize; //int32
    uint32_t __pad2; //const
    uint64_t st_blocks; //intptr
    uint64_t st_atime; //intptr
    uint64_t st_atime_nsec; //intptr
    uint64_t st_mtime; //intptr
    uint64_t st_mtime_nsec; //intptr
    uint64_t st_ctime; //intptr
    uint64_t st_ctime_nsec; //intptr
    uint32_t __unused4; //const
    uint32_t __unused5; //const
};

DEFINE_BPF_MAP(syscall_info_map, HASH, uint64_t, struct syscall_info, 512);
#define bpf_printk(fmt, ...)                                   \
({                                                             \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

SEC("seccomp")
int __always_inline filter_fstat(struct seccomp_data *ctx) {
    int ret = SECCOMP_RET_ALLOW;
    char dev [] = "/dev/bifrost";

    if (ctx->nr == 80 && bpf_check_fd(dev, ctx->args[0])) {
        struct syscall_info info = {};
        info.fd = ctx->args[0];

    //arg ptr[out, stat] ptr 0xf8ffa0 8
    //arg stat stat 0xf8ffa0 128
    struct stat v58;
    if (bpf_probe_read_sleepable(&v58, sizeof(v58), (void *)ctx->args[1]+0) < 0)
        return SECCOMP_RET_ERRNO | EINVAL;
    //arg intptr intptr 0xf8ffa0 8
    //arg intptr intptr 0xf8ffa0 8
    //arg int32 int32 0xf8ffa0 4
    //arg int32 int32 0xf8ffa0 4
    //arg intptr intptr 0xf8ffa0 8
    //arg const[0, const] const 0xf8ffa0 8
    //arg intptr intptr 0xf8ffa0 8
    //arg int32 int32 0xf8ffa0 4
    //arg const[0, const] const 0xf8ffa0 4
    //arg intptr intptr 0xf8ffa0 8
    //arg intptr intptr 0xf8ffa0 8
    //arg intptr intptr 0xf8ffa0 8
    //arg intptr intptr 0xf8ffa0 8
    //arg intptr intptr 0xf8ffa0 8
    //arg intptr intptr 0xf8ffa0 8
    //arg intptr intptr 0xf8ffa0 8
    //arg const[0, const] const 0xf8ffa0 4
    //arg const[0, const] const 0xf8ffa0 4

        info.id = 1;

        if (ret == SECCOMP_RET_ALLOW) {
            uint64_t pid_tgid = bpf_get_current_pid_tgid();
            bpf_syscall_info_map_update_elem(&pid_tgid, &info, BPF_ANY);
        }
    }
    if (ret != SECCOMP_RET_ALLOW) {;
        bpf_printk("fstat reject\n");
    }
    return ret;
}

char _license[] SEC("license") = "GPL";
