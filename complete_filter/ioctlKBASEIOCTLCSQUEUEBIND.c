#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include<linux/types.h>
#include<bpf/bpf_helpers.h>
#include <linux/errno.h>
#include <sys/types.h>
#include "tracer_id.h"

#define DEFINE_BPF_MAP_NO_ACCESSORS(the_map, TYPE, KeyType, ValueType, num_entries) \
struct {                                                                            \
    __uint(type, BPF_MAP_TYPE_##TYPE);                                              \
    __type(key, KeyType);                                                           \
    __type(value, ValueType);                                                       \
    __uint(max_entries, num_entries);                                               \
} the_map SEC(".maps");


#define DEFINE_BPF_MAP_N(the_map, TYPE, KeyType, ValueType, num_entries)              \
    DEFINE_BPF_MAP_NO_ACCESSORS(the_map, TYPE, KeyType, ValueType, num_entries)       \
static inline __always_inline __unused ValueType* bpf_##the_map##_lookup_elem(      \
    const KeyType* k) {                                                             \
    return bpf_map_lookup_elem(&the_map, k);                                        \
};                                                                                  \
                                                                                    \
static inline __always_inline __unused int bpf_##the_map##_update_elem(              \
    const KeyType* k, const ValueType* v, unsigned long long flags) {               \
    return bpf_map_update_elem(&the_map, k, v, flags);                              \
};                                                                                  \
                                                                                    \
static inline __always_inline __unused int bpf_##the_map##_delete_elem(const KeyType* k) { \
    return bpf_map_delete_elem(&the_map, k);                                        \
};


#define DEFINE_BPF_MAP_NO_ACCESSORS_F(the_map, TYPE, KeyType, ValueType, num_entries, flag) \
struct {                                                                            \
    __uint(type, BPF_MAP_TYPE_##TYPE);                                              \
    __type(key, KeyType);                                                           \
    __type(value, ValueType);                                                       \
    __uint(max_entries, num_entries);                                               \
    __uint(map_flags, flag);                                                        \
} the_map SEC(".maps");


#define DEFINE_BPF_MAP_F(the_map, TYPE, KeyType, ValueType, num_entries, flag)        \
    DEFINE_BPF_MAP_NO_ACCESSORS_F(the_map, TYPE, KeyType, ValueType, num_entries, flag) \
static inline __always_inline __unused ValueType* bpf_##the_map##_lookup_elem(      \
    const KeyType* k) {                                                             \
    return bpf_map_lookup_elem(&the_map, k);                                        \
};                                                                                  \
                                                                                    \
static inline __always_inline __unused int bpf_##the_map##_update_elem(              \
    const KeyType* k, const ValueType* v, unsigned long long flags) {               \
    return bpf_map_update_elem(&the_map, k, v, flags);                              \
};                                                                                  \
                                                                                    \
static inline __always_inline __unused int bpf_##the_map##_delete_elem(const KeyType* k) { \
    return bpf_map_delete_elem(&the_map, k);                                        \
};

struct syscall_info {
    uint8_t id;
    uint64_t fd;
};

struct kbase_ioctl_cs_queue_bind {
    uint64_t buffer_gpu_addr; //gpu_addr
    uint8_t group_handle; //cs_queue_group_handle
    uint8_t csi_index; //int8
    char padding[6]; //array
    uint64_t mmap_handle; //int64
};

DEFINE_BPF_MAP_N(syscall_info_map, HASH, uint64_t, struct syscall_info, 512);
/*
#define bpf_printk(fmt, ...)                                   \
({                                                             \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})
*/

SEC("seccomp")
int __always_inline filter_ioctl_KBASE_IOCTL_CS_QUEUE_BIND(struct seccomp_data *ctx) {
    int ret = SECCOMP_RET_ALLOW;
    char dev [] = "/dev/mali0";

    if (ctx->nr == 29 && ctx->args[1] == 0xc0108027 && bpf_check_fd(dev, ctx->args[0])) {
        struct syscall_info info = {};
        info.fd = ctx->args[0];

    //arg ptr[inout, kbase_ioctl_cs_queue_bind] ptr 0xf8ffa0 8
    //arg kbase_ioctl_cs_queue_bind kbase_ioctl_cs_queue_bind 0xf8ffa0 16
    	struct kbase_ioctl_cs_queue_bind v70;
    	if (bpf_probe_read_sleepable(&v70, sizeof(v70), (void *)ctx->args[2]+0) < 0)
        	return SECCOMP_RET_ERRNO | EINVAL;
    //arg int8 int8 0xf8ffa0 1
    //arg int64 int64 0xf8ffa0 8

        info.id = 16;

        if (ret == SECCOMP_RET_ALLOW) {
            uint64_t pid_tgid = bpf_get_current_pid_tgid();
            bpf_syscall_info_map_update_elem(&pid_tgid, &info, BPF_ANY);
        }
    }
    if (ret != SECCOMP_RET_ALLOW) {;
        bpf_printk("ioctl_KBASE_IOCTL_CS_QUEUE_BIND reject\n");
    }
    return ret;
}

char _license[] SEC("license") = "GPL";
