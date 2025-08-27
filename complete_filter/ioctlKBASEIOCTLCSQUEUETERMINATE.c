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

struct kbase_ioctl_cs_queue_terminate {
    uint64_t buffer_gpu_addr; //gpu_addr
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
int __always_inline filter_ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE(struct seccomp_data *ctx) {
    int ret = SECCOMP_RET_ALLOW;
    char dev [] = "/dev/bifrost";

    if (ctx->nr == 29 && ctx->args[1] == 0x40088029 && bpf_check_fd(dev, ctx->args[0])) {
        struct syscall_info info = {};
        info.fd = ctx->args[0];

    //arg ptr[in, kbase_ioctl_cs_queue_terminate] ptr 0xf8ffa0 8
    //arg kbase_ioctl_cs_queue_terminate kbase_ioctl_cs_queue_terminate 0xf8ffa0 8
    	struct kbase_ioctl_cs_queue_terminate v85;
    	if (bpf_probe_read_sleepable(&v85, sizeof(v85), (void *)ctx->args[2]+0) < 0)
        	return SECCOMP_RET_ERRNO | EINVAL;

        info.id = 43;

        if (ret == SECCOMP_RET_ALLOW) {
            uint64_t pid_tgid = bpf_get_current_pid_tgid();
            bpf_syscall_info_map_update_elem(&pid_tgid, &info, BPF_ANY);
        }
    }
    if (ret != SECCOMP_RET_ALLOW) {;
        bpf_printk("ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE reject\n");
    }
    return ret;
}

char _license[] SEC("license") = "GPL";
