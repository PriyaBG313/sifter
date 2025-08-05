#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <linux/errno.h>
#include <sys/types.h>
#include "tracer_id.h"
#include <stdbool.h>

#define DEFINE_BPF_MAP_NO_ACCESSORS(the_map, TYPE, KeyType, ValueType, num_entries) \
struct {									 \
	__uint(type, BPF_MAP_TYPE_##TYPE);                                       \
        __type(key, KeyType);                                              	 \
        __type(value, ValueType);                                          	 \
        __uint(max_entries, num_entries);                                        \
        } the_map SEC(".maps");							 \


#define DEFINE_BPF_MAP_N(the_map, TYPE, KeyType, ValueType, num_entries)         \
	DEFINE_BPF_MAP_NO_ACCESSORS(the_map, TYPE, KeyType, ValueType, num_entries)	\
static inline __always_inline __unused ValueType* bpf_##the_map##_lookup_elem(               \
            const KeyType* k) {                                                                  \
        return bpf_map_lookup_elem(&the_map, k);                                          \
    };                                                                                           \
                                                                                                 \
    static inline __always_inline __unused int bpf_##the_map##_update_elem(                      \
            const KeyType* k, const ValueType* v, unsigned long long flags) {                    \
        return bpf_map_update_elem(&the_map, k, v, flags);                                \
    };                                                                                           \
                                                                                                 \
    static inline __always_inline __unused int bpf_##the_map##_delete_elem(const KeyType* k) {   \
        return bpf_map_delete_elem(&the_map, k);                                          \
    };


#define DEFINE_BPF_MAP_NO_ACCESSORS_F(the_map, TYPE, KeyType, ValueType, num_entries, flag) \
struct {                                                                        \
        __uint(type, BPF_MAP_TYPE_##TYPE);                                      \
        __type(key, KeyType);                                              	\
        __type(value, ValueType);                                          	\
        __uint(max_entries, num_entries);                                       \
        __uint(map_flags, flag);						\
	} the_map SEC(".maps");							\


#define DEFINE_BPF_MAP_F(the_map, TYPE, KeyType, ValueType, num_entries, flag)         \
        DEFINE_BPF_MAP_NO_ACCESSORS_F(the_map, TYPE, KeyType, ValueType, num_entries, flag) \
	static inline __always_inline __unused ValueType* bpf_##the_map##_lookup_elem(               \
            const KeyType* k) {                                                                  \
        return bpf_map_lookup_elem(&the_map, k);                                          \
    };                                                                                           \
                                                                                                 \
    static inline __always_inline __unused int bpf_##the_map##_update_elem(                      \
            const KeyType* k, const ValueType* v, unsigned long long flags) {                    \
        return bpf_map_update_elem(&the_map, k, v, flags);                                \
    };                                                                                           \
                                                                                                 \
    static inline __always_inline __unused int bpf_##the_map##_delete_elem(const KeyType* k) {   \
        return bpf_map_delete_elem(&the_map, k);                                          \
    };



struct base_jd_udata {
    uint64_t blob[2];
};

struct base_dependency {
	uint8_t atom_id;
	uint8_t dependency_type;
};

struct prfcnt_enum_block_counter;
struct prfcnt_enum_request;
struct prfcnt_enum_sample_info;

struct prfcnt_enum_item_header {
	int16_t item_type;
	int16_t item_version;
};

union prfcnt_enum_union {
	struct prfcnt_enum_block_counter* block_counter;
	struct prfcnt_enum_request* request;
	struct prfcnt_enum_sample_info* sample_info;
};

struct prfcnt_request_mode;
struct prfcnt_request_enable;
struct prfcnt_request_scope;

struct prfcnt_request_item_header {
	int16_t item_type;
	int16_t item_version;
};

union prfcnt_request_union {
	struct prfcnt_request_mode* req_mode;
	struct prfcnt_request_enable* req_enable;
	struct prfcnt_request_scope* req_scope;
};


struct kbase_ioctl_buffer_liveness_update {
    uint64_t live_ranges_address; //ptr64
    uint64_t live_ranges_count; //len
    uint64_t buffer_va_address; //ptr64
    uint64_t buffer_sizes_address; //ptr64
    uint64_t buffer_count; //len
};

struct kbase_pixel_gpu_slc_liveness_mark {
    uint32_t type; //int32
    uint32_t index; //int32
};

struct ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_live_ranges_address_buf {
    struct kbase_pixel_gpu_slc_liveness_mark elem[10]; //array
};

struct ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_va_address_buf {
    uint64_t elem[10]; //array
};

struct ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_sizes_address_buf {
    uint64_t elem[10]; //array
};

struct kbase_ioctl_context_priority_check {
    uint8_t priority; //queue_group_priority
};

struct kbase_ioctl_cs_cpu_queue_info {
    uint64_t buffer; //ptr64
    uint64_t size; //len
};

struct kbase_ioctl_cs_get_glb_iface {
    uint32_t max_group_num; //int32
    uint32_t max_total_stream_num; //int32
    uint64_t groups_ptr; //ptr64
    uint64_t streams_ptr; //ptr64
    uint32_t glb_version; //int32
    uint32_t features; //int32
    uint32_t group_num; //int32
    uint32_t prfcnt_size; //int32
    uint32_t total_stream_num; //int32
    uint32_t instr_featurs; //int32
};

struct kbase_ioctl_cs_queue_bind {
    uint64_t buffer_gpu_addr; //gpu_addr
    uint8_t group_handle; //cs_queue_group_handle
    uint8_t csi_index; //int8
    char padding[6]; //array
    uint64_t mmap_handle; //int64
};

struct kbase_ioctl_cs_queue_group_create {
    uint64_t tiler_mask; //int64
    uint64_t fragment_mask; //int64
    uint64_t compute_mask; //int64
    uint8_t cs_min; //int8
    uint8_t priority; //queue_group_priority
    uint8_t tiler_max; //int8
    uint8_t fragment_max; //int8
    uint8_t compute_max; //int8
    uint8_t csi_handlers; //csf_csi_flags
    char padding[2]; //array
    uint64_t reserved; //int64
    uint8_t group_handle; //cs_queue_group_handle
    char padding_out[3]; //array
    uint32_t group_uid; //int32
};

struct kbase_ioctl_cs_queue_group_create_1_6 {
    uint64_t tiler_mask; //int64
    uint64_t fragment_mask; //int64
    uint64_t compute_mask; //int64
    uint8_t cs_min; //int8
    uint8_t priority; //queue_group_priority
    uint8_t tiler_max; //int8
    uint8_t fragment_max; //int8
    uint8_t compute_max; //int8
    char padding[2]; //array
    char pad1[1]; //pad
    uint64_t reserved; //int64
    uint8_t group_handle; //cs_queue_group_handle
    char padding_out[3]; //array
    uint32_t group_uid; //int32
};

struct kbase_ioctl_cs_queue_group_terminate {
    uint8_t group_handle; //cs_queue_group_handle
    char padding[7]; //array
};

struct kbase_ioctl_cs_queue_kick {
    uint64_t buffer_gpu_addr; //gpu_addr
};

struct base_ioctl_cs_queue_register {
    uint64_t buffer_gpu_addr; //gpu_addr
    uint32_t buffer_size; //int32
    uint8_t priority; //int8
    char padding[6]; //array
    char pad1[5]; //pad
};

struct kbase_ioctl_cs_queue_register_ex {
    uint64_t buffer_gpu_addr; //gpu_addr
    uint32_t buffer_size; //int32
    uint8_t priority; //int8
    char padding[3]; //array
    uint64_t ex_offset_var_addr; //gpu_addr
    uint64_t ex_buffer_base; //gpu_addr
    uint32_t ex_buffer_size; //int32
    uint8_t ex_event_size; //int8
    uint8_t ex_event_state; //int8
    char ex_padding[2]; //array
};

struct kbase_ioctl_cs_queue_terminate {
    uint64_t buffer_gpu_addr; //gpu_addr
};

struct kbase_ioctl_cs_tiler_heap_init {
    uint32_t chunk_size; //tiler_heap_chunk_sizes
    uint32_t initial_chunks; //int32
    uint32_t max_chunks; //int32
    uint16_t target_in_flight; //int16
    uint8_t group_id; //int8
    uint8_t padding; //const
    uint64_t buf_desc_va; //int64
    uint64_t gpu_heap_va; //gpu_heap_va
    uint64_t first_chunk_va; //int64
};

struct kbase_ioctl_cs_tiler_heap_init_1_13 {
    uint32_t chunk_size; //tiler_heap_chunk_sizes
    uint32_t initial_chunks; //int32
    uint32_t max_chunks; //int32
    uint16_t target_in_flight; //int16
    uint8_t group_id; //int8
    uint8_t padding; //const
    uint64_t gpu_heap_va; //gpu_heap_va
    uint64_t first_chunk_va; //int64
};

struct kbase_ioctl_cs_tiler_heap_term {
    uint64_t gpu_heap_va; //gpu_heap_va
};

struct kbase_ioctl_disjoint_query {
    uint32_t counter; //int32
};

struct kbase_ioctl_fence_validate {
    uint32_t fd; //fd_fence
};

struct kbase_ioctl_get_context_id {
    uint32_t id; //int32
};

struct kbase_ioctl_get_cpu_gpu_timeinfo {
    uint32_t request_flags; //base_timerequest_allowed_flags
    char paddings[7]; //array
    char pad1[1]; //pad
    uint64_t sec; //int64
    uint32_t nsec; //int32
    uint32_t padding; //int32
    uint64_t timestamp; //int64
    uint64_t cycle_counter; //int64
};

struct kbase_ioctl_get_ddk_version {
    uint64_t version_buffer; //ptr64
    uint32_t size; //len
    uint32_t padding; //const
};

struct kbase_ioctl_get_gpuprops {
    uint64_t buffer; //ptr64
    uint32_t size; //len
    uint32_t flags; //const
};

struct kbase_ioctl_hwcnt_enable {
    uint64_t dump_buffer; //gpu_addr
    uint32_t jm_bm; //int32
    uint32_t shader_bm; //int32
    uint32_t tiler_bm; //int32
    uint32_t mmu_l2_bm; //int32
};

struct kbase_ioctl_hwcnt_reader_setup {
    uint32_t buffer_count; //int32
    uint32_t jm_bm; //int32
    uint32_t shader_bm; //int32
    uint32_t tiler_bm; //int32
    uint32_t mmu_l2_bm; //int32
};

struct kbase_ioctl_hwcnt_values {
    uint64_t data; //ptr64
    uint32_t size; //len
    uint32_t padding; //const
};

struct kbase_ioctl_job_submit {
    uint64_t addr; //ptr64
    uint32_t nr_atoms; //len
    uint32_t stride; //const
};

struct base_jd_atom_v2 {
    uint64_t jc; //int64
    struct base_jd_udata udata; //base_jd_udata
    uint64_t extres_list; //int64
    uint16_t nr_extres; //int16
    uint16_t compat_core_req; //int16
    struct base_dependency pre_dep[2]; //array
    uint8_t atom_number; //int8
    uint8_t prio; //base_jd_prio
    uint8_t device_nr; //int8
    uint8_t jobslot; //int8
    uint32_t core_req; //base_jd_core_req
    uint8_t renderpass_id; //int8
    char padding[7]; //array
};

struct ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_addr_buf {
    struct base_jd_atom_v2 elem[10]; //array
};

struct kbase_ioctl_kcpu_queue_new {
    uint8_t id; //kcpu_queue_id
    char pad[7]; //array
};

struct kbase_ioctl_kcpu_queue_delete {
    uint8_t id; //kcpu_queue_id
    char pad[7]; //array
};

struct kbase_ioctl_kcpu_queue_enqueue {
    uint64_t addr; //gpu_addr
    uint32_t nr_commands; //len
    uint8_t id; //kcpu_queue_id
    char padding[3]; //array
};

struct kbase_ioctl_kinstr_prfcnt_enum_info {
    uint32_t info_item_size; //len
    uint32_t info_item_count; //bytesize
    uint64_t info_list_ptr; //ptr
};

struct prfcnt_enum_item {
    struct prfcnt_enum_item_header hdr; //prfcnt_enum_item_header
    char pad1[4]; //pad
    union prfcnt_enum_union     u; //prfcnt_enum_union
};

struct ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_info_list_ptr_buf {
    struct prfcnt_enum_item elem[10]; //array
};

struct kbase_ioctl_kinstr_prfcnt_setup {
    uint32_t request_item_count; //len
    uint32_t request_item_size; //int32
    uint64_t requests_ptr; //ptr64
    uint32_t prfcnt_metadata_item_size; //int32
    uint32_t prfcnt_mmap_size_bytes; //int32
};

struct prfcnt_request_item {
    struct prfcnt_request_item_header hdr; //prfcnt_request_item_header
    char pad1[4]; //pad
    union prfcnt_request_union     u; //prfcnt_request_union
};

struct ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_requests_ptr_buf {
    struct prfcnt_request_item elem[10]; //array
};

struct kbase_ioctl_mem_alias {
    uint64_t flags; //base_mem_alloc_flags
    uint64_t stride; //int64
    uint64_t nents; //len
    uint64_t aliasing_info; //ptr64
    uint64_t out_flags; //int64
    uint64_t gpu_va; //gpu_addr
    uint64_t va_pages; //int64
};

struct base_mem_aliasing_info {
    uint64_t handle; //gpu_addr
    uint64_t offset; //int64
    uint64_t length; //int64
};

struct ioctl_KBASE_IOCTL_MEM_ALIAS_arg_aliasing_info_buf {
    struct base_mem_aliasing_info elem[10]; //array
};

struct kbase_ioctl_mem_alloc {
    uint64_t va_pages; //int64
    uint64_t commit_pages; //int64
    uint64_t extent; //int64
    uint64_t flags; //base_mem_alloc_flags
    uint64_t out_flags; //int64
    uint64_t gpu_va; //gpu_addr
};

struct kbase_ioctl_mem_alloc_ex {
    uint64_t va_pages; //int64
    uint64_t commit_pages; //int64
    uint64_t extension; //int64
    uint64_t flags; //base_mem_alloc_flags
    uint64_t fixed_address; //int64
    char extra[24]; //array
    uint64_t out_flags; //int64
    uint64_t gpu_va; //gpu_addr
};

struct kbase_ioctl_mem_commit {
    uint64_t gpu_addr; //gpu_addr
    uint64_t pages; //int64
};

struct kbase_ioctl_mem_exec_init {
    uint64_t va_pages; //int64
};

struct kbase_ioctl_mem_find_cpu_offset {
    uint64_t gpu_addr; //gpu_addr
    uint64_t cpu_addr; //user_addr
    uint64_t size; //int64
    uint64_t offset; //int64
};

struct kbase_ioctl_mem_find_gpu_start_and_offset {
    uint64_t gpu_addr; //gpu_addr
    uint64_t size; //int64
    uint64_t start; //gpu_addr
    uint64_t offset; //int64
};

struct kbase_ioctl_mem_flags_change {
    uint64_t gpu_va; //gpu_addr
    uint64_t flags; //base_mem_alloc_flags
    uint64_t mask; //int64
};

struct kbase_ioctl_mem_free {
    uint64_t gpu_addr; //gpu_addr
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

struct kbase_ioctl_mem_jit_init {
    uint64_t va_pages; //int64
    uint8_t max_allocations; //int8
    uint8_t trim_level; //int8
    uint8_t group_id; //int8
    char padding[5]; //array
    uint64_t phys_pages; //int64
};

struct kbase_ioctl_mem_jit_init_10_2 {
    uint64_t va_pages; //int64
};

struct kbase_ioctl_mem_jit_init_11_5 {
    uint64_t va_pages; //int64
    uint8_t max_allocations; //int8
    uint8_t trim_level; //int8
    uint8_t group_id; //int8
    char padding[5]; //array
};

struct kbase_ioctl_mem_profile_add {
    uint64_t buffer; //ptr64
    uint32_t len; //len
    uint32_t padding; //const
};

struct kbase_ioctl_mem_query {
    uint64_t gpu_addr; //gpu_addr
    uint64_t query; //kbase_ioctl_mem_query_flags
    uint64_t value; //int64
};

struct kbase_ioctl_mem_sync {
    uint64_t handle; //gpu_addr
    uint64_t user_addr; //user_addr
    uint64_t size; //int64
    uint8_t type; //base_syncset_op_flags
    char padding[7]; //array
};

struct kbase_ioctl_read_user_page {
    uint32_t offset; //user_offsets
    uint32_t padding; //const
    uint32_t val_lo; //int32
    uint32_t val_hi; //int32
};

struct kbase_ioctl_set_flags {
    uint32_t create_flags; //basep_context_create_kernel_flags
};

struct kbase_ioctl_set_limited_core_count {
    uint8_t max_core_count; //int8
};

struct kbase_ioctl_soft_event_update {
    uint64_t event; //gpu_addr
    uint32_t new_status; //int32
    uint32_t flags; //const
};

struct kbase_ioctl_sticky_resource_map {
    uint64_t count; //len
    uint64_t address; //ptr64
};

struct ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_address_buf {
    uint64_t elem[10]; //array
};

struct kbase_ioctl_sticky_resource_unmap {
    uint64_t count; //len
    uint64_t address; //ptr64
};

struct ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_address_buf {
    uint64_t elem[10]; //array
};

struct kbase_ioctl_stream_create {
    char name[32]; //array
};

struct kbase_ioctl_tlstream_acquire {
    uint32_t flags; //int32
};

struct kbase_ioctl_version_check {
    uint16_t major; //int16
    uint16_t minor; //int16
};

typedef struct {
    uint64_t ignore;
    int64_t id;
    uint64_t regs[6];
} sys_enter_args;

typedef struct {
    uint64_t ignore;
    int64_t id;
    uint64_t ret;
} sys_exit_args;

typedef struct {
	uint64_t ts;
	uint64_t id;
	uint64_t args[6];
} sys_enter_ent_t;

typedef struct {
	uint64_t ts;
	uint64_t id;
	uint64_t nr;
	uint64_t ret;
} sys_exit_ent_t;

typedef struct {
    struct bpf_spin_lock lock;
    uint32_t val;
} trace_entry_ctr_t;

typedef struct {
	char chars[16];
} comm_string;

DEFINE_BPF_MAP_N(syscall_fd_mask, ARRAY, int, uint8_t, 461);
DEFINE_BPF_MAP_N(traced_tgid_map, HASH, uint32_t, uint32_t, 1024);
DEFINE_BPF_MAP_N(traced_pid_tgid_comm_map, HASH, uint64_t, comm_string, 65536);
DEFINE_BPF_MAP_N(target_prog_comm_map, HASH, comm_string, uint32_t, 128);
DEFINE_BPF_MAP_N(comm_setting_pid_tgid_map, HASH, uint64_t, int, 1024);
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg, ARRAY, int, struct kbase_ioctl_buffer_liveness_update, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_live_ranges_address, ARRAY, int, struct ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_live_ranges_address_buf, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_va_address, ARRAY, int, struct ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_va_address_buf, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_sizes_address, ARRAY, int, struct ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_sizes_address_buf, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK_arg, ARRAY, int, struct kbase_ioctl_context_priority_check, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP_arg, ARRAY, int, struct kbase_ioctl_cs_cpu_queue_info, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_EVENT_SIGNAL_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_EVENT_SIGNAL_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg, ARRAY, int, struct kbase_ioctl_cs_get_glb_iface, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_groups_ptr, ARRAY, int, uint64_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_streams_ptr, ARRAY, int, uint64_t, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_QUEUE_BIND_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_BIND_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_BIND_arg, ARRAY, int, struct kbase_ioctl_cs_queue_bind, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg, ARRAY, int, struct kbase_ioctl_cs_queue_group_create, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg, ARRAY, int, struct kbase_ioctl_cs_queue_group_create_1_6, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE_arg, ARRAY, int, struct kbase_ioctl_cs_queue_group_terminate, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_QUEUE_KICK_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_KICK_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_KICK_arg, ARRAY, int, struct kbase_ioctl_cs_queue_kick, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_arg, ARRAY, int, struct base_ioctl_cs_queue_register, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_arg, ARRAY, int, struct kbase_ioctl_cs_queue_register_ex, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE_arg, ARRAY, int, struct kbase_ioctl_cs_queue_terminate, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg, ARRAY, int, struct kbase_ioctl_cs_tiler_heap_init, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_arg, ARRAY, int, struct kbase_ioctl_cs_tiler_heap_init_1_13, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_CS_TILER_HEAP_TERM_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_TILER_HEAP_TERM_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_CS_TILER_HEAP_TERM_arg, ARRAY, int, struct kbase_ioctl_cs_tiler_heap_term, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_DISJOINT_QUERY_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_DISJOINT_QUERY_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_DISJOINT_QUERY_arg, ARRAY, int, struct kbase_ioctl_disjoint_query, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_FENCE_VALIDATE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_FENCE_VALIDATE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_FENCE_VALIDATE_arg, ARRAY, int, struct kbase_ioctl_fence_validate, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_GET_CONTEXT_ID_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_GET_CONTEXT_ID_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_GET_CONTEXT_ID_arg, ARRAY, int, struct kbase_ioctl_get_context_id, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_arg, ARRAY, int, struct kbase_ioctl_get_cpu_gpu_timeinfo, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_GET_DDK_VERSION_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_GET_DDK_VERSION_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_GET_DDK_VERSION_arg, ARRAY, int, struct kbase_ioctl_get_ddk_version, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_GET_GPUPROPS_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_GET_GPUPROPS_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_GET_GPUPROPS_arg, ARRAY, int, struct kbase_ioctl_get_gpuprops, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_HWCNT_CLEAR_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_HWCNT_CLEAR_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_HWCNT_DUMP_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_HWCNT_DUMP_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_HWCNT_ENABLE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_HWCNT_ENABLE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_HWCNT_ENABLE_arg, ARRAY, int, struct kbase_ioctl_hwcnt_enable, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_arg, ARRAY, int, struct kbase_ioctl_hwcnt_reader_setup, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_HWCNT_SET_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_HWCNT_SET_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_HWCNT_SET_arg, ARRAY, int, struct kbase_ioctl_hwcnt_values, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_JOB_SUBMIT_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_JOB_SUBMIT_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_JOB_SUBMIT_arg, ARRAY, int, struct kbase_ioctl_job_submit, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_addr, ARRAY, int, struct ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_addr_buf, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_KCPU_QUEUE_CREATE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KCPU_QUEUE_CREATE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KCPU_QUEUE_CREATE_arg, ARRAY, int, struct kbase_ioctl_kcpu_queue_new, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_KCPU_QUEUE_DELETE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KCPU_QUEUE_DELETE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KCPU_QUEUE_DELETE_arg, ARRAY, int, struct kbase_ioctl_kcpu_queue_delete, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE_arg, ARRAY, int, struct kbase_ioctl_kcpu_queue_enqueue, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg, ARRAY, int, struct kbase_ioctl_kinstr_prfcnt_enum_info, 4096)
//priya
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_info_list_ptr, ARRAY, int, struct ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_info_list_ptr_buf, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_requests_ptr, ARRAY, int, struct ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_requests_ptr_buf, 4096)
//
	
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg, ARRAY, int, struct kbase_ioctl_kinstr_prfcnt_setup, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_ALIAS_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_ALIAS_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_ALIAS_arg, ARRAY, int, struct kbase_ioctl_mem_alias, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_ALIAS_arg_aliasing_info, ARRAY, int, struct ioctl_KBASE_IOCTL_MEM_ALIAS_arg_aliasing_info_buf, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_ALLOC_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_ALLOC_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_ALLOC_arg, ARRAY, int, struct kbase_ioctl_mem_alloc, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_ALLOC_EX_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_ALLOC_EX_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_ALLOC_EX_arg, ARRAY, int, struct kbase_ioctl_mem_alloc_ex, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_COMMIT_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_COMMIT_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_COMMIT_arg, ARRAY, int, struct kbase_ioctl_mem_commit, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_EXEC_INIT_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_EXEC_INIT_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_EXEC_INIT_arg, ARRAY, int, struct kbase_ioctl_mem_exec_init, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET_arg, ARRAY, int, struct kbase_ioctl_mem_find_cpu_offset, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET_arg, ARRAY, int, struct kbase_ioctl_mem_find_gpu_start_and_offset, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE_arg, ARRAY, int, struct kbase_ioctl_mem_flags_change, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_FREE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_FREE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_FREE_arg, ARRAY, int, struct kbase_ioctl_mem_free, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_IMPORT_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_IMPORT_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_IMPORT_arg, ARRAY, int, struct kbase_ioctl_mem_import, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_JIT_INIT_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_JIT_INIT_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_JIT_INIT_arg, ARRAY, int, struct kbase_ioctl_mem_jit_init, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_JIT_INIT_10_2_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_JIT_INIT_10_2_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_JIT_INIT_10_2_arg, ARRAY, int, struct kbase_ioctl_mem_jit_init_10_2, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5_arg, ARRAY, int, struct kbase_ioctl_mem_jit_init_11_5, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_PROFILE_ADD_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_PROFILE_ADD_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_PROFILE_ADD_arg, ARRAY, int, struct kbase_ioctl_mem_profile_add, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_QUERY_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_QUERY_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_QUERY_arg, ARRAY, int, struct kbase_ioctl_mem_query, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_MEM_SYNC_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_SYNC_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_MEM_SYNC_arg, ARRAY, int, struct kbase_ioctl_mem_sync, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_POST_TERM_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_POST_TERM_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_READ_USER_PAGE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_READ_USER_PAGE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_READ_USER_PAGE_arg, ARRAY, int, struct kbase_ioctl_read_user_page, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_SET_FLAGS_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_SET_FLAGS_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_SET_FLAGS_arg, ARRAY, int, struct kbase_ioctl_set_flags, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_SET_LIMITED_CORE_COUNT_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_SET_LIMITED_CORE_COUNT_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_SET_LIMITED_CORE_COUNT_arg, ARRAY, int, struct kbase_ioctl_set_limited_core_count, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE_arg, ARRAY, int, struct kbase_ioctl_soft_event_update, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg, ARRAY, int, struct kbase_ioctl_sticky_resource_map, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_address, ARRAY, int, struct ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_address_buf, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg, ARRAY, int, struct kbase_ioctl_sticky_resource_unmap, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_address, ARRAY, int, struct ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_address_buf, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_STREAM_CREATE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_STREAM_CREATE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_STREAM_CREATE_arg, ARRAY, int, struct kbase_ioctl_stream_create, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_TLSTREAM_ACQUIRE_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_TLSTREAM_ACQUIRE_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_TLSTREAM_ACQUIRE_arg, ARRAY, int, struct kbase_ioctl_tlstream_acquire, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_TLSTREAM_FLUSH_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_TLSTREAM_FLUSH_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_VERSION_CHECK_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_VERSION_CHECK_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_VERSION_CHECK_arg, ARRAY, int, struct kbase_ioctl_version_check, 4096)
DEFINE_BPF_MAP_F(ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED_ent, ARRAY, int, sys_enter_ent_t, 4096)
DEFINE_BPF_MAP_N(ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED_arg, ARRAY, int, struct kbase_ioctl_version_check, 4096)
DEFINE_BPF_MAP_F(mmap_bifrost_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(mmap_bifrost_ent, ARRAY, int, sys_enter_ent_t, 1024)
DEFINE_BPF_MAP_F(other_syscalls_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(other_syscalls_ent, ARRAY, int, sys_enter_ent_t, 262144)
DEFINE_BPF_MAP_N(other_syscalls_nr, ARRAY, int, int, 262144)
DEFINE_BPF_MAP_F(syscall_return_ctr, ARRAY, int, trace_entry_ctr_t, 1, BPF_F_LOCK)
DEFINE_BPF_MAP_N(syscall_return_ent, ARRAY, int, sys_exit_ent_t, 262144)

/*
#define bpf_printk(fmt, ...)                                   \
({                                                             \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})
*/

#define get_and_inc_ctr(v, ctr_name, size_bits)                        \
    int ctr_i = 0;                                                     \
    trace_entry_ctr_t *ctr = bpf_##ctr_name##_ctr_lookup_elem(&ctr_i); \
    if (ctr) {                                                         \
        bpf_spin_lock(&ctr->lock);                                     \
        idx = ctr->val & ((1 << size_bits)-1);                         \
        ctr->val = ctr->val + 1;                                       \
  	    bpf_spin_unlock(&ctr->lock);                                   \
    } else {                                                           \
    	v = -1;                                                        \
    }

int __always_inline get_current_pid() {
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid & 0x00000000ffffffff;
    return pid;
}

#define TIF_32BIT       22  /* 32bit process */
#define _TIF_32BIT      (1 << TIF_32BIT)

int __always_inline process_mode() {
	uint64_t current = bpf_get_current_task();
	uint64_t flags;
	int ret = bpf_probe_read(&flags, 8, (void *)current);
	if (ret != 0)
		return 0;

	return (flags & _TIF_32BIT)? 32 : 64;
}

bool __always_inline is_current_prog_target() {
	comm_string comm = {};
	if (bpf_get_current_comm(&comm, 16))
		return false;
	return (bpf_target_prog_comm_map_lookup_elem(&comm) != NULL);
}

bool __always_inline is_forking_syscall(int nr, int is_32bit) {
	if (is_32bit) {
		return (nr == 2 || nr == 120 || nr == 190);
	} else {
		return (nr == 220);
	}
}

bool __always_inline is_comm_setting_syscall(int nr, bool is_32bit) {
	if (is_32bit) {
		return (nr == 11 || nr == 387);
	} else {
		return (nr == 167 || nr == 281);
	}
}

uint64_t __always_inline check_syscall_fd(sys_enter_args *ctx)
{
    uint64_t fd_is_dev = 0;
    int syscall_nr = ctx->id;
    uint8_t *fd_mask = bpf_syscall_fd_mask_lookup_elem(&syscall_nr);
    if (fd_mask) {
        char dev [] = "/dev/bifrost";
        if ((*fd_mask >> 0) & 0x01 && 
            (bpf_check_fd(dev, ctx->regs[0]))) {
            fd_is_dev = ctx->regs[0];
        }
        if ((*fd_mask >> 1) & 0x01 && 
            (bpf_check_fd(dev, ctx->regs[1]))) {
            fd_is_dev = ctx->regs[1];
        }
        if ((*fd_mask >> 2) & 0x01 && 
            (bpf_check_fd(dev, ctx->regs[2]))) {
            fd_is_dev = ctx->regs[2];
        }
        if ((*fd_mask >> 3) & 0x01 && 
            (bpf_check_fd(dev, ctx->regs[3]))) {
            fd_is_dev = ctx->regs[3];
        }
        if ((*fd_mask >> 4) & 0x01 && 
            (bpf_check_fd(dev, ctx->regs[4]))) {
            fd_is_dev = ctx->regs[4];
        }
        if ((*fd_mask >> 5) & 0x01 && 
            (bpf_check_fd(dev, ctx->regs[5]))) {
            fd_is_dev = ctx->regs[5];
        }
    }
    return fd_is_dev;
}

int __always_inline trace_mmap_bifrost(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, mmap_bifrost, 10);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_mmap_bifrost_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_buffer_liveness_update] ptr 0xf8fe80 8
    //arg kbase_ioctl_buffer_liveness_update kbase_ioctl_buffer_liveness_update 0xf8fe80 40
    struct kbase_ioctl_buffer_liveness_update v0;
    if (bpf_probe_read_sleepable(&v0, sizeof(v0), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_buffer_liveness_update *ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_p = bpf_ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_p)
        return 1;
    //arg ptr[in, array[kbase_pixel_gpu_slc_liveness_mark]] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_p->live_ranges_address = v0.live_ranges_address;
    //arg array[kbase_pixel_gpu_slc_liveness_mark] array 0xf8fe80 varlen
    struct ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_live_ranges_address_buf *ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_live_ranges_address_p = bpf_ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_live_ranges_address_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_live_ranges_address_p)
        return 1;
    if (bpf_probe_read_sleepable(ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_live_ranges_address_p, sizeof(*ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_live_ranges_address_p), (void *)v0.live_ranges_address+0) < 0)
        return 1;
    //arg len len 0xf8fe80 8
    ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_p->live_ranges_count = v0.live_ranges_count;
    //arg ptr[in, array[gpu_addr]] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_p->buffer_va_address = v0.buffer_va_address;
    //arg array[gpu_addr] array 0xf8fe80 varlen
    struct ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_va_address_buf *ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_va_address_p = bpf_ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_va_address_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_va_address_p)
        return 1;
    if (bpf_probe_read_sleepable(ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_va_address_p, sizeof(*ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_va_address_p), (void *)v0.buffer_va_address+0) < 0)
        return 1;
    //arg ptr[in, array[int64]] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_p->buffer_sizes_address = v0.buffer_sizes_address;
    //arg array[int64] array 0xf8fe80 varlen
    struct ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_sizes_address_buf *ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_sizes_address_p = bpf_ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_sizes_address_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_sizes_address_p)
        return 1;
    if (bpf_probe_read_sleepable(ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_sizes_address_p, sizeof(*ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_buffer_sizes_address_p), (void *)v0.buffer_sizes_address+0) < 0)
        return 1;
    //arg len len 0xf8fe80 8
    ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE_arg_p->buffer_count = v0.buffer_count;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_context_priority_check] ptr 0xf8fe80 8
    //arg kbase_ioctl_context_priority_check kbase_ioctl_context_priority_check 0xf8fe80 1
    struct kbase_ioctl_context_priority_check v1;
    if (bpf_probe_read_sleepable(&v1, sizeof(v1), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_context_priority_check *ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK_arg_p = bpf_ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK_arg_p)
        return 1;
    //arg queue_group_priority queue_group_priority 0xf8fe80 1
    ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK_arg_p->priority = v1.priority;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_cs_cpu_queue_info] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_cpu_queue_info kbase_ioctl_cs_cpu_queue_info 0xf8fe80 16
    struct kbase_ioctl_cs_cpu_queue_info v2;
    if (bpf_probe_read_sleepable(&v2, sizeof(v2), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_cpu_queue_info *ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP_arg_p = bpf_ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP_arg_p)
        return 1;
    //arg ptr[in, buffer] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP_arg_p->buffer = v2.buffer;
    //arg len len 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP_arg_p->size = v2.size;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_EVENT_SIGNAL(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_EVENT_SIGNAL, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_EVENT_SIGNAL_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_cs_get_glb_iface] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_get_glb_iface kbase_ioctl_cs_get_glb_iface 0xf8fe80 24
    struct kbase_ioctl_cs_get_glb_iface v3;
    if (bpf_probe_read_sleepable(&v3, sizeof(v3), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_get_glb_iface *ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p = bpf_ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p)
        return 1;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p->max_group_num = v3.max_group_num;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p->max_total_stream_num = v3.max_total_stream_num;
    //arg ptr[out, int64] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p->groups_ptr = v3.groups_ptr;
    //arg int64 int64 0xf8fe80 8
    uint64_t v4;
    if (bpf_probe_read_sleepable(&v4, sizeof(v4), (void *)v3.groups_ptr+0) < 0)
        return 1;
    uint64_t *ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_groups_ptr_p = bpf_ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_groups_ptr_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_groups_ptr_p)
        return 1;
    *ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_groups_ptr_p = v4;
    //arg ptr[out, int64] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p->streams_ptr = v3.streams_ptr;
    //arg int64 int64 0xf8fe80 8
    uint64_t v5;
    if (bpf_probe_read_sleepable(&v5, sizeof(v5), (void *)v3.streams_ptr+0) < 0)
        return 1;
    uint64_t *ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_streams_ptr_p = bpf_ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_streams_ptr_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_streams_ptr_p)
        return 1;
    *ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_streams_ptr_p = v5;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p->glb_version = v3.glb_version;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p->features = v3.features;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p->group_num = v3.group_num;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p->prfcnt_size = v3.prfcnt_size;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p->total_stream_num = v3.total_stream_num;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE_arg_p->instr_featurs = v3.instr_featurs;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_QUEUE_BIND(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_QUEUE_BIND, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_BIND_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_cs_queue_bind] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_queue_bind kbase_ioctl_cs_queue_bind 0xf8fe80 16
    struct kbase_ioctl_cs_queue_bind v6;
    if (bpf_probe_read_sleepable(&v6, sizeof(v6), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_queue_bind *ioctl_KBASE_IOCTL_CS_QUEUE_BIND_arg_p = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_BIND_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_QUEUE_BIND_arg_p)
        return 1;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_BIND_arg_p->csi_index = v6.csi_index;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_QUEUE_BIND_arg_p->mmap_handle = v6.mmap_handle;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_cs_queue_group_create] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_queue_group_create kbase_ioctl_cs_queue_group_create 0xf8fe80 40
    struct kbase_ioctl_cs_queue_group_create v7;
    if (bpf_probe_read_sleepable(&v7, sizeof(v7), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_queue_group_create *ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p->tiler_mask = v7.tiler_mask;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p->fragment_mask = v7.fragment_mask;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p->compute_mask = v7.compute_mask;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p->cs_min = v7.cs_min;
    //arg queue_group_priority queue_group_priority 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p->priority = v7.priority;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p->tiler_max = v7.tiler_max;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p->fragment_max = v7.fragment_max;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p->compute_max = v7.compute_max;
    //arg csf_csi_flags csf_csi_flags 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p->csi_handlers = v7.csi_handlers;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p->reserved = v7.reserved;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_arg_p->group_uid = v7.group_uid;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_cs_queue_group_create_1_6] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_queue_group_create_1_6 kbase_ioctl_cs_queue_group_create_1_6 0xf8fe80 40
    struct kbase_ioctl_cs_queue_group_create_1_6 v8;
    if (bpf_probe_read_sleepable(&v8, sizeof(v8), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_queue_group_create_1_6 *ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p->tiler_mask = v8.tiler_mask;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p->fragment_mask = v8.fragment_mask;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p->compute_mask = v8.compute_mask;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p->cs_min = v8.cs_min;
    //arg queue_group_priority queue_group_priority 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p->priority = v8.priority;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p->tiler_max = v8.tiler_max;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p->fragment_max = v8.fragment_max;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p->compute_max = v8.compute_max;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p->reserved = v8.reserved;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6_arg_p->group_uid = v8.group_uid;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_cs_queue_group_terminate] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_queue_group_terminate kbase_ioctl_cs_queue_group_terminate 0xf8fe80 8
    struct kbase_ioctl_cs_queue_group_terminate v9;
    if (bpf_probe_read_sleepable(&v9, sizeof(v9), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_queue_group_terminate *ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE_arg_p = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE_arg_p)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_QUEUE_KICK(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_QUEUE_KICK, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_KICK_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_cs_queue_kick] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_queue_kick kbase_ioctl_cs_queue_kick 0xf8fe80 8
    struct kbase_ioctl_cs_queue_kick v10;
    if (bpf_probe_read_sleepable(&v10, sizeof(v10), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_queue_kick *ioctl_KBASE_IOCTL_CS_QUEUE_KICK_arg_p = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_KICK_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_QUEUE_KICK_arg_p)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, base_ioctl_cs_queue_register] ptr 0xf8fe80 8
    //arg base_ioctl_cs_queue_register base_ioctl_cs_queue_register 0xf8fe80 24
    struct base_ioctl_cs_queue_register v11;
    if (bpf_probe_read_sleepable(&v11, sizeof(v11), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct base_ioctl_cs_queue_register *ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_arg_p = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_arg_p)
        return 1;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_arg_p->buffer_size = v11.buffer_size;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_arg_p->priority = v11.priority;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_cs_queue_register_ex] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_queue_register_ex kbase_ioctl_cs_queue_register_ex 0xf8fe80 40
    struct kbase_ioctl_cs_queue_register_ex v12;
    if (bpf_probe_read_sleepable(&v12, sizeof(v12), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_queue_register_ex *ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_arg_p = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_arg_p)
        return 1;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_arg_p->buffer_size = v12.buffer_size;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_arg_p->priority = v12.priority;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_arg_p->ex_buffer_size = v12.ex_buffer_size;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_arg_p->ex_event_size = v12.ex_event_size;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX_arg_p->ex_event_state = v12.ex_event_state;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_cs_queue_terminate] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_queue_terminate kbase_ioctl_cs_queue_terminate 0xf8fe80 8
    struct kbase_ioctl_cs_queue_terminate v13;
    if (bpf_probe_read_sleepable(&v13, sizeof(v13), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_queue_terminate *ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE_arg_p = bpf_ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE_arg_p)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_cs_tiler_heap_init] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_tiler_heap_init kbase_ioctl_cs_tiler_heap_init 0xf8fe80 24
    struct kbase_ioctl_cs_tiler_heap_init v14;
    if (bpf_probe_read_sleepable(&v14, sizeof(v14), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_tiler_heap_init *ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg_p = bpf_ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg_p)
        return 1;
    //arg tiler_heap_chunk_sizes tiler_heap_chunk_sizes 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg_p->chunk_size = v14.chunk_size;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg_p->initial_chunks = v14.initial_chunks;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg_p->max_chunks = v14.max_chunks;
    //arg int16 int16 0xf8fe80 2
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg_p->target_in_flight = v14.target_in_flight;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg_p->group_id = v14.group_id;
    //arg const[0, const] const 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg_p->padding = v14.padding;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg_p->buf_desc_va = v14.buf_desc_va;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_arg_p->first_chunk_va = v14.first_chunk_va;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_cs_tiler_heap_init_1_13] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_tiler_heap_init_1_13 kbase_ioctl_cs_tiler_heap_init_1_13 0xf8fe80 16
    struct kbase_ioctl_cs_tiler_heap_init_1_13 v15;
    if (bpf_probe_read_sleepable(&v15, sizeof(v15), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_tiler_heap_init_1_13 *ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_arg_p = bpf_ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_arg_p)
        return 1;
    //arg tiler_heap_chunk_sizes tiler_heap_chunk_sizes 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_arg_p->chunk_size = v15.chunk_size;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_arg_p->initial_chunks = v15.initial_chunks;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_arg_p->max_chunks = v15.max_chunks;
    //arg int16 int16 0xf8fe80 2
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_arg_p->target_in_flight = v15.target_in_flight;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_arg_p->group_id = v15.group_id;
    //arg const[0, const] const 0xf8fe80 1
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_arg_p->padding = v15.padding;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13_arg_p->first_chunk_va = v15.first_chunk_va;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_CS_TILER_HEAP_TERM(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_CS_TILER_HEAP_TERM, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_CS_TILER_HEAP_TERM_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_cs_tiler_heap_term] ptr 0xf8fe80 8
    //arg kbase_ioctl_cs_tiler_heap_term kbase_ioctl_cs_tiler_heap_term 0xf8fe80 8
    struct kbase_ioctl_cs_tiler_heap_term v16;
    if (bpf_probe_read_sleepable(&v16, sizeof(v16), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_cs_tiler_heap_term *ioctl_KBASE_IOCTL_CS_TILER_HEAP_TERM_arg_p = bpf_ioctl_KBASE_IOCTL_CS_TILER_HEAP_TERM_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_CS_TILER_HEAP_TERM_arg_p)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_DISJOINT_QUERY(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_DISJOINT_QUERY, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_DISJOINT_QUERY_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[out, kbase_ioctl_disjoint_query] ptr 0xf8fe80 8
    //arg kbase_ioctl_disjoint_query kbase_ioctl_disjoint_query 0xf8fe80 4
    struct kbase_ioctl_disjoint_query v17;
    if (bpf_probe_read_sleepable(&v17, sizeof(v17), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_disjoint_query *ioctl_KBASE_IOCTL_DISJOINT_QUERY_arg_p = bpf_ioctl_KBASE_IOCTL_DISJOINT_QUERY_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_DISJOINT_QUERY_arg_p)
        return 1;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_DISJOINT_QUERY_arg_p->counter = v17.counter;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_FENCE_VALIDATE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_FENCE_VALIDATE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_FENCE_VALIDATE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_fence_validate] ptr 0xf8fe80 8
    //arg kbase_ioctl_fence_validate kbase_ioctl_fence_validate 0xf8fe80 4
    struct kbase_ioctl_fence_validate v18;
    if (bpf_probe_read_sleepable(&v18, sizeof(v18), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_fence_validate *ioctl_KBASE_IOCTL_FENCE_VALIDATE_arg_p = bpf_ioctl_KBASE_IOCTL_FENCE_VALIDATE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_FENCE_VALIDATE_arg_p)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_GET_CONTEXT_ID(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_GET_CONTEXT_ID, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_GET_CONTEXT_ID_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[out, kbase_ioctl_get_context_id] ptr 0xf8fe80 8
    //arg kbase_ioctl_get_context_id kbase_ioctl_get_context_id 0xf8fe80 4
    struct kbase_ioctl_get_context_id v19;
    if (bpf_probe_read_sleepable(&v19, sizeof(v19), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_get_context_id *ioctl_KBASE_IOCTL_GET_CONTEXT_ID_arg_p = bpf_ioctl_KBASE_IOCTL_GET_CONTEXT_ID_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_GET_CONTEXT_ID_arg_p)
        return 1;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_GET_CONTEXT_ID_arg_p->id = v19.id;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_get_cpu_gpu_timeinfo] ptr 0xf8fe80 8
    //arg kbase_ioctl_get_cpu_gpu_timeinfo kbase_ioctl_get_cpu_gpu_timeinfo 0xf8fe80 32
    struct kbase_ioctl_get_cpu_gpu_timeinfo v20;
    if (bpf_probe_read_sleepable(&v20, sizeof(v20), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_get_cpu_gpu_timeinfo *ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_arg_p = bpf_ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_arg_p)
        return 1;
    //arg base_timerequest_allowed_flags base_timerequest_allowed_flags 0xf8fe80 4
    ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_arg_p->request_flags = v20.request_flags;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_arg_p->sec = v20.sec;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_arg_p->nsec = v20.nsec;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_arg_p->padding = v20.padding;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_arg_p->timestamp = v20.timestamp;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO_arg_p->cycle_counter = v20.cycle_counter;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_GET_DDK_VERSION(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_GET_DDK_VERSION, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_GET_DDK_VERSION_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_get_ddk_version] ptr 0xf8fe80 8
    //arg kbase_ioctl_get_ddk_version kbase_ioctl_get_ddk_version 0xf8fe80 16
    struct kbase_ioctl_get_ddk_version v21;
    if (bpf_probe_read_sleepable(&v21, sizeof(v21), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_get_ddk_version *ioctl_KBASE_IOCTL_GET_DDK_VERSION_arg_p = bpf_ioctl_KBASE_IOCTL_GET_DDK_VERSION_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_GET_DDK_VERSION_arg_p)
        return 1;
    //arg ptr[out, buffer] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_GET_DDK_VERSION_arg_p->version_buffer = v21.version_buffer;
    //arg len len 0xf8fe80 4
    ioctl_KBASE_IOCTL_GET_DDK_VERSION_arg_p->size = v21.size;
    //arg const[0, const] const 0xf8fe80 4
    ioctl_KBASE_IOCTL_GET_DDK_VERSION_arg_p->padding = v21.padding;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_GET_GPUPROPS(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_GET_GPUPROPS, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_GET_GPUPROPS_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_get_gpuprops] ptr 0xf8fe80 8
    //arg kbase_ioctl_get_gpuprops kbase_ioctl_get_gpuprops 0xf8fe80 16
    struct kbase_ioctl_get_gpuprops v22;
    if (bpf_probe_read_sleepable(&v22, sizeof(v22), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_get_gpuprops *ioctl_KBASE_IOCTL_GET_GPUPROPS_arg_p = bpf_ioctl_KBASE_IOCTL_GET_GPUPROPS_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_GET_GPUPROPS_arg_p)
        return 1;
    //arg ptr[out, buffer] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_GET_GPUPROPS_arg_p->buffer = v22.buffer;
    //arg len len 0xf8fe80 4
    ioctl_KBASE_IOCTL_GET_GPUPROPS_arg_p->size = v22.size;
    //arg const[0, const] const 0xf8fe80 4
    ioctl_KBASE_IOCTL_GET_GPUPROPS_arg_p->flags = v22.flags;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_HWCNT_CLEAR(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_HWCNT_CLEAR, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_HWCNT_CLEAR_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_HWCNT_DUMP(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_HWCNT_DUMP, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_HWCNT_DUMP_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_HWCNT_ENABLE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_HWCNT_ENABLE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_HWCNT_ENABLE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_hwcnt_enable] ptr 0xf8fe80 8
    //arg kbase_ioctl_hwcnt_enable kbase_ioctl_hwcnt_enable 0xf8fe80 24
    struct kbase_ioctl_hwcnt_enable v23;
    if (bpf_probe_read_sleepable(&v23, sizeof(v23), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_hwcnt_enable *ioctl_KBASE_IOCTL_HWCNT_ENABLE_arg_p = bpf_ioctl_KBASE_IOCTL_HWCNT_ENABLE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_HWCNT_ENABLE_arg_p)
        return 1;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_HWCNT_ENABLE_arg_p->jm_bm = v23.jm_bm;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_HWCNT_ENABLE_arg_p->shader_bm = v23.shader_bm;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_HWCNT_ENABLE_arg_p->tiler_bm = v23.tiler_bm;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_HWCNT_ENABLE_arg_p->mmu_l2_bm = v23.mmu_l2_bm;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_HWCNT_READER_SETUP(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_HWCNT_READER_SETUP, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_hwcnt_reader_setup] ptr 0xf8fe80 8
    //arg kbase_ioctl_hwcnt_reader_setup kbase_ioctl_hwcnt_reader_setup 0xf8fe80 20
    struct kbase_ioctl_hwcnt_reader_setup v24;
    if (bpf_probe_read_sleepable(&v24, sizeof(v24), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_hwcnt_reader_setup *ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_arg_p = bpf_ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_arg_p)
        return 1;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_arg_p->buffer_count = v24.buffer_count;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_arg_p->jm_bm = v24.jm_bm;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_arg_p->shader_bm = v24.shader_bm;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_arg_p->tiler_bm = v24.tiler_bm;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_HWCNT_READER_SETUP_arg_p->mmu_l2_bm = v24.mmu_l2_bm;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_HWCNT_SET(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_HWCNT_SET, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_HWCNT_SET_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_hwcnt_values] ptr 0xf8fe80 8
    //arg kbase_ioctl_hwcnt_values kbase_ioctl_hwcnt_values 0xf8fe80 16
    struct kbase_ioctl_hwcnt_values v25;
    if (bpf_probe_read_sleepable(&v25, sizeof(v25), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_hwcnt_values *ioctl_KBASE_IOCTL_HWCNT_SET_arg_p = bpf_ioctl_KBASE_IOCTL_HWCNT_SET_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_HWCNT_SET_arg_p)
        return 1;
    //arg ptr[out, buffer] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_HWCNT_SET_arg_p->data = v25.data;
    //arg len len 0xf8fe80 4
    ioctl_KBASE_IOCTL_HWCNT_SET_arg_p->size = v25.size;
    //arg const[0, const] const 0xf8fe80 4
    ioctl_KBASE_IOCTL_HWCNT_SET_arg_p->padding = v25.padding;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_JOB_SUBMIT(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_JOB_SUBMIT, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_JOB_SUBMIT_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_job_submit] ptr 0xf8fe80 8
    //arg kbase_ioctl_job_submit kbase_ioctl_job_submit 0xf8fe80 16
    struct kbase_ioctl_job_submit v26;
    if (bpf_probe_read_sleepable(&v26, sizeof(v26), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_job_submit *ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_p = bpf_ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_p)
        return 1;
    //arg ptr[out, array[base_jd_atom_v2]] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_p->addr = v26.addr;
    //arg array[base_jd_atom_v2] array 0xf8fe80 varlen
    struct ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_addr_buf *ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_addr_p = bpf_ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_addr_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_addr_p)
        return 1;
    if (bpf_probe_read_sleepable(ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_addr_p, sizeof(*ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_addr_p), (void *)v26.addr+0) < 0)
        return 1;
    //arg len len 0xf8fe80 4
    ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_p->nr_atoms = v26.nr_atoms;
    //arg const[56, const] const 0xf8fe80 4
    ioctl_KBASE_IOCTL_JOB_SUBMIT_arg_p->stride = v26.stride;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_KCPU_QUEUE_CREATE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_KCPU_QUEUE_CREATE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_KCPU_QUEUE_CREATE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[out, kbase_ioctl_kcpu_queue_new] ptr 0xf8fe80 8
    //arg kbase_ioctl_kcpu_queue_new kbase_ioctl_kcpu_queue_new 0xf8fe80 8
    struct kbase_ioctl_kcpu_queue_new v27;
    if (bpf_probe_read_sleepable(&v27, sizeof(v27), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_kcpu_queue_new *ioctl_KBASE_IOCTL_KCPU_QUEUE_CREATE_arg_p = bpf_ioctl_KBASE_IOCTL_KCPU_QUEUE_CREATE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_KCPU_QUEUE_CREATE_arg_p)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_KCPU_QUEUE_DELETE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_KCPU_QUEUE_DELETE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_KCPU_QUEUE_DELETE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_kcpu_queue_delete] ptr 0xf8fe80 8
    //arg kbase_ioctl_kcpu_queue_delete kbase_ioctl_kcpu_queue_delete 0xf8fe80 8
    struct kbase_ioctl_kcpu_queue_delete v28;
    if (bpf_probe_read_sleepable(&v28, sizeof(v28), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_kcpu_queue_delete *ioctl_KBASE_IOCTL_KCPU_QUEUE_DELETE_arg_p = bpf_ioctl_KBASE_IOCTL_KCPU_QUEUE_DELETE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_KCPU_QUEUE_DELETE_arg_p)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_kcpu_queue_enqueue] ptr 0xf8fe80 8
    //arg kbase_ioctl_kcpu_queue_enqueue kbase_ioctl_kcpu_queue_enqueue 0xf8fe80 16
    struct kbase_ioctl_kcpu_queue_enqueue v29;
    if (bpf_probe_read_sleepable(&v29, sizeof(v29), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_kcpu_queue_enqueue *ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE_arg_p = bpf_ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE_arg_p)
        return 1;
    //arg len len 0xf8fe80 4
    ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE_arg_p->nr_commands = v29.nr_commands;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_kinstr_prfcnt_enum_info] ptr 0xf8fe80 8
    //arg kbase_ioctl_kinstr_prfcnt_enum_info kbase_ioctl_kinstr_prfcnt_enum_info 0xf8fe80 16
    struct kbase_ioctl_kinstr_prfcnt_enum_info v30;
    if (bpf_probe_read_sleepable(&v30, sizeof(v30), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_kinstr_prfcnt_enum_info *ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_p = bpf_ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_p)
        return 1;
    //arg len len 0xf8fe80 4
    ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_p->info_item_size = v30.info_item_size;
    //arg bytesize bytesize 0xf8fe80 4
    ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_p->info_item_count = v30.info_item_count;
    //arg ptr[out, array[prfcnt_enum_item]] ptr 0xf8fe80 8
    ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_p->info_list_ptr = v30.info_list_ptr;
    //arg array[prfcnt_enum_item] array 0xf8fe80 varlen
    struct ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_info_list_ptr_buf *ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_info_list_ptr_p = bpf_ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_info_list_ptr_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_info_list_ptr_p)
        return 1;
    if (bpf_probe_read_sleepable(ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_info_list_ptr_p, sizeof(*ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO_arg_info_list_ptr_p), (void *)v30.info_list_ptr+0) < 0)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_kinstr_prfcnt_setup] ptr 0xf8fe80 8
    //arg kbase_ioctl_kinstr_prfcnt_setup kbase_ioctl_kinstr_prfcnt_setup 0xf8fe80 16
    struct kbase_ioctl_kinstr_prfcnt_setup v31;
    if (bpf_probe_read_sleepable(&v31, sizeof(v31), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_kinstr_prfcnt_setup *ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_p = bpf_ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_p)
        return 1;
    //arg len len 0xf8fe80 4
    ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_p->request_item_count = v31.request_item_count;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_p->request_item_size = v31.request_item_size;
    //arg ptr[in, array[prfcnt_request_item]] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_p->requests_ptr = v31.requests_ptr;
    //arg array[prfcnt_request_item] array 0xf8fe80 varlen
    struct ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_requests_ptr_buf *ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_requests_ptr_p = bpf_ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_requests_ptr_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_requests_ptr_p)
        return 1;
    if (bpf_probe_read_sleepable(ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_requests_ptr_p, sizeof(*ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_requests_ptr_p), (void *)v31.requests_ptr+0) < 0)
        return 1;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_p->prfcnt_metadata_item_size = v31.prfcnt_metadata_item_size;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP_arg_p->prfcnt_mmap_size_bytes = v31.prfcnt_mmap_size_bytes;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_ALIAS(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_ALIAS, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_ALIAS_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_mem_alias] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_alias kbase_ioctl_mem_alias 0xf8fe80 32
    struct kbase_ioctl_mem_alias v32;
    if (bpf_probe_read_sleepable(&v32, sizeof(v32), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_alias *ioctl_KBASE_IOCTL_MEM_ALIAS_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_ALIAS_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_ALIAS_arg_p)
        return 1;
    //arg base_mem_alloc_flags base_mem_alloc_flags 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALIAS_arg_p->flags = v32.flags;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALIAS_arg_p->stride = v32.stride;
    //arg len len 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALIAS_arg_p->nents = v32.nents;
    //arg ptr[in, array[base_mem_aliasing_info]] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALIAS_arg_p->aliasing_info = v32.aliasing_info;
    //arg array[base_mem_aliasing_info] array 0xf8fe80 varlen
    struct ioctl_KBASE_IOCTL_MEM_ALIAS_arg_aliasing_info_buf *ioctl_KBASE_IOCTL_MEM_ALIAS_arg_aliasing_info_p = bpf_ioctl_KBASE_IOCTL_MEM_ALIAS_arg_aliasing_info_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_ALIAS_arg_aliasing_info_p)
        return 1;
    if (bpf_probe_read_sleepable(ioctl_KBASE_IOCTL_MEM_ALIAS_arg_aliasing_info_p, sizeof(*ioctl_KBASE_IOCTL_MEM_ALIAS_arg_aliasing_info_p), (void *)v32.aliasing_info+0) < 0)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALIAS_arg_p->out_flags = v32.out_flags;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALIAS_arg_p->va_pages = v32.va_pages;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_ALLOC(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_ALLOC, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_ALLOC_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_mem_alloc] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_alloc kbase_ioctl_mem_alloc 0xf8fe80 32
    struct kbase_ioctl_mem_alloc v33;
    if (bpf_probe_read_sleepable(&v33, sizeof(v33), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_alloc *ioctl_KBASE_IOCTL_MEM_ALLOC_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_ALLOC_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_ALLOC_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALLOC_arg_p->va_pages = v33.va_pages;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALLOC_arg_p->commit_pages = v33.commit_pages;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALLOC_arg_p->extent = v33.extent;
    //arg base_mem_alloc_flags base_mem_alloc_flags 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALLOC_arg_p->flags = v33.flags;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALLOC_arg_p->out_flags = v33.out_flags;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_ALLOC_EX(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_ALLOC_EX, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_ALLOC_EX_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_mem_alloc_ex] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_alloc_ex kbase_ioctl_mem_alloc_ex 0xf8fe80 64
    struct kbase_ioctl_mem_alloc_ex v34;
    if (bpf_probe_read_sleepable(&v34, sizeof(v34), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_alloc_ex *ioctl_KBASE_IOCTL_MEM_ALLOC_EX_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_ALLOC_EX_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_ALLOC_EX_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALLOC_EX_arg_p->va_pages = v34.va_pages;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALLOC_EX_arg_p->commit_pages = v34.commit_pages;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALLOC_EX_arg_p->extension = v34.extension;
    //arg base_mem_alloc_flags base_mem_alloc_flags 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALLOC_EX_arg_p->flags = v34.flags;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALLOC_EX_arg_p->fixed_address = v34.fixed_address;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_ALLOC_EX_arg_p->out_flags = v34.out_flags;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_COMMIT(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_COMMIT, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_COMMIT_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_mem_commit] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_commit kbase_ioctl_mem_commit 0xf8fe80 16
    struct kbase_ioctl_mem_commit v35;
    if (bpf_probe_read_sleepable(&v35, sizeof(v35), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_commit *ioctl_KBASE_IOCTL_MEM_COMMIT_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_COMMIT_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_COMMIT_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_COMMIT_arg_p->pages = v35.pages;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_EXEC_INIT(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_EXEC_INIT, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_EXEC_INIT_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_mem_exec_init] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_exec_init kbase_ioctl_mem_exec_init 0xf8fe80 8
    struct kbase_ioctl_mem_exec_init v36;
    if (bpf_probe_read_sleepable(&v36, sizeof(v36), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_exec_init *ioctl_KBASE_IOCTL_MEM_EXEC_INIT_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_EXEC_INIT_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_EXEC_INIT_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_EXEC_INIT_arg_p->va_pages = v36.va_pages;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_mem_find_cpu_offset] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_find_cpu_offset kbase_ioctl_mem_find_cpu_offset 0xf8fe80 24
    struct kbase_ioctl_mem_find_cpu_offset v37;
    if (bpf_probe_read_sleepable(&v37, sizeof(v37), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_find_cpu_offset *ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET_arg_p->size = v37.size;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET_arg_p->offset = v37.offset;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_mem_find_gpu_start_and_offset] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_find_gpu_start_and_offset kbase_ioctl_mem_find_gpu_start_and_offset 0xf8fe80 16
    struct kbase_ioctl_mem_find_gpu_start_and_offset v38;
    if (bpf_probe_read_sleepable(&v38, sizeof(v38), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_find_gpu_start_and_offset *ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET_arg_p->size = v38.size;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET_arg_p->offset = v38.offset;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_mem_flags_change] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_flags_change kbase_ioctl_mem_flags_change 0xf8fe80 24
    struct kbase_ioctl_mem_flags_change v39;
    if (bpf_probe_read_sleepable(&v39, sizeof(v39), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_flags_change *ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE_arg_p)
        return 1;
    //arg base_mem_alloc_flags base_mem_alloc_flags 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE_arg_p->flags = v39.flags;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE_arg_p->mask = v39.mask;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_FREE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_FREE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_FREE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_mem_free] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_free kbase_ioctl_mem_free 0xf8fe80 8
    struct kbase_ioctl_mem_free v40;
    if (bpf_probe_read_sleepable(&v40, sizeof(v40), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_free *ioctl_KBASE_IOCTL_MEM_FREE_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_FREE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_FREE_arg_p)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_IMPORT(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_IMPORT, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_IMPORT_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_mem_import] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_import kbase_ioctl_mem_import 0xf8fe80 24
    struct kbase_ioctl_mem_import v41;
    if (bpf_probe_read_sleepable(&v41, sizeof(v41), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_import *ioctl_KBASE_IOCTL_MEM_IMPORT_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_IMPORT_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_IMPORT_arg_p)
        return 1;
    //arg base_mem_alloc_flags base_mem_alloc_flags 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_IMPORT_arg_p->flags = v41.flags;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_IMPORT_arg_p->phandle = v41.phandle;
    //arg base_mem_import_type base_mem_import_type 0xf8fe80 4
    ioctl_KBASE_IOCTL_MEM_IMPORT_arg_p->type = v41.type;
    //arg const[0, const] const 0xf8fe80 4
    ioctl_KBASE_IOCTL_MEM_IMPORT_arg_p->padding = v41.padding;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_IMPORT_arg_p->out_flags = v41.out_flags;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_IMPORT_arg_p->va_pages = v41.va_pages;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_JIT_INIT(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_JIT_INIT, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_JIT_INIT_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_mem_jit_init] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_jit_init kbase_ioctl_mem_jit_init 0xf8fe80 24
    struct kbase_ioctl_mem_jit_init v42;
    if (bpf_probe_read_sleepable(&v42, sizeof(v42), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_jit_init *ioctl_KBASE_IOCTL_MEM_JIT_INIT_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_JIT_INIT_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_JIT_INIT_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_JIT_INIT_arg_p->va_pages = v42.va_pages;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_MEM_JIT_INIT_arg_p->max_allocations = v42.max_allocations;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_MEM_JIT_INIT_arg_p->trim_level = v42.trim_level;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_MEM_JIT_INIT_arg_p->group_id = v42.group_id;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_JIT_INIT_arg_p->phys_pages = v42.phys_pages;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_JIT_INIT_10_2(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_JIT_INIT_10_2, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_JIT_INIT_10_2_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_mem_jit_init_10_2] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_jit_init_10_2 kbase_ioctl_mem_jit_init_10_2 0xf8fe80 8
    struct kbase_ioctl_mem_jit_init_10_2 v43;
    if (bpf_probe_read_sleepable(&v43, sizeof(v43), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_jit_init_10_2 *ioctl_KBASE_IOCTL_MEM_JIT_INIT_10_2_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_JIT_INIT_10_2_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_JIT_INIT_10_2_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_JIT_INIT_10_2_arg_p->va_pages = v43.va_pages;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_mem_jit_init_11_5] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_jit_init_11_5 kbase_ioctl_mem_jit_init_11_5 0xf8fe80 16
    struct kbase_ioctl_mem_jit_init_11_5 v44;
    if (bpf_probe_read_sleepable(&v44, sizeof(v44), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_jit_init_11_5 *ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5_arg_p->va_pages = v44.va_pages;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5_arg_p->max_allocations = v44.max_allocations;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5_arg_p->trim_level = v44.trim_level;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5_arg_p->group_id = v44.group_id;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_PROFILE_ADD(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_PROFILE_ADD, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_PROFILE_ADD_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_mem_profile_add] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_profile_add kbase_ioctl_mem_profile_add 0xf8fe80 16
    struct kbase_ioctl_mem_profile_add v45;
    if (bpf_probe_read_sleepable(&v45, sizeof(v45), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_profile_add *ioctl_KBASE_IOCTL_MEM_PROFILE_ADD_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_PROFILE_ADD_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_PROFILE_ADD_arg_p)
        return 1;
    //arg ptr[in, buffer] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_PROFILE_ADD_arg_p->buffer = v45.buffer;
    //arg len len 0xf8fe80 4
    ioctl_KBASE_IOCTL_MEM_PROFILE_ADD_arg_p->len = v45.len;
    //arg const[0, const] const 0xf8fe80 4
    ioctl_KBASE_IOCTL_MEM_PROFILE_ADD_arg_p->padding = v45.padding;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_QUERY(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_QUERY, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_QUERY_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_mem_query] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_query kbase_ioctl_mem_query 0xf8fe80 16
    struct kbase_ioctl_mem_query v46;
    if (bpf_probe_read_sleepable(&v46, sizeof(v46), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_query *ioctl_KBASE_IOCTL_MEM_QUERY_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_QUERY_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_QUERY_arg_p)
        return 1;
    //arg kbase_ioctl_mem_query_flags kbase_ioctl_mem_query_flags 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_QUERY_arg_p->query = v46.query;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_QUERY_arg_p->value = v46.value;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_MEM_SYNC(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_MEM_SYNC, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_MEM_SYNC_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_mem_sync] ptr 0xf8fe80 8
    //arg kbase_ioctl_mem_sync kbase_ioctl_mem_sync 0xf8fe80 32
    struct kbase_ioctl_mem_sync v47;
    if (bpf_probe_read_sleepable(&v47, sizeof(v47), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_mem_sync *ioctl_KBASE_IOCTL_MEM_SYNC_arg_p = bpf_ioctl_KBASE_IOCTL_MEM_SYNC_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_MEM_SYNC_arg_p)
        return 1;
    //arg int64 int64 0xf8fe80 8
    ioctl_KBASE_IOCTL_MEM_SYNC_arg_p->size = v47.size;
    //arg base_syncset_op_flags base_syncset_op_flags 0xf8fe80 1
    ioctl_KBASE_IOCTL_MEM_SYNC_arg_p->type = v47.type;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_POST_TERM(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_POST_TERM, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_POST_TERM_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_READ_USER_PAGE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_READ_USER_PAGE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_READ_USER_PAGE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_read_user_page] ptr 0xf8fe80 8
    //arg kbase_ioctl_read_user_page kbase_ioctl_read_user_page 0xf8fe80 8
    struct kbase_ioctl_read_user_page v48;
    if (bpf_probe_read_sleepable(&v48, sizeof(v48), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_read_user_page *ioctl_KBASE_IOCTL_READ_USER_PAGE_arg_p = bpf_ioctl_KBASE_IOCTL_READ_USER_PAGE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_READ_USER_PAGE_arg_p)
        return 1;
    //arg const[0, user_offsets] user_offsets 0xf8fe80 4
    ioctl_KBASE_IOCTL_READ_USER_PAGE_arg_p->offset = v48.offset;
    //arg const[0, const] const 0xf8fe80 4
    ioctl_KBASE_IOCTL_READ_USER_PAGE_arg_p->padding = v48.padding;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_READ_USER_PAGE_arg_p->val_lo = v48.val_lo;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_READ_USER_PAGE_arg_p->val_hi = v48.val_hi;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_SET_FLAGS(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_SET_FLAGS, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_SET_FLAGS_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_set_flags] ptr 0xf8fe80 8
    //arg kbase_ioctl_set_flags kbase_ioctl_set_flags 0xf8fe80 4
    struct kbase_ioctl_set_flags v49;
    if (bpf_probe_read_sleepable(&v49, sizeof(v49), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_set_flags *ioctl_KBASE_IOCTL_SET_FLAGS_arg_p = bpf_ioctl_KBASE_IOCTL_SET_FLAGS_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_SET_FLAGS_arg_p)
        return 1;
    //arg basep_context_create_kernel_flags basep_context_create_kernel_flags 0xf8fe80 4
    ioctl_KBASE_IOCTL_SET_FLAGS_arg_p->create_flags = v49.create_flags;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_SET_LIMITED_CORE_COUNT(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_SET_LIMITED_CORE_COUNT, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_SET_LIMITED_CORE_COUNT_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_set_limited_core_count] ptr 0xf8fe80 8
    //arg kbase_ioctl_set_limited_core_count kbase_ioctl_set_limited_core_count 0xf8fe80 1
    struct kbase_ioctl_set_limited_core_count v50;
    if (bpf_probe_read_sleepable(&v50, sizeof(v50), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_set_limited_core_count *ioctl_KBASE_IOCTL_SET_LIMITED_CORE_COUNT_arg_p = bpf_ioctl_KBASE_IOCTL_SET_LIMITED_CORE_COUNT_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_SET_LIMITED_CORE_COUNT_arg_p)
        return 1;
    //arg int8 int8 0xf8fe80 1
    ioctl_KBASE_IOCTL_SET_LIMITED_CORE_COUNT_arg_p->max_core_count = v50.max_core_count;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_soft_event_update] ptr 0xf8fe80 8
    //arg kbase_ioctl_soft_event_update kbase_ioctl_soft_event_update 0xf8fe80 16
    struct kbase_ioctl_soft_event_update v51;
    if (bpf_probe_read_sleepable(&v51, sizeof(v51), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_soft_event_update *ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE_arg_p = bpf_ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE_arg_p)
        return 1;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE_arg_p->new_status = v51.new_status;
    //arg const[0, const] const 0xf8fe80 4
    ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE_arg_p->flags = v51.flags;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_sticky_resource_map] ptr 0xf8fe80 8
    //arg kbase_ioctl_sticky_resource_map kbase_ioctl_sticky_resource_map 0xf8fe80 16
    struct kbase_ioctl_sticky_resource_map v52;
    if (bpf_probe_read_sleepable(&v52, sizeof(v52), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_sticky_resource_map *ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_p = bpf_ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_p)
        return 1;
    //arg len len 0xf8fe80 8
    ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_p->count = v52.count;
    //arg ptr[in, array[int64]] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_p->address = v52.address;
    //arg array[int64] array 0xf8fe80 varlen
    struct ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_address_buf *ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_address_p = bpf_ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_address_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_address_p)
        return 1;
    if (bpf_probe_read_sleepable(ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_address_p, sizeof(*ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP_arg_address_p), (void *)v52.address+0) < 0)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_sticky_resource_unmap] ptr 0xf8fe80 8
    //arg kbase_ioctl_sticky_resource_unmap kbase_ioctl_sticky_resource_unmap 0xf8fe80 16
    struct kbase_ioctl_sticky_resource_unmap v53;
    if (bpf_probe_read_sleepable(&v53, sizeof(v53), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_sticky_resource_unmap *ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_p = bpf_ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_p)
        return 1;
    //arg len len 0xf8fe80 8
    ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_p->count = v53.count;
    //arg ptr[in, array[int64]] ptr64 0xf8fe80 8
    ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_p->address = v53.address;
    //arg array[int64] array 0xf8fe80 varlen
    struct ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_address_buf *ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_address_p = bpf_ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_address_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_address_p)
        return 1;
    if (bpf_probe_read_sleepable(ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_address_p, sizeof(*ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP_arg_address_p), (void *)v53.address+0) < 0)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_STREAM_CREATE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_STREAM_CREATE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_STREAM_CREATE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_stream_create] ptr 0xf8fe80 8
    //arg kbase_ioctl_stream_create kbase_ioctl_stream_create 0xf8fe80 32
    struct kbase_ioctl_stream_create v54;
    if (bpf_probe_read_sleepable(&v54, sizeof(v54), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_stream_create *ioctl_KBASE_IOCTL_STREAM_CREATE_arg_p = bpf_ioctl_KBASE_IOCTL_STREAM_CREATE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_STREAM_CREATE_arg_p)
        return 1;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_TLSTREAM_ACQUIRE(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_TLSTREAM_ACQUIRE, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_TLSTREAM_ACQUIRE_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[in, kbase_ioctl_tlstream_acquire] ptr 0xf8fe80 8
    //arg kbase_ioctl_tlstream_acquire kbase_ioctl_tlstream_acquire 0xf8fe80 4
    struct kbase_ioctl_tlstream_acquire v55;
    if (bpf_probe_read_sleepable(&v55, sizeof(v55), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_tlstream_acquire *ioctl_KBASE_IOCTL_TLSTREAM_ACQUIRE_arg_p = bpf_ioctl_KBASE_IOCTL_TLSTREAM_ACQUIRE_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_TLSTREAM_ACQUIRE_arg_p)
        return 1;
    //arg int32 int32 0xf8fe80 4
    ioctl_KBASE_IOCTL_TLSTREAM_ACQUIRE_arg_p->flags = v55.flags;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_TLSTREAM_FLUSH(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_TLSTREAM_FLUSH, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_TLSTREAM_FLUSH_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_VERSION_CHECK(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_VERSION_CHECK, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_VERSION_CHECK_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_version_check] ptr 0xf8fe80 8
    //arg kbase_ioctl_version_check kbase_ioctl_version_check 0xf8fe80 4
    struct kbase_ioctl_version_check v56;
    if (bpf_probe_read_sleepable(&v56, sizeof(v56), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_version_check *ioctl_KBASE_IOCTL_VERSION_CHECK_arg_p = bpf_ioctl_KBASE_IOCTL_VERSION_CHECK_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_VERSION_CHECK_arg_p)
        return 1;
    //arg int16 int16 0xf8fe80 2
    ioctl_KBASE_IOCTL_VERSION_CHECK_arg_p->major = v56.major;
    //arg int16 int16 0xf8fe80 2
    ioctl_KBASE_IOCTL_VERSION_CHECK_arg_p->minor = v56.minor;
    return ret;
}

int __always_inline trace_ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED, 12);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED_ent_lookup_elem(&idx);
    if (ent) {
    	ent->ts = bpf_ktime_get_ns();
    	ent->id = pid_tgid;
    	ent->args[0] = ctx->regs[0];
    	ent->args[1] = ctx->regs[1];
    	ent->args[2] = ctx->regs[2];
    	ent->args[3] = ctx->regs[3];
    	ent->args[4] = ctx->regs[4];
    	ent->args[5] = ctx->regs[5];
    }
    //arg ptr[inout, kbase_ioctl_version_check] ptr 0xf8fe80 8
    //arg kbase_ioctl_version_check kbase_ioctl_version_check 0xf8fe80 4
    struct kbase_ioctl_version_check v57;
    if (bpf_probe_read_sleepable(&v57, sizeof(v57), (void *)ctx->regs[2]+0) < 0)
        return 1;
    struct kbase_ioctl_version_check *ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED_arg_p = bpf_ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED_arg_lookup_elem(&idx);
    if (!ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED_arg_p)
        return 1;
    //arg int16 int16 0xf8fe80 2
    ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED_arg_p->major = v57.major;
    //arg int16 int16 0xf8fe80 2
    ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED_arg_p->minor = v57.minor;
    return ret;
}

int __always_inline trace_syscall_return(sys_exit_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, syscall_return, 18);
    sys_exit_ent_t *ent = bpf_syscall_return_ent_lookup_elem(&idx);
    if (idx != -1 && ent) {
        ent->ts = bpf_ktime_get_ns();
        ent->id = pid_tgid;
        ent->nr = ctx->id;
        ent->ret = ctx->ret;
    }

    return ret;
}

int __always_inline trace_other_syscalls(sys_enter_args *ctx, uint64_t pid_tgid, uint64_t flag) {
    int ret = 0;
    int idx;
    get_and_inc_ctr(idx, other_syscalls, 18);
    if (idx == -1)
        return 1;

    sys_enter_ent_t *ent = bpf_other_syscalls_ent_lookup_elem(&idx);
    if (ent) {
        ent->ts = bpf_ktime_get_ns();
        ent->id = pid_tgid | flag;
        ent->args[0] = ctx->regs[0];
        ent->args[1] = ctx->regs[1];
        ent->args[2] = ctx->regs[2];
        ent->args[3] = ctx->regs[3];
        ent->args[4] = ctx->regs[4];
        ent->args[5] = ctx->regs[5];
    }

    int *nr = bpf_other_syscalls_nr_lookup_elem(&idx);
    if (!nr)
        return 1;
    *nr = ctx->id;

    return ret;
}

int __always_inline trace_ioctl(sys_enter_args *ctx, uint64_t pid_tgid) {
    int ret = 0;
    uint64_t ioctl_cmd = ctx->regs[1];
    switch (ioctl_cmd) {
    case 0x40288043:
        ret = trace_ioctl_KBASE_IOCTL_BUFFER_LIVENESS_UPDATE(ctx, pid_tgid);
        break;
    case 0xc0018036:
        ret = trace_ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK(ctx, pid_tgid);
        break;
    case 0x40108035:
        ret = trace_ioctl_KBASE_IOCTL_CS_CPU_QUEUE_DUMP(ctx, pid_tgid);
        break;
    case 0x802c:
        ret = trace_ioctl_KBASE_IOCTL_CS_EVENT_SIGNAL(ctx, pid_tgid);
        break;
    case 0xc0188033:
        ret = trace_ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE(ctx, pid_tgid);
        break;
    case 0xc0108027:
        ret = trace_ioctl_KBASE_IOCTL_CS_QUEUE_BIND(ctx, pid_tgid);
        break;
    case 0xc028803a:
        ret = trace_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE(ctx, pid_tgid);
        break;
    case 0xc020802a:
        ret = trace_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6(ctx, pid_tgid);
        break;
    case 0x4008802b:
        ret = trace_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE(ctx, pid_tgid);
        break;
    case 0x40088025:
        ret = trace_ioctl_KBASE_IOCTL_CS_QUEUE_KICK(ctx, pid_tgid);
        break;
    case 0x40108024:
        ret = trace_ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER(ctx, pid_tgid);
        break;
    case 0x40288028:
        ret = trace_ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER_EX(ctx, pid_tgid);
        break;
    case 0x40088029:
        ret = trace_ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE(ctx, pid_tgid);
        break;
    case 0xc0188030:
        ret = trace_ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT(ctx, pid_tgid);
        break;
    case 0xc0108030:
        ret = trace_ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT_1_13(ctx, pid_tgid);
        break;
    case 0x40088031:
        ret = trace_ioctl_KBASE_IOCTL_CS_TILER_HEAP_TERM(ctx, pid_tgid);
        break;
    case 0x8004800c:
        ret = trace_ioctl_KBASE_IOCTL_DISJOINT_QUERY(ctx, pid_tgid);
        break;
    case 0x40048019:
        ret = trace_ioctl_KBASE_IOCTL_FENCE_VALIDATE(ctx, pid_tgid);
        break;
    case 0x80048011:
        ret = trace_ioctl_KBASE_IOCTL_GET_CONTEXT_ID(ctx, pid_tgid);
        break;
    case 0xc0208032:
        ret = trace_ioctl_KBASE_IOCTL_GET_CPU_GPU_TIMEINFO(ctx, pid_tgid);
        break;
    case 0x4010800d:
        ret = trace_ioctl_KBASE_IOCTL_GET_DDK_VERSION(ctx, pid_tgid);
        break;
    case 0x40108003:
        ret = trace_ioctl_KBASE_IOCTL_GET_GPUPROPS(ctx, pid_tgid);
        break;
    case 0x800b:
        ret = trace_ioctl_KBASE_IOCTL_HWCNT_CLEAR(ctx, pid_tgid);
        break;
    case 0x800a:
        ret = trace_ioctl_KBASE_IOCTL_HWCNT_DUMP(ctx, pid_tgid);
        break;
    case 0x40188009:
        ret = trace_ioctl_KBASE_IOCTL_HWCNT_ENABLE(ctx, pid_tgid);
        break;
    case 0x40148008:
        ret = trace_ioctl_KBASE_IOCTL_HWCNT_READER_SETUP(ctx, pid_tgid);
        break;
    case 0x40108020:
        ret = trace_ioctl_KBASE_IOCTL_HWCNT_SET(ctx, pid_tgid);
        break;
    case 0x40108002:
        ret = trace_ioctl_KBASE_IOCTL_JOB_SUBMIT(ctx, pid_tgid);
        break;
    case 0x8008802d:
        ret = trace_ioctl_KBASE_IOCTL_KCPU_QUEUE_CREATE(ctx, pid_tgid);
        break;
    case 0x4008802e:
        ret = trace_ioctl_KBASE_IOCTL_KCPU_QUEUE_DELETE(ctx, pid_tgid);
        break;
    case 0x4010802f:
        ret = trace_ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE(ctx, pid_tgid);
        break;
    case 0xc0108038:
        ret = trace_ioctl_KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO(ctx, pid_tgid);
        break;
    case 0xc0108039:
        ret = trace_ioctl_KBASE_IOCTL_KINSTR_PRFCNT_SETUP(ctx, pid_tgid);
        break;
    case 0xc0208015:
        ret = trace_ioctl_KBASE_IOCTL_MEM_ALIAS(ctx, pid_tgid);
        break;
    case 0xc0208005:
        ret = trace_ioctl_KBASE_IOCTL_MEM_ALLOC(ctx, pid_tgid);
        break;
    case 0xc040803b:
        ret = trace_ioctl_KBASE_IOCTL_MEM_ALLOC_EX(ctx, pid_tgid);
        break;
    case 0x40108014:
        ret = trace_ioctl_KBASE_IOCTL_MEM_COMMIT(ctx, pid_tgid);
        break;
    case 0x40088026:
        ret = trace_ioctl_KBASE_IOCTL_MEM_EXEC_INIT(ctx, pid_tgid);
        break;
    case 0xc0188010:
        ret = trace_ioctl_KBASE_IOCTL_MEM_FIND_CPU_OFFSET(ctx, pid_tgid);
        break;
    case 0xc010801f:
        ret = trace_ioctl_KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET(ctx, pid_tgid);
        break;
    case 0x40188017:
        ret = trace_ioctl_KBASE_IOCTL_MEM_FLAGS_CHANGE(ctx, pid_tgid);
        break;
    case 0x40088007:
        ret = trace_ioctl_KBASE_IOCTL_MEM_FREE(ctx, pid_tgid);
        break;
    case 0xc0188016:
        ret = trace_ioctl_KBASE_IOCTL_MEM_IMPORT(ctx, pid_tgid);
        break;
    case 0x4018800e:
        ret = trace_ioctl_KBASE_IOCTL_MEM_JIT_INIT(ctx, pid_tgid);
        break;
    case 0x4008800e:
        ret = trace_ioctl_KBASE_IOCTL_MEM_JIT_INIT_10_2(ctx, pid_tgid);
        break;
    case 0x4010800e:
        ret = trace_ioctl_KBASE_IOCTL_MEM_JIT_INIT_11_5(ctx, pid_tgid);
        break;
    case 0x4010801b:
        ret = trace_ioctl_KBASE_IOCTL_MEM_PROFILE_ADD(ctx, pid_tgid);
        break;
    case 0xc0108006:
        ret = trace_ioctl_KBASE_IOCTL_MEM_QUERY(ctx, pid_tgid);
        break;
    case 0x4020800f:
        ret = trace_ioctl_KBASE_IOCTL_MEM_SYNC(ctx, pid_tgid);
        break;
    case 0x8004:
        ret = trace_ioctl_KBASE_IOCTL_POST_TERM(ctx, pid_tgid);
        break;
    case 0xc008803c:
        ret = trace_ioctl_KBASE_IOCTL_READ_USER_PAGE(ctx, pid_tgid);
        break;
    case 0x40048001:
        ret = trace_ioctl_KBASE_IOCTL_SET_FLAGS(ctx, pid_tgid);
        break;
    case 0x40018037:
        ret = trace_ioctl_KBASE_IOCTL_SET_LIMITED_CORE_COUNT(ctx, pid_tgid);
        break;
    case 0x4010801c:
        ret = trace_ioctl_KBASE_IOCTL_SOFT_EVENT_UPDATE(ctx, pid_tgid);
        break;
    case 0x4010801d:
        ret = trace_ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP(ctx, pid_tgid);
        break;
    case 0x4010801e:
        ret = trace_ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP(ctx, pid_tgid);
        break;
    case 0x40208018:
        ret = trace_ioctl_KBASE_IOCTL_STREAM_CREATE(ctx, pid_tgid);
        break;
    case 0x40048012:
        ret = trace_ioctl_KBASE_IOCTL_TLSTREAM_ACQUIRE(ctx, pid_tgid);
        break;
    case 0x8013:
        ret = trace_ioctl_KBASE_IOCTL_TLSTREAM_FLUSH(ctx, pid_tgid);
        break;
    case 0xc0048000:
        ret = trace_ioctl_KBASE_IOCTL_VERSION_CHECK(ctx, pid_tgid);
       break;
    //case 0xc0048000:
    //    ret = trace_ioctl_KBASE_IOCTL_VERSION_CHECK_RESERVED(ctx, pid_tgid);
    //    break;
    default:
        ret = trace_other_syscalls(ctx, pid_tgid, 0x400000000000000);
    }
    return ret;
}

void __always_inline trace_syscalls(sys_enter_args *ctx, uint64_t pid_tgid) {
    int nr = ctx->id;
    int fd_is_dev = 0;
    char dev [] = "/dev/bifrost";
    uint8_t *fd_mask = bpf_syscall_fd_mask_lookup_elem(&nr);
    if (fd_mask) {
        for (int i = 0; i < 5; i++) {
            if ((*fd_mask >> i) & 0x01 &&
                (bpf_check_fd(dev, ctx->regs[i]))) {
                fd_is_dev = 1;
                break;
            }
        }
    }
    if (fd_is_dev) {
        if (nr == 29) {
            trace_ioctl(ctx, pid_tgid);
        } else if (nr == 222) {
            trace_mmap_bifrost(ctx, pid_tgid);
        } else {
            trace_other_syscalls(ctx, pid_tgid, 0x4000000000000000);
        }
    } else {
        trace_other_syscalls(ctx, pid_tgid, 0);
    }

    return;
}

//DEFINE_BPF_PROG("tracepoint/raw_syscalls/sys_exit", 0, 0, sys_exit_prog)
SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit_prog (sys_exit_args *ctx) {
    int nr = ctx->id;
    uint32_t data = 1;
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t tgid = pid_tgid;
    bool is_tgid_traced = bpf_traced_tgid_map_lookup_elem(&tgid) != NULL;
    bool is_comm_setting = bpf_comm_setting_pid_tgid_map_lookup_elem(&pid_tgid) != NULL;
    bool is_32bit = (process_mode() == 32);

    bpf_comm_setting_pid_tgid_map_delete_elem(&pid_tgid);
    if (is_comm_setting) {
        if (is_current_prog_target()) {
            bpf_traced_tgid_map_update_elem(&tgid, &data, BPF_ANY);
        }
    }

    if (is_tgid_traced) {
        if (is_comm_setting) {
            comm_string comm;
            bpf_get_current_comm(&comm, 16);
            bpf_traced_pid_tgid_comm_map_update_elem(&pid_tgid, &comm, BPF_ANY);
        } else if (is_forking_syscall(nr, is_32bit)) {
            uint32_t child_tgid = ctx->ret;
            bpf_traced_tgid_map_update_elem(&child_tgid, &data, BPF_ANY);
        }
        trace_syscall_return(ctx, pid_tgid);
    }

	return 0;
}

//LICENSE("GPL");
char _license[] SEC("license") = "GPL";
