#include <bpf/BpfMap.h>
#include <bpf/BpfUtils.h>
#include <bpf/bpf.h>
#include <libbpf.h>
#include <libbpf_android.h>
#include <linux/android/binder.h>
#include <atomic>
#include <iostream>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>
#include <dirent.h>
#include <deque>
#include <map>
#include <set>
#include <bitset>
#include <sstream>
#include <signal.h>
#include <thread>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string>

#include "tracer_id.h"

using android::base::unique_fd;
using std::chrono::steady_clock;
using std::chrono::duration;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::microseconds;

std::ofstream g_log_stream;
std::atomic<bool> g_stop(false);
std::atomic<uint64_t> g_update_ctr;
uint64_t g_update_ts;

std::vector<std::thread> g_spawner_proc_ths;
std::string g_traced_prog;

std::string g_bpf_prog_name;

struct trace_entry_ctr_t {
    struct bpf_spin_lock lock;
    uint32_t val;
};

struct rb_elem {
    struct bpf_spin_lock lock;
    uint8_t next;
    uint16_t id0[128];
    uint16_t id1[128];
};

struct u_rb_elem {
    uint8_t ctr;
    uint16_t id[256];
    u_rb_elem(): ctr(0) {
        memset(&id, 0, 256);
    }
};

#define BITSET_NR_ENTRY 3 // 1 event + 1 ioctl + 1 syscall
#define BITSET_SIZE     (BITSET_NR_ENTRY * ID_NR_SIZE)

int id_to_bitset_off(uint16_t id) {
    uint8_t hdr = ID_HDR(id);
    int ret = 0;
    switch (hdr) {
    case ID_HDR_SYSCALL: ret = ID_NR(id); break;
    case ID_HDR_IOCTL: ret = ID_NR(id) + ID_NR_SIZE; break;
    case ID_HDR_EVENT: ret = ID_NR(id) + ID_NR_SIZE*2; break;
    }
    return ret;
}

struct sifter_rb {
    int len;
    std::string name;
    unique_fd fd;
    unique_fd ctr_fd;
    std::vector<u_rb_elem> saved;
    std::map<std::deque<uint16_t>, std::bitset<BITSET_SIZE> > tbl; // [syscall seq][next syscall]

    sifter_rb(int l, std::string nm, int f, int ctr):
        len(l), name(nm), fd(android::base::unique_fd(f)),
        ctr_fd(android::base::unique_fd(ctr)) {
        saved.resize(32768);
    };

    void update_tbl(int pid, uint8_t ctr, rb_elem &rb, bool missing_events) {
        bool first_half = (ctr%2 == 0);
        uint8_t dst_start = first_half? 0 : 128;
        uint16_t *src_ptr = first_half? rb.id0 : rb.id1;
        memcpy(&saved[pid].id[dst_start], src_ptr, 128);

        std::deque<uint16_t> seq;
        uint8_t start = missing_events? dst_start : dst_start-len;
        for (int i = 0; i < len; i++) {
            uint8_t off = start+i;
            seq.push_back(saved[pid].id[off]);
        }
        for (int i = 0; i < 127-len; i++) {
            uint8_t off = start+len+i;
            uint16_t next = saved[pid].id[off];
            if (tbl.find(seq) != tbl.end()) {
                if (!tbl[seq].test(id_to_bitset_off(next))) {
                    printf("r0\n");
                    g_update_ctr++;
                }
                tbl[seq].set(id_to_bitset_off(next));
            } else {
                printf("r1\n");
                g_update_ctr++;
                tbl[seq] = std::bitset<BITSET_SIZE>(0);
                tbl[seq].set(id_to_bitset_off(next));
            }
            if (next == ID_EVENT_END)
                break;
            seq.pop_front();
            seq.push_back(next);
        }
    };
};

struct sifter_lut {
    int type;
    std::string name;
    unique_fd fd;
    std::vector<uint64_t> val;

    sifter_lut(int t, std::string nm, int size, int f):
        type(t), name(nm), fd(android::base::unique_fd(f)) {
        val.resize(size);
    };
};

struct sifter_map {
    int type;
    std::string name;
    unique_fd fd;
    std::vector<uint64_t> val;

    sifter_map(int t, std::string nm, int size, int f):
        type(t), name(nm), fd(android::base::unique_fd(f)) {
        val.resize(size);
    };
};

struct sifter_prog {
    int type;
    std::string event;
    std::string entry;
    unique_fd fd;

    sifter_prog(int t, std::string ev, std::string en, int f):
        type(t), event(ev), entry(en), fd(android::base::unique_fd(f)) {};
};

#define CTR_BITS        10
#define CTR_SIZE        (1 << CTR_BITS)
#define CTR_IDX_MASK    (CTR_SIZE - 1)
#define CTR_CTR_MASK    ~CTR_IDX_MASK
#define CTR_IDX(x)      (CTR_IDX_MASK & x)
#define CTR_CTR(x)      (CTR_CTR_MASK & x)

struct sifter_arg {
    int         size;
    std::string name;
    unique_fd   fd;
    char        *buf;

    sifter_arg(int s, std::string name, int fd):
        size(s), name(name), fd(unique_fd(fd)) {

        buf = (char *)malloc(size);
        if (!buf) {
            std::cerr << "Failed to allocate memory for tracing " << name << "\n";
        }
    };

    ~sifter_arg() { free(buf); }
};

struct sifter_syscall {
    int ctr_size;
    uint32_t ctr_idx_mask;
    uint32_t ctr_ctr_mask;
    bool inited;
    std::string program_name;
    std::string syscall_name;
    unique_fd ctr_fd;
    std::vector<sifter_arg *> args;

    sifter_syscall(std::string prog_nm, std::string sc_nm, int ctr_bits):
        inited(false), program_name(prog_nm), syscall_name(sc_nm) {
        std::string path = "/sys/fs/bpf/map_" + prog_nm + "_" + sc_nm + "_ctr";
        int fd = bpf_obj_get(path.c_str());
        if (fd == -1)
            return;

        ctr_size = 1 << ctr_bits;
        ctr_idx_mask = ctr_size - 1;
        ctr_ctr_mask = ~ctr_idx_mask;
        inited = true;
        ctr_fd = unique_fd(fd);
    };
    
    bool is_inited() const {
        return inited;
    }

    bool add_arg(int size, std::string arg_nm) {
        std::string path = "/sys/fs/bpf/map_" + program_name + "_" + arg_nm;
        int fd = bpf_obj_get(path.c_str());
        if (fd == -1)
            return false;

        sifter_arg *arg = new sifter_arg(size, arg_nm, fd);
        args.push_back(arg);
        return true;
    }

    inline uint32_t ctr_idx(int ctr) {
        return ctr & ctr_idx_mask;
    }

    inline uint32_t ctr_ctr(int ctr) {
        return ctr & ctr_ctr_mask;
    }
};

int proc_bitness(std::vector<int> &proc_bitness, int pid, int verbose) {
    int bitness = proc_bitness[pid];
    if (bitness != -1)
        return bitness;

    std::ifstream ifs;
    int len = 0;
    char target[256];
    std::string file = "/proc/" + std::to_string(pid) + "/exe";
    len = readlink(file.c_str(), target, sizeof(target)-1);

    target[len] = '\0';
    //std::cout << "check " << target << "\n";

    //Determine Zygote processes bitness by name: app_process32/64
    if (len > 2) {
        if (target[len-2] == '3' && target[len-1] == '2')
            bitness = 32;
        if (target[len-2] == '6' && target[len-1] == '4')
            bitness = 64;
        if (bitness != -1) {
            proc_bitness[pid] = bitness;
            return bitness;
        }
    }

    //Determine processes bitness by ELF header magic number
    char magic[5] = {};
    ifs.open(target, std::ios::binary);
    if (!ifs) {
        if (verbose > 3)
            std::cout << "Error checking bitness via ELF magic: cannot open "
                    << target << " (" << pid << ")\n";
    } else {
        ifs.read(magic, 5);
        if (*(uint32_t *)(magic) == 0x464c457f) {
            if (magic[4] == 1) {
                bitness = 32;
            } else if (magic[4] == 2) {
                bitness = 64;
            } else if (verbose > 3){
                std::cout << "Error checking bitness via ELF header: "
                        << target << " (" << pid << ") invalid EI_CLASS "
                        << std::hex << (uint32_t)magic[4] << std::dec << "\n";
            }
        } else if (verbose > 3) {
            std::cout << "Error checking bitness via ELF header: "
                        << target << " (" << pid << ") invalid ELF magic number\n";
        }
    }
    ifs.close();
    proc_bitness[pid] = bitness;
    return bitness;
}

/*
 * Trace entry:
 *   User:
 *   |     64     |     64     |  8*size    |
 *     timestamp      event        data
 *                |  32  | 32  |
 *                   hdr   size
 *
 *   Kernel syscall:
 *   |     64     |     64     |    ...     |
 *     timestamp     pid tgid    arguments
 *
 */
#define EVENT_USER                0x8000000000000000
#define EVENT_USER_SIZE_MASK      0x00000000ffffffff
#define EVENT_USER_HDR_MASK       0xffffffff00000000
#define DEF_EVENT_USER(id, size)  (EVENT_USER | (id << 32) | size)
#define EVENT_USER_TRACE_START    DEF_EVENT_USER(1UL, 0)
#define EVENT_USER_TRACE_LOST     DEF_EVENT_USER(2UL, sizeof(uint32_t))

void write_user_event(std::ofstream &ofs, uint64_t event, void *buf = NULL) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t timestamp = ts.tv_sec * 1000000000 + ts.tv_nsec;
    ofs.write(reinterpret_cast<const char*>(&timestamp), sizeof(uint64_t));
    ofs.write(reinterpret_cast<const char*>(&event), sizeof(uint64_t));

    int size = event & EVENT_USER_SIZE_MASK;
    if (size > 0) {
        if (buf) {
            ofs.write(reinterpret_cast<const char*>(buf), size);
        } else {
            std::cerr << "write_user_event got null source ptr\n";
            buf = calloc(1, size);
            ofs.write(reinterpret_cast<const char*>(buf), size);
        }
    }
}

void print_buffer(const char *buf, int size) {
    for (int i = 0; i < size; i++) {
        std::ios cout_state(nullptr);
        cout_state.copyfmt(std::cout);
        std::cout << std::hex << std::setfill('0') << std::setw(2);
        std::cout << (int)buf[i] << (((i+1)%16 == 0 || i == size-1)? "\n" : " ");
        std::cout.copyfmt(cout_state);
    }
}

class sifter_tracer {
private:
    int m_init;
    int m_verbose;
    int m_bitness;
    std::string m_name;
    std::vector<sifter_prog> m_progs;
    std::vector<sifter_map> m_maps;
    std::vector<sifter_lut> m_luts;
    std::vector<sifter_rb> m_rbs;
    std::vector<sifter_syscall *> m_syscalls;
    std::vector<std::thread *> m_update_threads;
    std::vector<int> m_proc_bitness;
    std::set<int> m_ignored_pids;
    std::vector<std::string> m_target_prog_comm_list;
    unique_fd m_target_prog_comm_map_fd;
    int m_min_pid;
    bool m_maps_update_start;
    bool m_rbs_update_start;
    bool m_args_update_start;

    void update_maps_thread() {
        while (m_maps_update_start) {
            for (auto &m : m_maps) {
                int size = m.val.size();
                std::vector<uint64_t> val(size);
                for (int i = 0; i < size; i++)
                    android::bpf::findMapEntry(m.fd, &i, &val[i]);

                switch (m.type) {
                    case 0:
                        if (val[0] < m.val[0]) {
                            printf("m0\n");
                            g_update_ctr++;
                            m.val[0] = val[0];
                        }
                        if (val[1] > m.val[1]) {
                            printf("m0\n");
                            g_update_ctr++;
                            m.val[1] = val[1];
                        }
                        break;
                    case 1:
                        if (~m.val[0] & val[0]) {
                            printf("m1\n");
                            g_update_ctr++;
                        }
                        if (~m.val[1] & val[1]) {
                            printf("m1\n");
                            g_update_ctr++;
                        }
                        m.val[0] |= val[0];
                        m.val[1] |= val[1];
                        break;
                }
            }
        }
    }

    void update_rbs_thread() {
        m_min_pid = gettid();
        while (m_rbs_update_start) {
            for (auto &rb : m_rbs) {
                auto begin = std::chrono::steady_clock::now();
                for (int p = m_min_pid; p < 32768; p++) {
                    if (m_ignored_pids.find(p) != m_ignored_pids.end())
                        continue;

                    uint8_t ctr;
                    android::bpf::findMapEntry(rb.ctr_fd, &p, &ctr);
                    uint8_t last_ctr = rb.saved[p].ctr;
                    if (ctr != last_ctr
                        && proc_bitness(m_proc_bitness, p, m_verbose) == m_bitness) {
                        bool missing_events = (ctr != last_ctr+1);
                        if (m_verbose > 0) {
                            if (missing_events)
                                std::cout << "Update events pid[" << p << "] "
                                    << (int)ctr << " - " << (int)last_ctr << "\n";
                            else
                                std::cout << "Update events pid[" << p << "] "
                                    << (int)ctr <<"\n";
                        }
                        rb_elem rbp;
                        android::bpf::findMapEntry(rb.fd, &p, &rbp);
                        rb.saved[p].ctr = ctr;
                        rb.update_tbl(p, ctr, rbp, missing_events);
                    }
                }
                auto end = std::chrono::steady_clock::now();
                std::chrono::duration<float> scan_time = end - begin;
                uint32_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(scan_time).count();
                usleep(1000000-dur_ms*1000);
                g_update_ts++;
                g_log_stream << g_update_ts << "," << g_update_ctr << "\n";
                g_log_stream.flush();
                if (m_verbose > 1) {
                    std::cout << "finish seq update in " << dur_ms << " ms, #update = " << g_update_ctr << "\n";
                }
            }
        }
    }

    void update_arg_thread(sifter_syscall *sc) {
        steady_clock::time_point curr_time;
        steady_clock::time_point last_update_time = steady_clock::now();
        uint64_t last_update_period = 0;
        uint64_t update_period = 0;
        trace_entry_ctr_t curr_ctr_struct;
        uint32_t curr_ctr;
        uint32_t last_ctr = 0;
        int zero_idx = 0;

        std::string trace = "raw_trace_" + sc->syscall_name + ".dat";
        std::ofstream ofs(trace, std::ofstream::app);
        if (!ofs) {
            std::cerr << "Failed to open trace file " << trace << "\n";
            return;
        }

        write_user_event(ofs, EVENT_USER_TRACE_START);

        while (1) {
            android::bpf::findMapEntry(sc->ctr_fd, &zero_idx, &curr_ctr_struct);
            curr_ctr = curr_ctr_struct.val;

            int start = 0, end = 0;
            uint32_t ctr_diff = curr_ctr - last_ctr;
            curr_time = steady_clock::now();
            last_update_period = duration_cast<microseconds>(curr_time - last_update_time).count();
            if (ctr_diff > sc->ctr_size) {
                std::cout << "lost events: " << sc->syscall_name << " "
                        << last_ctr << "-" << curr_ctr << "\n";
                write_user_event(ofs, EVENT_USER_TRACE_LOST, &ctr_diff);

                start = sc->ctr_idx(curr_ctr - sc->ctr_size/8);
                end = sc->ctr_idx(curr_ctr);
                last_ctr = curr_ctr;
                last_update_time = curr_time;
            } else if (ctr_diff > sc->ctr_size/8 || !m_args_update_start) {
                if (m_verbose > 2)
                    std::cout << "saving events: " << sc->syscall_name << " "
                            << last_ctr << "-" << curr_ctr << "\n";

                start = sc->ctr_idx(last_ctr);
                end = sc->ctr_idx(curr_ctr);
                last_ctr = curr_ctr;
                last_update_time = curr_time;
            }

            int i = start;
            while (i != end) {
                for (int a = 0; a < sc->args.size(); a++) {
                    sifter_arg *arg = sc->args[a];
                    android::bpf::findMapEntry(arg->fd, &i, arg->buf);
                    ofs.write(reinterpret_cast<const char*>(arg->buf), arg->size);

                    if (m_verbose > 3) {
                        std::cout << "\n";
                        print_buffer(arg->buf, arg->size);
                    }
                }
                i = ++i & (sc->ctr_size - 1);
            }
            update_period = (last_update_period + update_period) / 2;
            if (update_period > 10000) {
                update_period = 10000;
            }
            usleep(update_period);

            if (!m_args_update_start && ctr_diff == 0)
                break;
        }

        ofs.close();
    }

public:
    size_t map_num() {
        return m_maps.size();
    }

    size_t rb_num() {
        return m_rbs.size();
    }

    size_t syscall_num() {
        return m_syscalls.size();
    }

    int add_prog(int type, std::string event, std::string entry) {
        std::string probe_name;
        switch (type) {
            case 0: probe_name = std::string("_kretprobe_") + entry; break;
            case 1: probe_name = std::string("_kprobe_") + entry; break;
            case 2: probe_name = std::string("_tracepoint_") + event + "_" + entry; break;
            case 3: probe_name = std::string("_kprobe_") + event; break;
            case 4: probe_name = std::string("_kprobe_") + event; break;
        }
        std::string path = "/sys/fs/bpf/prog_" + m_name + probe_name;
        if (access(path.c_str(), 0) != 0) {
	    bool isCritical = true;
            int ret = android::bpf::loadProg(path.c_str(), &isCritical);
            if (ret) {
                std::cerr << path << " does not exist and attempt to load it failed\n";
                return ret;
            }
        }
        int fd = bpf_obj_get(path.c_str());
        if (fd != -1)
            m_progs.push_back(sifter_prog(type, event, entry, fd));
        return fd;
    }

    int add_map(int type, std::string map) {
        std::string path = "/sys/fs/bpf/map_" + m_name + "_" + map;
        int fd = bpf_obj_get(path.c_str());
        if (fd != -1)
            m_maps.push_back(sifter_map(type, map, 2, fd));
        return fd;
    }

    int add_lut(int type, std::string map, std::vector<uint64_t> &val) {
        std::string path = "/sys/fs/bpf/map_" + m_name + "_" + map;
        int fd = bpf_obj_get(path.c_str());
        if (fd != -1)
            m_luts.push_back(sifter_lut(type, map, val.size(), fd));
        for (int i = 0; i < val.size(); i++) {
            android::bpf::writeToMapEntry(m_luts.back().fd, &i, &val[i], BPF_ANY);
        }
        return fd;
    }

    int add_rb(int len, std::string map) {
        std::string path = "/sys/fs/bpf/map_" + m_name + "_" + map;
        int fd = bpf_obj_get(path.c_str());
        path += "_ctr";
        int ctr_fd = bpf_obj_get(path.c_str());
        if (fd != -1 && ctr_fd != -1) {
            m_rbs.push_back(sifter_rb(len, map, fd, ctr_fd));
            return fd;
        }
        return -1;
    }

    int attach_prog() {
        for (auto &p : m_progs) {
            if (p.type == 0 || p.type == 1) {
                bpf_probe_attach_type type = p.type == 1? BPF_PROBE_ENTRY : BPF_PROBE_RETURN;
                int ret = bpf_attach_kprobe(p.fd, type, p.event.c_str(), p.entry.c_str(), 0, 10);
                if (ret < 0) {
                    std::cout << "bpf_attach_kprobe return " << ret << " " << errno << "\n";
                    return -1;
                }
            } else if (p.type == 3 || p.type == 4) {
                bpf_probe_attach_type type = p.type == 4? BPF_PROBE_ENTRY : BPF_PROBE_RETURN;
                int delim_pos = p.entry.find(":");
                if (delim_pos == std::string::npos) {
                    std::cout << "bpf_attach_uprobe entry should be <path>:<offset>\n";
                    return -1;
                }
                std::string path = p.entry.substr(0, delim_pos);
                std::string offset = p.entry.substr(delim_pos+1);
                size_t pos = 0;
                uint64_t off = std::stoull(offset.c_str(), &pos, 16);
                if (pos != offset.size()) {
                    std::cout << "bpf_attach_uprobe offset " << offset << "is not a valid number\n";
                    return -1;
                }

                int ret = bpf_attach_uprobe(p.fd, type, p.event.c_str(), path.c_str(), off, -1, 0);
                if (ret < 0) {
                    std::cout << "bpf_attach_uprobe return " << ret << " " << errno << "\n";
                    return -1;
                }
            } else if (p.type == 2) {
                int ret = bpf_attach_tracepoint(p.fd, p.event.c_str(), p.entry.c_str());
                if (ret < 0) {
                    std::cout << "bpf_attach_tracepoint return " << ret << " " << errno << "\n";
                    return -1;
                }
            }
        }
        return 0;
    }

    int detach_prog() {
        for (auto &p : m_progs) {
            if (p.type == 0 || p.type == 1) {
                int ret = bpf_detach_kprobe(p.event.c_str());
                if (ret < 0) {
                    std::cout << "bpf_detach_kprobe return " << ret << " " << errno << "\n";
                    return -1;
                }
            } else if (p.type == 2) {
                int ret = bpf_detach_tracepoint(p.event.c_str(), p.entry.c_str());
                if (ret < 0) {
                    std::cout << "bpf_detach_tracepoint return " << ret << " " << errno << "\n";
                    return -1;
                }
            }
        }
        return 0;
    }

    void print_rbs() {
        for (auto &rb : m_rbs) {
            for (auto &entry : rb.tbl) {
                for (auto it : entry.first)
                    std::cout << std::setw(5) << it << " ";
                std::cout << "| ";
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[i])
                        std::cout << std::setw(5) << i << " ";
                }
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[ID_NR_SIZE+i])
                        std::cout << std::setw(5) << ((ID_HDR_IOCTL << ID_HDR_SHIFT) | i) << " ";
                }
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[2*ID_NR_SIZE+i])
                        std::cout << std::setw(5) << ((ID_HDR_EVENT << ID_HDR_SHIFT) | i) << " ";
                }
                std::cout << "\n";
            }
            std::cout << "Total: " << rb.tbl.size() << " sequences" << "\n";
        }
    }

    int save_traced_pid_comm() {
        std::string path = "/sys/fs/bpf/map_" + m_name + "_traced_pid_tgid_comm_map";
        std::ofstream ofs("traced_pid_tgid_comm_map.log");
        int fd = bpf_obj_get(path.c_str());
        if (fd == -1 || !ofs)
            return -1;

        unique_fd ufd = unique_fd(fd);
        uint64_t pid;
        char comm[16];

        if (android::bpf::getFirstMapKey(ufd, &pid))
            goto error;

        if (android::bpf::findMapEntry(ufd, &pid, (void *)comm))
            goto error;

        ofs << pid << " " << comm << "\n";
        while (android::bpf::getNextMapKey(ufd, &pid, &pid) == 0) {
            if (android::bpf::findMapEntry(ufd, &pid, (void *)comm))
                goto error;
            ofs << pid << " " << comm << "\n";
        }
        ofs.close();
        return 0;

error:
        ofs.close();
        return -1;
    }

    void dump_rbs(std::string file) {
        std::ofstream ofs(file, std::ofstream::app);
        for (auto &rb : m_rbs) {
            ofs << "r " << rb.tbl.size() << "\n";
            for (auto &entry : rb.tbl) {
                ofs << std::setw(3) << entry.first.size()
                        << std::setw(4) << entry.second.count() << " ";
                for (auto it : entry.first)
                    ofs << std::setw(5) << it << " ";
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[i])
                        ofs << std::setw(5) << i << " ";
                }
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[ID_NR_SIZE+i])
                        ofs << std::setw(5) << ((ID_HDR_IOCTL << ID_HDR_SHIFT) | i) << " ";
                }
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[2*ID_NR_SIZE+i])
                        ofs << std::setw(5) << ((ID_HDR_EVENT << ID_HDR_SHIFT) | i) << " ";
                }
                ofs << "\n";
            }
        }
    }

    void recover_rbs(std::string file) {
        std::ifstream ifs(file);

        if (ifs) {
            for (auto &m : m_rbs) {
                char c;
                while (ifs >> c && c != 'r') {}

                uint64_t seqs_size, seq_size, next_size, v;
                ifs >> seqs_size;
                for (int j = 0; j < seqs_size; j++) {
                    std::deque<uint16_t> seq;
                    std::bitset<BITSET_SIZE> next;
                    ifs >> seq_size >> next_size;
                    seq.resize(seq_size);
                    for (int i = 0; i < seq_size; i++) {
                        ifs >> seq[i];
                    }
                    for (int i = 0; i < next_size; i++) {
                        ifs >> v;
                        next.set(id_to_bitset_off(v));
                    }
                    m.tbl[seq] = next;
                }
            }
        }
    }

    void print_maps() {
        for (auto &m : m_maps) {
            int size = m.val.size();
            std::cout << m.name << " [";
            for (int i = 0; i < size; i++) {
                android::bpf::findMapEntry(m.fd, &i, &m.val[i]);
                std::cout << m.val[i];
                if (i != size-1)
                    std::cout << ", ";
            }
            std::cout << "]\n";
        }
    }

    void dump_maps(std::string file) {
        if (m_maps.empty())
            return;

        std::ofstream ofs(file, std::ofstream::app);
        ofs << "m\n";
        for (auto &m : m_maps) {
            for (auto v : m.val)
                ofs << v << " ";
            ofs << "\n";
        }
    }

    void recover_maps(std::string file) {
        std::ifstream ifs(file);

        if (!ifs) {
            for (auto &m: m_maps) {
                switch (m.type) {
                    case 0:
                        m.val[0] = (uint64_t)-1;
                        m.val[1] = 0;
                        break;
                    case 1:
                        m.val[0] = 0;
                        m.val[1] = 0;
                        break;
                }
            }
        } else {
            char c;
            while (ifs >> c && c != 'm') {}

            for (auto &m : m_maps) {
                for (auto &v : m.val)
                    ifs >> v;
            }
        }

    }

    void start_update_maps() {
        m_maps_update_start = 1;
        std::thread *th = new std::thread(&sifter_tracer::update_maps_thread, this);
        m_update_threads.push_back(th);
    }

    void stop_update_maps() {
        m_rbs_update_start = 0;
    }

    void start_update_rbs() {
        m_ignored_pids.insert(gettid());
        m_rbs_update_start = 1;
        std::thread *th = new std::thread(&sifter_tracer::update_rbs_thread, this);
        m_update_threads.push_back(th);
    }

    void stop_update_rbs() {
        m_rbs_update_start = 0;
    }

    void start_update_args() {
        m_args_update_start = 1;
        for (auto s : m_syscalls) {
            std::thread *th = new std::thread(&sifter_tracer::update_arg_thread, this, s);
            m_update_threads.push_back(th);
        }
    }

    void stop_update_args() {
        m_args_update_start = 0;
    }
    
    operator bool() const {
        return m_init == 1;
    }

    //sifter_tracer(): m_init(0) {};

    sifter_tracer(std::string file, std::vector<std::string> &target_prog_list, int verbose=0)
        : m_init(0), m_verbose(verbose), m_target_prog_comm_list(target_prog_list) {
        std::ifstream ifs(file);

        if (!ifs) {
            std::cerr << "Failed to parse configuration. File \"" << file
                << "\" does not exist\n";
            return;
        }

        ifs >> m_name >> m_bitness;
        g_bpf_prog_name = m_name;
        char cfg_type;
        while (ifs >> cfg_type) {
            switch (cfg_type) {
                case 'p': {
                    int type;
                    std::string event, entry;
                    ifs >> type >> event >> entry;
                    if (add_prog(type, event, entry) == -1) {
                        std::cerr << "Failed to add prog (type:"
                            << type << ", " << event << ", " << entry << ")\n";
                        return;
                    }

                    if (m_verbose > 0)
                        std::cout << "Added prog (type:"
                            << type << ", " << event << ", " << entry << ")\n";
                    break;
                }
                case 'm': {
                    int type;
                    std::string name;
                    ifs >> type >> name;
                    if (add_map(type, name) == -1) {
                        std::cerr << "Failed to add map (type:"
                            << type << ", name:" << name << ")\n";
                        return;
                    }

                    if (m_verbose > 0)
                        std::cout << "Added map (type:"
                            << type << ", name:" << name << ")\n";
                    break;
                }
                case 'l': {
                    int type, size;
                    int i = 0;
                    std::string name;
                    ifs >> type >> name >> size;
                    std::vector<uint64_t> vals;
                    vals.resize(size);
                    while (i < size && ifs >> vals[i++]) {}
                    if (i != size) {
                        std::cerr << "Failed to add lookup table (type:"
                            << type << ", name:" << name << ", size:" << size
                            << "). Too few entries (" << i-1 << ")\n";
                        return;
                    }

                    if (add_lut(type, name, vals) == -1) {
                        std::cerr << "Failed to add lookup table (type:"
                            << type << ", name:" << name << ", size:" << size
                            << "). errno(" << errno << ")\n";
                        return;
                    }

                    if (m_verbose > 0)
                        std::cout << "Added lookup table (type:"
                            << type << ", name:" << name << ", size:" << size << ")\n";
                    break;
                }
                case 'r': {
                    int length;
                    std::string name;
                    ifs >> length >> name;
                    if (add_rb(length, name) == -1) {
                        std::cerr << "Failed to add ringbuffer (name:" << name << ")\n";
                        return;
                    }
                    if (m_verbose > 0)
                        std::cout << "Added ringbuffer (name:" << name << ")\n";
                    break;
                }
                case 's': {
                    int arg_num;
                    int ctr_bits;
                    std::string name;
                    ifs >> ctr_bits >> arg_num >> name;
                    sifter_syscall *syscall = new sifter_syscall(m_name, name, ctr_bits);
                    if (!syscall->is_inited()) {
                        std::cerr << "Failed to add syscall (name:" << name << ")\n";
                        return;
                    }
                    if (m_verbose > 0)
                        std::cout << "Added syscall (name:" << name << ")\n";

                    int arg_size;
                    std::string arg_name;
                    for (int i = 0; i < arg_num; i++) {
                        ifs >> arg_size >> arg_name;
                        if (!syscall->add_arg(arg_size, arg_name)) {
                            std::cerr << "Failed to add argument (name:" << arg_name << ")\n";
                            return;
                        } else if (m_verbose > 0) {
                            std::cout << "Added argument (name:" << arg_name << ")\n";
                        }
                    }
                    m_syscalls.push_back(syscall);

                    break;
                }
                default:
                    std::cerr << "Failed to parse configuration. Invalid cfg entry \'"
                        << cfg_type << "\'\n";
                    return;
            }
        }
        m_proc_bitness.resize(32768, -1);

        g_update_ctr = 0;
        g_update_ts = 0;
        std::stringstream ss;
        std::time_t t = std::time(nullptr);
        ss << "tracing_agent_" << t << ".log";
        g_log_stream.open(ss.str());
        if (!g_log_stream) {
            std::cerr << "Failed to open update log\n";
            return;
        }

        std::string path = "/sys/fs/bpf/map_" + m_name + "_target_prog_comm_map";
        int target_prog_comm_map_fd = bpf_obj_get(path.c_str());
        if (target_prog_comm_map_fd != -1)
            m_target_prog_comm_map_fd = unique_fd(target_prog_comm_map_fd);

        uint32_t dummy_val = 1;
        for (auto s : m_target_prog_comm_list) {
            char target_prog_comm[16] = {};
            strncpy(target_prog_comm, s.c_str(), 16);
            android::bpf::writeToMapEntry(m_target_prog_comm_map_fd,
                    target_prog_comm, &dummy_val, BPF_ANY);
        }

        m_init = 1;
    }

    ~sifter_tracer() {
        m_init = 0;
        stop_update_rbs();
        detach_prog();
        for (auto th : m_update_threads) {
            th->join();
        }
    }

};

void signal_handler(int s) {
    (void)s;
    g_stop.store(true);
}

std::string get_proc_name(int pid) {
    std::ifstream ifs;
    std::string proc_name;
    std::string proc_name_path = "/proc/" + std::to_string(pid) + "/cmdline";
    ifs.open(proc_name_path);
    std::getline(ifs, proc_name);
    return proc_name.substr(0, proc_name.find('\0'));
}

void get_proc_spawners(std::vector<int> &proc_spawners) {
    DIR *dir;
    if ((dir = opendir("/proc/")) == NULL) {
        std::cerr << "Failed to open /proc/, which is needed to monitor processes of interest\n";
        return;
    }

    const char *proc_spawners_name[] = {"-/system/bin/sh", "zygote", "zygote64"};
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        char *p;
        long pid = strtol(de->d_name, &p, 10);
        if (*p)
            continue;

        std::string proc_name = get_proc_name(pid);
        for (int i = 0; i < 3; i++) {
            if (proc_name.compare(proc_spawners_name[i]) == 0) {
                proc_spawners.push_back(pid);
                std::cout << "Monitoring process spawners [" << pid << "] " << proc_name << "\n";
                break;
            }
        }
    }
    closedir(dir);

    return;
}

std::string ptrace_read_str(int pid, uint64_t addr) {
    union u {
        uint32_t val;
        char chars[4];
    } data;
    std::cout << "addr: "<< std::hex << addr << "\n";
    char path[256];
    for (int i = 0; i < 256; i+=4) {
        data.val = ptrace(PTRACE_PEEKDATA, pid, addr+i*4 , NULL);
        std::cout << std::hex << data.val << std::dec << " ";
        memcpy(&path[i], data.chars, 4);
        if (data.chars[0] == 0 || data.chars[1] == 0 || data.chars[2] == 0 || data.chars[3] == 0)
            break;
    }
    return std::string(path);
}

bool loop_until_identified(int pid, std::string prog_name) {
    int ret = 0;
    int status = 0;
    unsigned long data = 0;
    struct user_regs_struct regs;
    struct iovec io;
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);
    while (1) {
        std::cout << "[" << pid << "] waitpid\n";
        waitpid(pid, &status, 0);
        std::cout << "[" << pid << "] status changed: " << std::hex << status << std::dec<<"\n";
        if (WIFEXITED(status)) {
            std::cout << "[" << pid << "] exit\n";
            break;
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data);
            std::cout << "[" << pid << "] fork [" << data << "] " << "\n";
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data);
            std::cout << "[" << pid << "] vfork [" << data << "] " << "\n";
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data);
            std::cout << "[" << pid << "] clone [" << data << "]\n";
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))) {
            std::string new_prog_name = get_proc_name(pid);
            std::cout << "[" << pid << "] execve " << new_prog_name << "\n";
            if (prog_name.compare(new_prog_name) == 0)
                return true;
            else
                return false;
        }
        std::cout << "[" << pid << "] cont \n";
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        if (g_stop.load()) break;
    };

    return false;
}

void proc_spawner_monitor_th(int spwaner_pid) {
    int ret = 0;
    int status = 0;
    unsigned long data = 0;
    ret = ptrace(PTRACE_ATTACH, spwaner_pid, NULL, NULL);
    if (ret != 0) {
        std::cerr << "[" << spwaner_pid << "] ptrace attach error: " << strerror(errno) << "\n";
        return;
    }
    waitpid(spwaner_pid, &status, 0);

    data = PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC;
    ret = ptrace(PTRACE_SETOPTIONS, spwaner_pid, NULL, data);
    if (ret != 0) {
        std::cerr << "[" << spwaner_pid << "] ptrace set option error: " << strerror(errno) << "\n";
        return;
    }
    ptrace(PTRACE_CONT, spwaner_pid, NULL, NULL);

    while (1) {
        std::cout << "[" << spwaner_pid << "] waitpid\n";
        waitpid(spwaner_pid, &status, 0);
        std::cout << "[" << spwaner_pid << "] status changed: " << status << "\n";
        if (WIFEXITED(status)) {
            std::cout << "[" << spwaner_pid << "] exit\n";
            break;
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, spwaner_pid, NULL, &data);
            std::cout << "[" << spwaner_pid << "] fork [" << data << "] " << "\n";
            loop_until_identified(data, g_traced_prog);
            ptrace(PTRACE_DETACH, data, NULL, NULL);
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, spwaner_pid, NULL, &data);
            std::cout << "[" << spwaner_pid << "] vfork [" << data << "] " << "\n";
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, spwaner_pid, NULL, &data);
            std::cout << "[" << spwaner_pid << "] clone [" << data << "] " << "\n";
        }
        std::cout << "[" << spwaner_pid << "] cont \n";
        ptrace(PTRACE_CONT, spwaner_pid, NULL, NULL);

        if (g_stop.load()) break;
    };

    ptrace(PTRACE_DETACH, spwaner_pid, NULL, NULL);
    return;
}

int main(int argc, char *argv[]) {
    bool recover = true;
    int log_interval = 1;
    int verbose = 0;
    char empty_string[] = "";
    char *config_file = empty_string;
    char *log_file = empty_string;
    char *target_prog = empty_string;

    int opt;
    while ((opt = getopt (argc, argv, "hi:v:c:r:o:p:")) != -1) {
        switch (opt) {
            case 'h':
                std::cout << "Sifter agent\n";
                std::cout << "Options\n";
                std::cout << "-c config   : agent configuration file [required]\n";
                std::cout << "-o output   : maps logging output file [required except manual mode]\n";
                std::cout << "-p program  : target programs to be traced (comm's seperated by \",\")\n";
                std::cout << "-i interval : maps logging interval in seconds [default=10]\n";
                std::cout << "-r recover  : recover from log when start [default=1 (enabled)]\n";
                std::cout << "-v verbose  : verbosity [default=0]\n";
                std::cout << "-h          : helps\n";
                return 0;
	    case 'i': if (optarg) log_interval = std::stoi(std::string(optarg)); break;
	    case 'v': if (optarg) verbose = std::stoi(std::string(optarg)); break;
            case 'c': if (optarg) config_file = optarg; break;
	    case 'r': if (optarg) recover = std::stoi(std::string(optarg)) > 0; break;
            case 'o': if (optarg) log_file = optarg; break;
            case 'p': if (optarg) target_prog = optarg; break;
            case '?':
                if (optopt == 'c')
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
                return 1;
            default: abort();
        }
    }

//    g_traced_prog = std::string(traced_prog);
//    std::vector<int> proc_spawners;
//    get_proc_spawners(proc_spawners);
//    for (auto pid : proc_spawners) {
//        std::thread th(proc_spawner_monitor_th, pid);
//        g_spawner_proc_ths.push_back(std::move(th));
//    }

    struct sigaction sa = {};
    sa.sa_handler = signal_handler;
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    int i = 0, last_delim_pos = -1;
    std::vector<std::string> target_prog_list;
    while (1) {
        if (target_prog[i] == ',' || target_prog[i] == '\0') {
            std::string prog(&target_prog[last_delim_pos+1], i-last_delim_pos-1);
            target_prog_list.push_back(prog);
            last_delim_pos = i;
            if (target_prog[i] == '\0')
                break;
        }
        i++;
    }

    sifter_tracer tracer(config_file, target_prog_list, verbose);

    if (!tracer) {
        std::cout << "Failed to create tracer\n";
        return 1;
    }

    tracer.attach_prog();

    if (recover) {
        if (tracer.rb_num() > 0)
            tracer.recover_rbs(log_file);
        if (tracer.map_num() > 0)
            tracer.recover_maps(log_file);
    }

    if (tracer.map_num() > 0) {
        tracer.start_update_maps();
    }

    if (tracer.rb_num() > 0) {
        tracer.start_update_rbs();
    }

    if (tracer.syscall_num() > 0) {
        tracer.start_update_args();
    }

    std::string tmp_file = std::string(log_file) + ".tmp";
    while (1) {
        tracer.dump_maps(tmp_file);
        tracer.dump_rbs(tmp_file);
        std::rename(tmp_file.c_str(), log_file);
        std::remove(tmp_file.c_str());
        sleep(log_interval);
        if (g_stop.load()) break;
    }

    tracer.save_traced_pid_comm();
    tracer.stop_update_maps();
    tracer.stop_update_rbs();
    tracer.stop_update_args();
    return 0;
}
