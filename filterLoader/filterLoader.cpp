#include <bpf/BpfMap.h>
#include <bpf/BpfUtils.h>
#include <bpf/bpf.h>
#include <libbpf.h>
#include <libbpf_android.h>

#include <log/log.h> 

#include <iostream>
#include <string>
#include <memory>
#include <stdexcept>
#include <vector>

#include <sys/syscall.h>
#include <linux/seccomp.h>

#include <sys/stat.h>
// Ensures C-style linkage for the libbpf headers.
extern "C" {
    #include <bpf/libbpf.h>
}

// Defining a BPF program type for seccomp filters.
constexpr int BPF_PROG_TYPE_SECCOMP = 32;

// A custom deleter for bpf_object pointers to ensure proper cleanup with std::unique_ptr.
struct BpfObjectDeleter {
    void operator()(bpf_object* obj) const {
        if (obj) {
            bpf_object__close(obj);
        }
    }
};

// A smart pointer type for managing the lifecycle of a bpf_object.
using BpfObjectPtr = std::unique_ptr<bpf_object, BpfObjectDeleter>;

/**
 * @brief Loads, sets up, and pins a BPF program and its maps.
 *
 * @param bpf_file The path to the BPF object file.
 * @param prog_name The name of the program within the BPF object file to load.
 * @return true if the program and maps were successfully loaded and pinned, false otherwise.
 */
bool loadAndPinBpfProgram(const std::string& bpf_file, const std::string& prog_name) {
        // Open the BPF object file.
        BpfObjectPtr obj_ptr(bpf_object__open(bpf_file.c_str()));
        if (!obj_ptr) {
            ALOGE("Failed to open BPF object file: %s", bpf_file.c_str());
	    return false;
        }
        ALOGI("filterLoader: Successfully opened BPF object file: %s", bpf_file.c_str());

        // Find the BPF program by its name within the object file.
        bpf_program* prog = bpf_object__find_program_by_name(obj_ptr.get(), prog_name.c_str());
        if (!prog) {
            ALOGE("filterLoader: Could not find program '%s' in %s", prog_name.c_str(), bpf_file.c_str());
	    return false;
        }

        // Set the program type to seccomp.
        bpf_program__set_type(prog, static_cast<bpf_prog_type>(BPF_PROG_TYPE_SECCOMP));
        ALOGI("filterLoader: Set program type to BPF_PROG_TYPE_SECCOMP for '%s'.", prog_name.c_str());

        // Load the BPF object into the kernel.
        if (bpf_object__load(obj_ptr.get()) != 0) {
            ALOGE("filterLoader: Failed to load BPF object into the kernel for file: %s", bpf_file.c_str());
	    return false;
        }
        ALOGI("filterLoader: Successfully loaded BPF program '%s'!", prog_name.c_str());

        // Pin the program to the BPF filesystem.
        std::string pin_path_prog = "/sys/fs/bpf/prog_" + prog_name;
        if (bpf_program__pin(prog, pin_path_prog.c_str()) != 0) {
            ALOGE("Failed to pin program '%s' to %s",prog_name.c_str(), pin_path_prog.c_str());
	    return false;
        }
        ALOGI("filterLoader: Successfully pinned program '%s' to %s", prog_name.c_str(), pin_path_prog.c_str());


        // Iterate over all maps in the BPF object and pin them.
        struct bpf_map *map;
        bpf_object__for_each_map(map, obj_ptr.get()) {
            const char* map_name = bpf_map__name(map);
            char pin_path_map[256];

            snprintf(pin_path_map, sizeof(pin_path_map), "/sys/fs/bpf/map_%s_%s", prog_name.c_str(), map_name);

            int err = bpf_map__pin(map, pin_path_map);
            if (err) {
                // We'll log an error but continue, treating map pinning failure as non-fatal for other programs.
                ALOGE("filterLoader: Error: failed to pin map '%s' at '%s': %s\n",
                        map_name, pin_path_map);
            } else {
                ALOGE("filterLoader: Successfully pinned map '%s' to %s", map_name, pin_path_map);
            }
        }

	const char * pin_path = pin_path_prog.c_str();
	if (chmod(pin_path, 0644) != 0) {
    		ALOGE("Failed to chmod %s: %s", pin_path, strerror(errno));
	} else {
    		ALOGI("Successfully set permissions for %s", pin_path);
	}

    return true; // Indicate success.
}


int main() {
    // Define the list of BPF files and their corresponding program names.
    // Each file should contain exactly one program as specified.
    const std::vector<std::string> bpf_files = {
        "/etc/bpf/bifrostFilterSeq.bpf",
        "/etc/bpf/fstat.bpf",
	"/etc/bpf/mmapbifrost.bpf",
	"/etc/bpf/read.bpf",
        "/etc/bpf/ioctlKBASEIOCTLCSQUEUEREGISTER.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLKCPUQUEUEENQUEUE.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLREADUSERPAGE.bpf",
	"/etc/bpf/ioctlKBASEIOCTLCSQUEUETERMINATE.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLMEMALLOCEX.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLSETFLAGS.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLCONTEXTPRIORITYCHECK.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLCSTILERHEAPINIT.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLMEMCOMMIT.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLSTICKYRESOURCEMAP.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLCSEVENTSIGNAL.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLCSTILERHEAPTERM.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLMEMEXECINIT.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLSTICKYRESOURCEUNMAP.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLCSGETGLBIFACE.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLFENCEVALIDATE.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLMEMFREE.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLCSQUEUEBIND.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLGETCONTEXTID.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLMEMIMPORT.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLCSQUEUEGROUPTERMINATE.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLKCPUQUEUECREATE.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLMEMJITINIT.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLCSQUEUEKICK.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLKCPUQUEUEDELETE.bpf",
    	"/etc/bpf/ioctlKBASEIOCTLMEMQUERY.bpf"
	// Add more BPF file paths here
    };

    const std::vector<std::string> prog_names = {
        "filter_seq",
        "filter_fstat",
	"filter_mmap_bifrost",
	"filter_read",
	"filter_ioctl_KBASE_IOCTL_CS_QUEUE_REGISTER",
    	"filter_ioctl_KBASE_IOCTL_KCPU_QUEUE_ENQUEUE",
    	"filter_ioctl_KBASE_IOCTL_READ_USER_PAGE",
    	"filter_ioctl_KBASE_IOCTL_CS_QUEUE_TERMINATE",
    	"filter_ioctl_KBASE_IOCTL_MEM_ALLOC_EX",
    	"filter_ioctl_KBASE_IOCTL_SET_FLAGS",
    	"filter_ioctl_KBASE_IOCTL_CONTEXT_PRIORITY_CHECK",
    	"filter_ioctl_KBASE_IOCTL_CS_TILER_HEAP_INIT",
    	"filter_ioctl_KBASE_IOCTL_MEM_COMMIT",
    	"filter_ioctl_KBASE_IOCTL_STICKY_RESOURCE_MAP",
    	"filter_ioctl_KBASE_IOCTL_CS_EVENT_SIGNAL",
    	"filter_ioctl_KBASE_IOCTL_CS_TILER_HEAP_TERM",
    	"filter_ioctl_KBASE_IOCTL_MEM_EXEC_INIT",
    	"filter_ioctl_KBASE_IOCTL_STICKY_RESOURCE_UNMAP",
    	"filter_ioctl_KBASE_IOCTL_CS_GET_GLB_IFACE",
    	"filter_ioctl_KBASE_IOCTL_FENCE_VALIDATE",
    	"filter_ioctl_KBASE_IOCTL_MEM_FREE",
    	"filter_ioctl_KBASE_IOCTL_CS_QUEUE_BIND",
    	"filter_ioctl_KBASE_IOCTL_GET_CONTEXT_ID",
    	"filter_ioctl_KBASE_IOCTL_MEM_IMPORT",
    	"filter_ioctl_KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE",
    	"filter_ioctl_KBASE_IOCTL_KCPU_QUEUE_CREATE",
    	"filter_ioctl_KBASE_IOCTL_MEM_JIT_INIT",
    	"filter_ioctl_KBASE_IOCTL_CS_QUEUE_KICK",
    	"filter_ioctl_KBASE_IOCTL_KCPU_QUEUE_DELETE",
    	"filter_ioctl_KBASE_IOCTL_MEM_QUERY"
        // Add more program names here, corresponding to the files above
    };

    // Ensure the number of files matches the number of program names.
    if (bpf_files.size() != prog_names.size()) {
        ALOGE("filterLoader: Error: The number of BPF files must match the number of program names.");
        return 1;
    }
    
    int success_count = 0;
    for (size_t i = 0; i < bpf_files.size(); ++i) {
        if (loadAndPinBpfProgram(bpf_files[i], prog_names[i])) {
            success_count++;
        }
    }

    ALOGI("filterLoader: Finished processing all BPF programs.");
    ALOGI("filterLoader: Successfully loaded and pinned %d out of %zu programs.", success_count, bpf_files.size());

    if (success_count != bpf_files.size()) {
        return 1; // Return an error code if any of the programs failed.
    }

    return 0;
}

