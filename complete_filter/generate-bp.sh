#!/bin/bash

# This script generates libbpf_prog entries for all .c files in the
# current directory and prints them to standard output.

# Loop through all files in the current directory ending with .c
for c_file in *.c; do
  # Get the base name of the file by removing the .c extension
  base_name="${c_file%.c}"

  # Print the libbpf_prog entry using a here document for clarity.
  # This substitutes the base_name into the template.
  cat << EOF
libbpf_prog {
    name: "${base_name}.bpf",
    srcs: ["${c_file}"],
    header_libs: [
        "bpf_prog_headers",
        "libcutils_headers",
        "android_bpf_defs",
    ],
    cflags: [
        "-Isystem/bpf/include/bpf",
        "-Iexternal/libbpf/include/uapi/linux",
    ],
}

EOF
done
