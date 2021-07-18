# System Diagnose Tools (SDT)
  
SDT is a collection of many useful tools and examples for efficient linux kernel tracing and debugging.
It makes use of Libbpf + BPF CO-RE (Compile Once – Run Everywhere) instead of BCC framework for more
resource efficiency and compatibility between kernel versions.

## Dependency:
### Kernel:
Our main target is long term kernel 5.4.x which is enabled 'BTF' debuginfo.

### Compiler:
clang && clang-libs && llvm && llvm-libs above or equal to version 11.

### Others:
dwarves & libdwarves above or equal to version 1.16.

## Build:
cd tools
make

## Usage:
Please refer to detail example files in examples directory.

## Available Tools:
tools/biopattern: Identify random/sequential disk access patterns.
tools/runqslower: Trace long process scheduling delays.
tools/runqlat: Run queue (scheduler) latency as a histogram.
tools/cpudist: Summarize on- and off-CPU time per task as a histogram.
tools/execsnoop: Trace new processes via exec() syscalls.
tools/opensoop: Trace open(2) syscalls.

## TODO:
Extend tool coverage for various kernel components.

## Contacts:
Any issue and bug report please contact us via below emails.

Chengguang Xu <charliecgxu@tencent.com>
Yongchao Duan <yongduan@tencent.com>

## Reference:
The following resources are useful to understand what BPF CO-RE is and how to use it:

BPF Portability and CO-RE
https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html
HOWTO: BCC to libbpf conversion
https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html
