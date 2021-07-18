// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 yongchao duan
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "f2flatency.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

const volatile unsigned int ctrl_filter_tgid = 0;
const volatile unsigned int ctrl_filter_pid = 0;
const volatile unsigned int ctrl_target_latency = 0; //ns
const volatile unsigned int ctrl_call_graph = 0;


struct hist latency;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROC);
    __type(key, u64);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_STACKS);
    __type(key, u32);
    __uint(value_size, STACK_DEPTH * sizeof(u64));
} stacks SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
} events SEC(".maps");



SEC("1")
int BPF_PROG(start_point)
{
    static uint64_t zero;
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;
    if (ctrl_filter_tgid && tgid != ctrl_filter_tgid)
        return 0;
    if (ctrl_filter_pid && pid != ctrl_filter_pid)
        return 0;
    u64 *lat = bpf_map_lookup_or_try_init(&start, &id, &zero);
    if (lat)
        *lat = bpf_ktime_get_ns();
    return 0;
}

SEC("2")
int BPF_PROG(end_point)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;
    if (ctrl_filter_tgid && tgid != ctrl_filter_tgid)
        return 0;
    if (ctrl_filter_pid && pid != ctrl_filter_pid)
        return 0;

    u64 *st = bpf_map_lookup_elem(&start, &id);
    if (!st)
        return 0;

    u64 ns = bpf_ktime_get_ns();
    s64 delta = ns - *st;

    if (delta < ctrl_target_latency)
        return 0;

    if (ctrl_target_latency) {
        int stackid = STACKID_NONE;
        struct task_stack s;
        if (ctrl_call_graph)
            stackid = bpf_get_stackid(ctx, &stacks, 0);
        if (stackid >= 0) {
            s.stackid = stackid;
            s.cpu = bpf_get_smp_processor_id();
            s.pid = pid;
            s.ns = ns;
            bpf_get_current_comm(s.comm, TASK_COMM_LEN);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &s, sizeof(s));
        }
    }

    u32 slot = log2(delta);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;
    __sync_fetch_and_add(&latency.slots[slot].n, 1);
    __sync_fetch_and_add(&latency.slots[slot].total_ns, (u64)delta);

    /* No filter, delete elem, avoid large hash tables */
    if (ctrl_filter_tgid == 0 && ctrl_filter_pid == 0)
        bpf_map_delete_elem(&start, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
