// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 yongchao duan
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "rundelay.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

//#define DEBUG

#define MAX_STACKS 4096
#define TASK_RUNNING 	0

const volatile unsigned int targ_latency = 0;

// Control feature enable and disable
const volatile bool ctrl_do_sample = 0;
const volatile unsigned int ctrl_sample_accuracy = 0;
const volatile bool ctrl_do_callchain = 0;
const volatile bool ctrl_do_resched_curr = 0;


#define MAX_CPUS 256
#define MAX_CPUS_MASK (MAX_CPUS-1)
struct thread_record threads[MAX_CPUS];


//key: cpu, value: pid
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} percpu_thread SEC(".maps");

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


static __always_inline
void record_debug(void *ctx, struct thread_record *tr, u32 debugid, bool stack)
{
#ifdef DEBUG
    u64 now = bpf_ktime_get_ns();
    if (tr->next < MAX_KEYPOINT) {
        unsigned char n = (tr->next++) & KEYPOINT_MASK;
        struct keypoint *kp = &tr->keypoint[n];
        kp->type = KEYPOINT_DEBUG;
        kp->cpu = bpf_get_smp_processor_id(); //cpu;
        kp->ts = now;

        kp->debug.debugid = debugid;

        int id = STACKID_NONE;
        if (ctrl_do_callchain && stack) {
            id = bpf_get_stackid(ctx, &stacks, 0);
            if (id >= 0) tr->stacks++;
            else id = STACKID_NONE;
        }
        kp->debug.stackid = id;
    }
    tr->now = now;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, tr, tr->next == MAX_KEYPOINT ? sizeof(*tr) :
        offsetof(struct thread_record, keypoint) + (tr->next & KEYPOINT_MASK) * sizeof(struct keypoint));
    tr->next = tr->stacks = 0;
#endif
}


static __always_inline
int trace_enqueue(void *ctx, struct task_struct *p)
{
    u64 pid = BPF_CORE_READ(p, pid);
    u32 key = 0;
    u64 *ppid = bpf_map_lookup_elem(&percpu_thread, &key);

    if (!pid || !ppid || pid != *ppid)
        return 0;

    u32 cpu = bpf_get_smp_processor_id();
    u32 off = (cpu & MAX_CPUS_MASK) * sizeof(struct thread_record);
    struct thread_record *tr = (void *)threads + off;
    if (tr->pid == 0) {
        tr->cpu = cpu;
        tr->pid = (u32)pid;
        tr->action = ACTION_CLEANUP;
        bpf_probe_read_kernel_str(&tr->comm, sizeof(tr->comm), BPF_CORE_READ(p, comm));
    }
    record_debug(ctx, tr, __DEBUG_ENQUEUE, 1);
    //May wake up more than once
    if (tr->action == ACTION_CLEANUP) {
    	tr->ts = bpf_ktime_get_ns();
        tr->cpu = cpu;
        tr->action = ACTION_WAKEUP;
    }
	return 0;
}

static __always_inline
void record_action_latency(void *ctx, struct thread_record *tr, u64 now)
{
    tr->now = now;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, tr, tr->next == MAX_KEYPOINT ? sizeof(*tr) :
        offsetof(struct thread_record, keypoint) + (tr->next & KEYPOINT_MASK) * sizeof(struct keypoint));
    tr->next = tr->stacks = 0;
}

static __always_inline
void __record_perf_sample(void *ctx, struct thread_record *tr, u32 cpu, u32 pid)
{
    int id = STACKID_NONE;
    if (ctrl_do_callchain) {
        id = bpf_get_stackid(ctx, &stacks, 0);
        if (id >= 0) tr->stacks++;
        else id = STACKID_NONE;
    }

    unsigned char next = (tr->next++) & KEYPOINT_MASK;
    struct keypoint *kp = &tr->keypoint[next];
    kp->type = KEYPOINT_PERF_SAMPLE;
    kp->cpu = cpu;
    kp->ts = bpf_ktime_get_ns();
    kp->perf.stackid = id;
    kp->perf.pid = pid;
    bpf_get_current_comm(kp->perf.comm, TASK_COMM_LEN);
}

static __always_inline
void record_perf_sample(void *ctx, struct thread_record *tr, u32 cpu, u32 pid)
{
    if (tr->action == ACTION_WAKEUP && tr->cpu == cpu) {
        
        if (bpf_ktime_get_ns() - tr->ts < ctrl_sample_accuracy)
            return ;
        
        if (tr->next < MAX_KEYPOINT) {
            __record_perf_sample(ctx, tr, cpu, pid);
        } else {
            u64 now = bpf_ktime_get_ns();
            if (now - tr->ts < targ_latency)
                return;
            record_action_latency(ctx, tr, now);
            __record_perf_sample(ctx, tr, cpu, pid);
        }

        record_debug(ctx, tr, __DEBUG_PERF_SAMPLE, 0);
    }
}

static __always_inline
void record_resched_curr(void *ctx, struct thread_record *tr, u32 cpu, u32 pid)
{
    if ((tr->action == ACTION_WAKEUP && tr->cpu == cpu) ||
        (tr->action == ACTION_RUN && tr->pid == pid)) {

        if (tr->next < MAX_KEYPOINT) {
            int id = STACKID_NONE;
            if (ctrl_do_callchain) {
                id = bpf_get_stackid(ctx, &stacks, 0);
                if (id >= 0) tr->stacks++;
                else id = STACKID_NONE;
            }

            unsigned char next = (tr->next++) & KEYPOINT_MASK;
            struct keypoint *kp = &tr->keypoint[next];
            kp->type = KEYPOINT_RESCHED_CURR;
            kp->cpu = bpf_get_smp_processor_id(); //cpu;
            kp->ts = bpf_ktime_get_ns();
            kp->resched_curr.flags = 0;
            kp->resched_curr.targ_cpu = cpu;
            kp->resched_curr.stackid = id;
            kp->resched_curr.pid = pid;
        }
        
        record_debug(ctx, tr, __DEBUG_RESCHED_CURR, 0);
    }
}

static __always_inline
int record_action_cleanup(void *ctx, struct thread_record *tr, u64 now)
{
    if (tr->action == ACTION_RUN) {
        tr->now = now;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, tr, tr->next == MAX_KEYPOINT ? sizeof(*tr) :
            offsetof(struct thread_record, keypoint) + (tr->next & KEYPOINT_MASK) * sizeof(struct keypoint));
    }
    record_debug(ctx, tr, __DEBUG_ACTION_CLEANUP, 0);
    tr->ts = 0;
    tr->now = 0;
    tr->action = ACTION_CLEANUP;
    tr->next = tr->stacks = 0;
    return 0;
}

static __always_inline
void record_action_drop(void *ctx, struct thread_record *tr, u64 now)
{
    if (tr->stacks != 0) {
        tr->now = now;
        tr->action = ACTION_DROP_STACKID;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, tr, tr->next == MAX_KEYPOINT ? sizeof(*tr) :
            offsetof(struct thread_record, keypoint) + (tr->next & KEYPOINT_MASK) * sizeof(struct keypoint));
    }
    record_debug(ctx, tr, __DEBUG_ACTION_DROP, 0);
    tr->ts = 0;
    tr->now = 0;
    tr->action = ACTION_CLEANUP;
    tr->next = tr->stacks = 0;
}

static __always_inline
void record_action_run(void *ctx, struct thread_record *tr, u64 now)
{
    if (tr->action == ACTION_WAKEUP) {
        tr->now = now;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, tr, tr->next == MAX_KEYPOINT ? sizeof(*tr) :
            offsetof(struct thread_record, keypoint) + (tr->next & KEYPOINT_MASK) * sizeof(struct keypoint));
    }
    record_debug(ctx, tr, __DEBUG_ACTION_RUN, 0);
    tr->ts = now;
    tr->action = ACTION_RUN;
    tr->next = tr->stacks = 0;
}

static __always_inline
void record_action_wakeup(void *ctx, struct thread_record *tr, u64 now)
{
    if (tr->action == ACTION_RUN) {
        tr->now = now;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, tr, tr->next == MAX_KEYPOINT ? sizeof(*tr) :
            offsetof(struct thread_record, keypoint) + (tr->next & KEYPOINT_MASK) * sizeof(struct keypoint));
    }
    record_debug(ctx, tr, __DEBUG_ACTION_WAKEUP, 0);
    tr->ts = now;
    tr->action = ACTION_WAKEUP;
    tr->next = tr->stacks = 0;
}

static __always_inline
void record_sched_switch(void *ctx, struct thread_record *tr, struct task_struct *prev,
	    struct task_struct *next, u64 now)
{
    if (tr->action == ACTION_WAKEUP) {

        if (tr->next < MAX_KEYPOINT) {
            unsigned char n = (tr->next++) & KEYPOINT_MASK;
            struct keypoint *kp = &tr->keypoint[n];
            kp->type = KEYPOINT_SCHED_SWITCH;
            kp->cpu = bpf_get_smp_processor_id(); //cpu;
            kp->ts = now;
            
            bpf_probe_read_kernel_str(&kp->sched_switch.prev_comm, sizeof(kp->sched_switch.prev_comm), BPF_CORE_READ(prev, comm));
            kp->sched_switch.prev_pid = BPF_CORE_READ(prev, pid);
            kp->sched_switch.prev_prio = BPF_CORE_READ(prev, prio);
            kp->sched_switch.prev_state = BPF_CORE_READ(prev, state);

            bpf_probe_read_kernel_str(&kp->sched_switch.next_comm, sizeof(kp->sched_switch.next_comm), BPF_CORE_READ(next, comm));
            kp->sched_switch.next_pid = BPF_CORE_READ(next, pid);
            kp->sched_switch.next_prio = BPF_CORE_READ(next, prio);
        }

        record_debug(ctx, tr, __DEBUG_SCHED_SWITCH, 0);
    }
}


SEC("raw_tp/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	return trace_enqueue(ctx, p);
}


SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
	return trace_enqueue(ctx, p);
}


SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
    if (!targ_latency)
        return 0;
    if (!ctrl_do_sample)
        return 0;

    u32 cpu = bpf_get_smp_processor_id();
    u32 pid = bpf_get_current_pid_tgid();
    u32 off = (cpu & MAX_CPUS_MASK) * sizeof(struct thread_record);
    struct thread_record *tr = (void *)threads + off;
    record_perf_sample(ctx, tr, cpu, pid);
    return 0;
}


SEC("kprobe/resched_curr")
int BPF_KPROBE(resched_curr, struct rq *rq)
{
    if (!targ_latency)
        return 0;
    if (!ctrl_do_resched_curr)
        return 0;

    u32 pid = BPF_CORE_READ(rq, curr, pid);
    u32 cpu = BPF_CORE_READ(rq, cpu);
    u32 off = (cpu & MAX_CPUS_MASK) * sizeof(struct thread_record);
    struct thread_record *tr = (void *)threads + off;
    record_resched_curr(ctx, tr, cpu, pid);
    return 0;
}


SEC("raw_tp/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev,
	struct task_struct *next)
{
    if (!targ_latency)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u32 cpu = bpf_get_smp_processor_id();
    u32 off = (cpu & MAX_CPUS_MASK) * sizeof(struct thread_record);
    struct thread_record *tr = (void *)threads + off;

    if (tr->pid == 0)
        return 0;
    
    if (tr->pid == BPF_CORE_READ(prev, pid)) {
        if (BPF_CORE_READ(prev, state) == TASK_RUNNING)
            record_action_wakeup(ctx, tr, now);
        else
            record_action_cleanup(ctx, tr, now);
    }

    record_sched_switch(ctx, tr, prev, next, now);

    if (tr->pid == BPF_CORE_READ(next, pid)) {
    	s64 delta = now - tr->ts;
        if (delta < targ_latency)
            record_action_drop(ctx, tr, now);
        else
            record_action_run(ctx, tr, now);
    }
    return 0;

}

char LICENSE[] SEC("license") = "GPL";

