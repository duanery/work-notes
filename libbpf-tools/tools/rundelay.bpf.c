// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 yongchao duan
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "rundelay.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_STACKS 2048
#define TASK_RUNNING 	0

const volatile pid_t targ_tgid = 0;
const volatile pid_t targ_pid = 0;
const volatile unsigned int targ_latency = 0;

// Control feature enable and disable
const volatile bool ctrl_do_sample = 0;
const volatile unsigned int ctrl_sample_accuracy = 0;
const volatile bool ctrl_do_callchain = 0;
const volatile bool ctrl_do_resched_curr = 0;


#define MAX_THREADS 16
#define MAX_THREADS_MASK (MAX_THREADS-1)
struct thread_record threads[MAX_THREADS];
int next_thread = 0;

#define THREAD_RECORD_OP(fn) ___apply(___arrayop, MAX_THREADS)(fn, 0)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_THREADS*2);
	__type(key, u32);
	__type(value, u32);
} thread_to_record SEC(".maps");

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

__kconfig extern bool CONFIG_THREAD_INFO_IN_TASK;
__kconfig extern bool CONFIG_FAIR_GROUP_SCHED;
__kconfig extern bool CONFIG_CFS_BANDWIDTH;


static __always_inline
unsigned int task_cpu(const struct task_struct *p)
{
    if (CONFIG_THREAD_INFO_IN_TASK)
        return BPF_CORE_READ(p, cpu);
    else
        return bpf_get_smp_processor_id();
    /*else {
        struct thread_info *t = BPF_CORE_READ(p, stack);
        return BPF_CORE_READ(t, cpu);
    }*/
}
static __always_inline
struct cfs_rq *curr_cfs_rq(struct rq *rq)
{
    if (CONFIG_FAIR_GROUP_SCHED)
        return BPF_CORE_READ(rq, curr, se.cfs_rq);
    else
        return &rq->cfs;
}


static __always_inline
int trace_enqueue(struct task_struct *p)
{
    if (!targ_tgid ||
        targ_tgid != BPF_CORE_READ(p, tgid))
        return 0;

    u32 pid = BPF_CORE_READ(p, pid);
    struct thread_record *tr;
    u32 *pi;

    if (targ_pid && targ_pid != pid)
        return 0;

    pi = bpf_map_lookup_elem(&thread_to_record, &pid);
    if (!pi) {
        if (next_thread >= MAX_THREADS)
            return 0;
        u32 i = next_thread++;
        tr = &threads[i & MAX_THREADS_MASK];
        tr->pid = pid;
        tr->action = ACTION_CLEANUP;
        bpf_probe_read_kernel_str(&tr->comm, sizeof(tr->comm), BPF_CORE_READ(p, comm));
    	bpf_map_update_elem(&thread_to_record, &pid, &i, 0);
    } else {
        tr = &threads[(*pi) & MAX_THREADS_MASK];
        if (tr->pid != pid)
            return 0;
    }
    if (tr->action == ACTION_CLEANUP) {
    	tr->ts = bpf_ktime_get_ns();
        tr->cpu = task_cpu(p);
        tr->action = ACTION_WAKEUP;
    }
	return 0;
}

static __always_inline
void record_migrate_task(void *ctx, struct thread_record *tr, unsigned int new_cpu)
{
    if (tr->action == ACTION_WAKEUP || tr->action == ACTION_RUN) {
        u32 old = tr->cpu;
        tr->cpu = new_cpu;

        if (tr->next < MAX_KEYPOINT) {
            int id = STACKID_NONE;
            if (ctrl_do_callchain) {
                id = bpf_get_stackid(ctx, &stacks, 0);
                if (id >= 0) tr->stacks++;
                else id = STACKID_NONE;
            }
        
            unsigned char next = (tr->next++) & KEYPOINT_MASK;
            struct keypoint *kp = &tr->keypoint[next];
            kp->type = KEYPOINT_MIGRATE_TASK;
            kp->cpu = bpf_get_smp_processor_id();
            kp->ts = bpf_ktime_get_ns();
            kp->migrate_task.old_cpu = old;
            kp->migrate_task.new_cpu = new_cpu;
            kp->migrate_task.stackid = id;
        }
    }
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
    tr->ts = 0;
    tr->now = 0;
    tr->cpu = 0;
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
    tr->ts = 0;
    tr->now = 0;
    tr->cpu = 0;
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
    tr->ts = now;
    tr->action = ACTION_WAKEUP;
    tr->next = tr->stacks = 0;
}




SEC("raw_tp/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	return trace_enqueue(p);
}


SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
	return trace_enqueue(p);
}


SEC("raw_tp/sched_migrate_task")
int BPF_PROG(sched_migrate_task, struct task_struct *p, unsigned int new_cpu)
{
    if (!targ_tgid ||
        targ_tgid != BPF_CORE_READ(p, tgid))
        return 0;

    u32 pid = BPF_CORE_READ(p, pid);
    u32 *pi;

    if (targ_pid && targ_pid != pid)
        return 0;
    
    pi = bpf_map_lookup_elem(&thread_to_record, &pid);
    if (pi) {
        struct thread_record *tr = &threads[(*pi) & MAX_THREADS_MASK];
        if (tr->pid == pid)
            record_migrate_task(ctx, tr, new_cpu);
    }
    return 0;
}


#define ___record_perf_sample(n) \
    if (n < next_thread) { \
        tr = &threads[n & MAX_THREADS_MASK]; \
        record_perf_sample(ctx, tr, cpu, pid); \
    } else return 0;

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
    if (!targ_latency)
        return 0;
    if (!ctrl_do_sample)
        return 0;

    u32 cpu = bpf_get_smp_processor_id();
    u32 pid = bpf_get_current_pid_tgid();
    struct thread_record *tr;
    THREAD_RECORD_OP(___record_perf_sample)
    return 0;
}


#define ___record_resched_curr(n) \
    if (n < next_thread) { \
        tr = &threads[n & MAX_THREADS_MASK]; \
        record_resched_curr(ctx, tr, cpu, pid); \
    } else return 0;

SEC("kprobe/resched_curr")
int BPF_KPROBE(resched_curr, struct rq *rq)
{
    if (!targ_latency)
        return 0;
    if (!ctrl_do_resched_curr)
        return 0;

    u32 pid = BPF_CORE_READ(rq, curr, pid);
    u32 cpu = BPF_CORE_READ(rq, cpu);
    struct thread_record *tr;
    THREAD_RECORD_OP(___record_resched_curr)
    return 0;
}


SEC("raw_tp/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev,
	struct task_struct *next)
{
	u32 pid;
    u64 now;
	s64 delta;
    u32 *pi;
    struct thread_record *tr;

    if (!targ_latency)
        return 0;

    now = bpf_ktime_get_ns();

    pid = BPF_CORE_READ(prev, pid);
    pi = bpf_map_lookup_elem(&thread_to_record, &pid);
    if (pi) {
        tr = &threads[(*pi) & MAX_THREADS_MASK];
        if (tr->pid == pid) {
            if (BPF_CORE_READ(prev, state) == TASK_RUNNING)
                record_action_wakeup(ctx, tr, now);
            else
                record_action_cleanup(ctx, tr, now);
        }
    } else
        if (BPF_CORE_READ(prev, state) == TASK_RUNNING)
            trace_enqueue(prev);

    
	pid = BPF_CORE_READ(next, pid);
    pi = bpf_map_lookup_elem(&thread_to_record, &pid);
    if (pi) {
        tr = &threads[(*pi) & MAX_THREADS_MASK];
        if (tr->pid == pid) {
        	delta = now - tr->ts;
            if (delta < targ_latency)
                record_action_drop(ctx, tr, now);
            else
                record_action_run(ctx, tr, now);
        }
    }
    return 0;

}

char LICENSE[] SEC("license") = "GPL";

