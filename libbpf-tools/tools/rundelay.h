/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RUNDELAY_H
#define __RUNDELAY_H

#define STACK_DEPTH 64

#define TASK_COMM_LEN	16

#define ACTION_CLEANUP      0
#define ACTION_DROP_STACKID 1
#define ACTION_WAKEUP       2
#define ACTION_RUN          3


#define KEYPOINT_NONE      0
#define KEYPOINT_PERF_SAMPLE  1
#define KEYPOINT_RESCHED_CURR 2
#define KEYPOINT_MIGRATE_TASK 3
#define KEYPOINT_SCHED_SWITCH 4

#define KEYPOINT_DEBUG        5
#define __DEBUG_ENQUEUE  1
#define __DEBUG_PERF_SAMPLE 2
#define __DEBUG_RESCHED_CURR 3
#define __DEBUG_ACTION_CLEANUP 4
#define __DEBUG_ACTION_DROP 5
#define __DEBUG_ACTION_RUN 6
#define __DEBUG_ACTION_WAKEUP 7
#define __DEBUG_SCHED_SWITCH 8



struct keypoint {
    unsigned char type; //KEYPOINT_*
    u32 cpu;
    u64 ts;
    union {
        // perf sample
        struct {
            u16 stackid;
            u32 pid;
            char comm[TASK_COMM_LEN];
        } perf;
        
        // resched_curr
        struct {
            unsigned char flags;
            u32 targ_cpu;
            u16 stackid;
            u32 pid;
            char comm[TASK_COMM_LEN];
        } resched_curr;
        
        struct {
            u32 old_cpu;
            u32 new_cpu;
            u16 stackid;
        } migrate_task;

        struct {
            char prev_comm[TASK_COMM_LEN];
            u32  prev_pid;
            int  prev_prio;
            u32  prev_state;
            char next_comm[TASK_COMM_LEN];
            u32  next_pid;
            int  next_prio;
        } sched_switch;

        struct {
            u64 now;
            u64 delay_ns;
        } latency;
        
        struct {
            u32 debugid;
            u16 stackid;
        } debug;
    };
};

#define STACKID_NONE 0xffff

#define MAX_KEYPOINT 16
#define KEYPOINT_MASK (MAX_KEYPOINT-1)

struct thread_record {
    u64 ts;
    u64 now;
    u16 cpu;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u16 action; //ACTION_*
    u16 stacks; //TODO
    u16 next;
    struct keypoint keypoint[MAX_KEYPOINT];
};

#define ___arrayop1(FN, n)  FN(n)
#define ___arrayop2(FN, n)  ___arrayop1(FN, n)  ___arrayop1(FN, n+1)
#define ___arrayop4(FN, n)  ___arrayop2(FN, n)  ___arrayop2(FN, n+2)
#define ___arrayop8(FN, n)  ___arrayop4(FN, n)  ___arrayop4(FN, n+4)
#define ___arrayop16(FN, n) ___arrayop8(FN, n)  ___arrayop8(FN, n+8)
#define ___arrayop24(FN, n) ___arrayop16(FN, n) ___arrayop8(FN, n+16)
#define ___arrayop32(FN, n) ___arrayop16(FN, n) ___arrayop16(FN, n+16)
#define ___arrayop64(FN, n) ___arrayop32(FN, n) ___arrayop32(FN, n+32)

#endif /* __RUNQLAT_H */

