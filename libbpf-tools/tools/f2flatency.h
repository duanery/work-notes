/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __F2FLATENCY_H
#define __F2FLATENCY_H


#define MAX_PROC  4096
#define MAX_STACKS 2048
#define STACKID_NONE (MAX_STACKS + 1)
#define STACK_DEPTH 64
#define TASK_COMM_LEN 16

#define MAX_SLOTS       26
struct hist {
    struct {
        uint32_t n;
        uint64_t total_ns;
    } slots[MAX_SLOTS];
};


struct task_stack {
    uint16_t stackid;
    uint16_t cpu;
    uint32_t pid;
    uint64_t ns;
    char comm[TASK_COMM_LEN];
};


#endif

