// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 yongchao duan
//
// 2021-06-25   yongchao duan   Created this.

/************************************************************************
功能介绍:
1. 测试内核2个点之间的延迟:
   1) 动态支持各种测量点: tracepoint点,raw tp点, kprobe点, kretprobe点.
      1> 测量函数的延迟, kprobe点和kretprobe点之间.
      2> 测量syscall的延迟. sys_enter_xxx到sys_exit_xxx之间的延迟.
      3> 测量同一个点间的延迟. 如上一个kvm:kvm_exit点到kvm:kvm_exit点直接的延迟.
   2) 抓取超过指定延迟的栈.
2. TODO
   1) 目前各个点之间的索引关系,靠的是pid,需要扩充.
   2) 测量多个点之间的延迟.
   3) 输出延迟的详细信息.

************************************************************************/
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "f2flatency.h"
#include <f2flatency.skel.h>
#include "trace_helpers.h"

#include <linux/types.h>
#include <asm/errno.h>

#define PERF_BUFFER_PAGES 16

enum {
    TRACEPOINT = 1,
    RAW_TRACEPOINT,
    KPROBE,
    KRETPROBE,
};

struct env {
    bool timestamp;
    bool verbose;
    int pid;
    int tgid;
    int stype;
    char *start_category;
    char *start_point;
    int etype;
    char *end_category;
    char *end_point;
    char *function;
    int latency;
    bool call_graph;
    time_t interval;
    int times;
} env = {
    .latency = 0,
    .interval = 99999999,
    .times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "f2flatency 0.1";
const char *argp_program_bug_address = "<yongduan@tencent.com>";
const char argp_program_doc[] =
"Summarize function to function latency as histograms.\n"
"\n"
"USAGE: f2flatency -s TP -e TP [-f func] [-p PID] [-g TGID] [-T] [-V] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    f2flatency -s raw:kvm_exit -e raw:kvm_entry         # sum kvm exit latency\n"
"    f2flatency -s raw:kvm_exit -e raw:kvm_entry 1 10    # print 1 second summaries, 10 times\n"
"    f2flatency -s raw:kvm_exit -e raw:kvm_entry -NT 1   # 1s summaries, nanoseconds, and timestamps\n";

static const struct argp_option opts[] = {
    { "pid", 'p', "PID", 0, "process pid/thread id" },
    { "tgid", 'G', "TGID", 0, "task group pid" },
    { "start", 's', "tp:cat:name|raw:name|[k|kr]:func", 0, "start point\n"
                                                          " tp : tracepoint:category:tp_name\n"
                                                          "raw : raw_tracepoint:raw_name\n"
                                                          "  k : kprobe:function\n"
                                                          " kr : kretprobe:function" },
    { "end", 'e', "tp:cat:name|raw:name|[k|kr]:func", 0, "end point" },
    { "func", 'f', "func", 0, "kernel function latency" },
    { "latency", 'L', "LAT(ns)", 0, "latency threshold, nanosecond" },
    { "call-graph", 'g', NULL, 0, "enables call-graph recording" },
    { "timestamp", 'T', NULL, 0, "Include timestamp on output" },
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "", 'h', NULL, OPTION_HIDDEN, "" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    static int pos_args;
    int *ptype = NULL;
    char **pcategory = NULL;
    char **ppoint = NULL;

    switch (key) {
    case 'h':
        argp_help(state->root_argp, stderr, ARGP_HELP_STD_HELP, "f2flatency");
        exit(0);
    case 'v':
        env.verbose = true;
        break;
    case 'T':
        env.timestamp = true;
        break;
    case 'p':
        env.pid = strtol(arg, NULL, 10);
        break;
    case 'G':
        env.tgid = strtol(arg, NULL, 10);
        break;
    case 's':
        ptype = &env.stype;
        pcategory = &env.start_category;
        ppoint = &env.start_point;
        goto __parse;
    case 'e':
        ptype = &env.etype;
        pcategory = &env.end_category;
        ppoint = &env.end_point;
    __parse:
        if (arg) {
            char type[8] = {0};
            union {
                struct {
                    char category[64];
                    char tp_name[64];
                };
                char raw_name[64];
                char function[64];
            } u;
            *ptype = 0;
            *pcategory = NULL;
            *ppoint = NULL;
            if (sscanf(arg, "%[^:]:%[^:]:%s", type, u.category, u.tp_name) >= 2) {
                if (strcmp(type, "tp") == 0) {
                    *ptype = TRACEPOINT;
                    *pcategory = strdup(u.category);
                    *ppoint = strdup(u.tp_name);
                } else if (strcmp(type, "raw") == 0) {
                    *ptype = RAW_TRACEPOINT;
                    *ppoint = strdup(u.raw_name);
                } else if (strcmp(type, "k") == 0) {
                    *ptype = KPROBE;
                    *ppoint = strdup(u.function);
                } else if (strcmp(type, "kr") == 0) {
                    *ptype = KRETPROBE;
                    *ppoint = strdup(u.function);
                }
            } else
                argp_usage(state);
        }
        break;
    case 'f':
        env.function = strdup(arg);
        break;
    case 'L':
        env.latency = strtol(arg, NULL, 10);
        break;
    case 'g':
        env.call_graph = true;
        break;
    case ARGP_KEY_ARG:
        errno = 0;
        if (pos_args == 0) {
            env.interval = strtol(arg, NULL, 10);
            if (errno) {
                fprintf(stderr, "invalid internal\n");
                argp_usage(state);
            }
        } else if (pos_args == 1) {
            env.times = strtol(arg, NULL, 10);
            if (errno) {
                fprintf(stderr, "invalid times\n");
                argp_usage(state);
            }
        } else {
            fprintf(stderr,
                "unrecognized positional argument: %s\n", arg);
            argp_usage(state);
        }
        pos_args++;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
        const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
    exiting = true;
}

static void print_time(time_t t)
{
    printf("\n");
    if (env.timestamp) {
        struct tm *tm;
        char ts[64];
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
        printf("%-8s\n", ts);
    }
}


#define min(x, y) ({                 \
    typeof(x) _min1 = (x);             \
    typeof(y) _min2 = (y);             \
    (void) (&_min1 == &_min2);         \
    _min1 < _min2 ? _min1 : _min2; })
static void print_stars(unsigned int val, unsigned int val_max, int width)
{
    int num_stars, num_spaces, i;
    bool need_plus;

    num_stars = min(val, val_max) * width / val_max;
    num_spaces = width - num_stars;
    need_plus = val > val_max;

    for (i = 0; i < num_stars; i++)
        printf("*");
    for (i = 0; i < num_spaces; i++)
        printf(" ");
    if (need_plus)
        printf("+");
}

static void print_log2_hist_avg(struct hist *lat, int vals_size, const char *val_type)
{
    int stars_max = 40, idx_max = -1;
    unsigned int val, val_max = 0;
    unsigned long long low, high;
    int stars, width, i;

    for (i = 0; i < vals_size; i++) {
        val = lat->slots[i].n;
        if (val > 0)
            idx_max = i;
        if (val > val_max)
            val_max = val;
    }

    if (idx_max < 0)
        return;

    if (idx_max <= 32)
        stars = stars_max;
    else
        stars = stars_max / 2;

    printf("%-*s : count    %-*s average\n", idx_max <= 32 ? 24 : 44,
                    val_type, stars, "distribution");

    for (i = 0; i <= idx_max; i++) {
        low = (1ULL << (i + 1)) >> 1;
        high = (1ULL << (i + 1)) - 1;
        if (low == high)
            low -= 1;
        val = lat->slots[i].n;
        width = idx_max <= 32 ? 10 : 20;
        printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
        print_stars(val, val_max, stars);
        if (val)
            printf("| %lu\n", lat->slots[i].total_ns / val);
        else
            printf("|\n");
    }
}

static struct hist zero;

static int print_hist(struct f2flatency_bpf__bss *bss)
{
    struct hist latency = bss->latency;
    bss->latency = zero;
    if (memcmp(&zero, &latency, sizeof(struct hist))) {
        char val_type[256];
        snprintf(val_type, sizeof(val_type), "%s->%s(ns)", env.start_point, env.end_point);
        print_log2_hist_avg(&latency, MAX_SLOTS, val_type);
        printf("\n");
    }
    return 0;
}

void prog_set_type(struct bpf_program *prog, int type)
{
    switch (type)
    {
        case TRACEPOINT:
            bpf_program__set_tracepoint(prog);
            break;
        case RAW_TRACEPOINT:
            bpf_program__set_raw_tracepoint(prog);
            break;
        case KPROBE:
        case KRETPROBE:
            bpf_program__set_kprobe(prog);
            break;
        default:
           fprintf(stderr, "failed to set program type\n");
           exit(1);
    }
}

struct bpf_link *prog_attach(struct bpf_program *prog, int type, char *name, char *category)
{
    switch (type)
    {
        case TRACEPOINT:
            return bpf_program__attach_tracepoint(prog, category, name);
        case RAW_TRACEPOINT:
            return bpf_program__attach_raw_tracepoint(prog, name);
        case KPROBE:
            return bpf_program__attach_kprobe(prog, 0, name);
        case KRETPROBE:
            return bpf_program__attach_kprobe(prog, 1, name);
    }
    return (void *)-EINVAL;
}

struct event_ctx {
    int map_fd;
    struct ksyms *ksyms;
};

static void print_stack(struct event_ctx *ctx, uint32_t key)
{
    uint64_t stack[STACK_DEPTH];
    const struct ksym *ksym;
    int err;
    int i;

    if (key != STACKID_NONE) {
        memset(stack, 0, sizeof(stack));
        err = bpf_map_lookup_elem(ctx->map_fd, &key, &stack);
        if (err < 0) {
            return;
        }
        for (i = 0; i < STACK_DEPTH; i++) {
            if (stack[i] == 0) break;
            ksym = ksyms__map_addr(ctx->ksyms, stack[i]);
            printf("    %016lx %s+0x%lx\n", stack[i], ksym ? ksym->name : "Unknown", stack[i] - ksym->addr);
        }
        bpf_map_delete_elem(ctx->map_fd, &key);
    }
}

static void handle_event(void *_ctx, int cpu, void *data, __u32 data_sz)
{
    struct event_ctx *ctx = _ctx;
    const struct task_stack *s = data;
    char now[32];

    snprintf(now, sizeof(now), "%lu.%09lu", s->ns/1000000000UL, s->ns%1000000000UL);
    printf("%-16s %6d [%03d] %s: %s\n", s->comm, s->pid, s->cpu, now, env.end_point);
    print_stack(ctx, s->stackid);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}


int main(int argc, char **argv)
{
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    struct f2flatency_bpf *obj;
    struct perf_buffer_opts pb_opts;
    struct perf_buffer *pb = NULL;
    struct event_ctx ctx;
    time_t t;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (env.function) {
        env.stype = KPROBE;
        env.start_category = NULL;
        env.start_point = env.function;
        env.etype = KRETPROBE;
        env.end_category = NULL;
        env.end_point = env.function;
    }

    if (env.stype == 0 && env.etype == 0) {
        fprintf(stderr, "need start point or end point\n");
        return 1;
    }
    if (env.stype == 0) {
        env.stype = env.etype;
        env.start_category = env.end_category;
        env.start_point = env.end_point;
    }
    if (env.etype == 0) {
        env.etype = env.stype;
        env.end_category = env.start_category;
        env.end_point = env.start_point;
    }

    libbpf_set_print(libbpf_print_fn);

    err = bump_memlock_rlimit();
    if (err) {
        fprintf(stderr, "failed to increase rlimit: %d\n", err);
        return 1;
    }

    obj = f2flatency_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open and/or load BPF object\n");
        return 1;
    }

    /* initialize global data (filtering options) */
    obj->rodata->ctrl_filter_tgid = env.tgid;
    obj->rodata->ctrl_filter_pid = env.pid;
    obj->rodata->ctrl_target_latency = env.latency;
    obj->rodata->ctrl_call_graph = env.call_graph;
    if (!env.latency)
        bpf_map__set_max_entries(obj->maps.events, 1);

    prog_set_type(obj->progs.start_point, env.stype);
    prog_set_type(obj->progs.end_point, env.etype);

    err = f2flatency_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    if (env.call_graph)
        ctx.ksyms = ksyms__load();
    ctx.map_fd = bpf_map__fd(obj->maps.stacks);
    pb_opts.sample_cb = handle_event;
    pb_opts.lost_cb = handle_lost_events;
    pb_opts.ctx = &ctx;
    pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                          &pb_opts);
    err = libbpf_get_error(pb);
    if (err) {
        pb = NULL;
        fprintf(stderr, "failed to open perf buffer: %d\n", err);
        goto cleanup;
    }

    obj->links.end_point = prog_attach(obj->progs.end_point, env.etype, env.end_point, env.end_category);
    if (libbpf_get_error(obj->links.end_point)) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }
    obj->links.start_point = prog_attach(obj->progs.start_point, env.stype, env.start_point, env.start_category);
    if (libbpf_get_error(obj->links.start_point)) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    printf("Tracing soft irq event time... Hit Ctrl-C to end.\n");

    time(&t);
    print_time(t);
    while ((err = perf_buffer__poll(pb, 100)) >= 0) {
        time_t now;
        time(&now);
        if (now - t >= env.interval) {
            printf("\n");
            print_hist(obj->bss);

            t = now;
            env.times--;
            if (env.times == 0)
                break;

            print_time(t);
        }
        if (exiting)
            break;
    }

cleanup:
    f2flatency_bpf__destroy(obj);

    return err != 0;
}

