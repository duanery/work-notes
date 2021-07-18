// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Yongchao Duan
//
// Based on runqlat(8) from BCC by Bredan Gregg.
// 10-Aug-2020   Wenbo Zhang   Created this.
//
#define _GNU_SOURCE
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <sched.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#include "rundelay.h"
#include "rundelay.skel.h"
#include "rundelay_cpu.skel.h"
#include "trace_helpers.h"



struct env {
    bool verbose;
	pid_t pid;
    int latency;
    int tid;
    int frequency;
    bool callgraph;
    bool resched_curr;
} env = {
	.frequency = 0,
    .callgraph = 0,
};

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100


static volatile bool exiting;

const char *argp_program_version = "rundelay 0.1";
const char *argp_program_bug_address = "<yongduan@tencent.com>";
static char argp_program_args_doc[] = "LATENCY(ns)";

const char argp_program_doc[] =
"rundelay -- sampling and analysis of scheduler delay.\n"
"\n"
"EXAMPLES:\n"
"    rundelay 1000000            # analysis run delay > 1000000 ns\n"
"    rundelay 5000000 -F 997 -g  # sampling run delay stack, frequency 997\n"
"    rundelay 5000000 -P 185 -F 997 -g  # analysis PID 185 only\n"
;


static const struct argp_option opts[] = {
	{ "pid", 'P', "PID", 0, "Trace this PID only" },
    { "tid", 'T', "TID", 0, "trace this tid only"},
    { "freq", 'F', "FREQ", 0, "do sample and set sample frequency"},
    { "callgraph", 'g', NULL, 0, "enables call-graph recording"},
    { "resched", 'r', NULL, 0, "enables resched_curr recording"},
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "", 'h', NULL, OPTION_HIDDEN, "" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
    case 'h':
        argp_help(state->root_argp, stderr, ARGP_HELP_STD_HELP, "rundelay");
        exit(0);
	case 'v':
		env.verbose = true;
		break;
	case 'P':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
    case 'T':
        errno = 0;
		env.tid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid tid: %s\n", arg);
			argp_usage(state);
		}
		break;
    case 'F':
        errno = 0;
		env.frequency = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid tid: %s\n", arg);
			argp_usage(state);
		}
		break;
    case 'g':
		env.callgraph = true;
		break;
    case 'r':
		env.resched_curr = true;
		break;
    case ARGP_KEY_ARG:
        switch (state->arg_num) {
            case 0:
                env.latency = strtol(arg, NULL, 10);
                break;
            default:
                argp_usage (state);
        };
        break;
    case ARGP_KEY_END:
        if (state->arg_num < 1)
            argp_usage (state);
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

static pid_t gettid(void)
{
   return syscall(SYS_gettid);
}


static const char *keypoint_type(int type)
{
    const char *str = "none";
    switch (type) {
        case KEYPOINT_PERF_SAMPLE:
            str = "perf_event";
            break;
        case KEYPOINT_RESCHED_CURR:
            str = "kprobe/resched_curr";
            break;
        case KEYPOINT_MIGRATE_TASK:
            str = "raw_tp/sched_migrate_task";
            break;
        case KEYPOINT_SCHED_SWITCH:
            str = "raw_tp/sched_switch";
            break;
        case KEYPOINT_DEBUG:
            str = "debug";
            break;
    }
    return str;
}
static const char *action_str(int act)
{
    const char *str = "none";
    switch (act) {
        case ACTION_CLEANUP:
            str = "CLEANUP";
            break;
        case ACTION_DROP_STACKID:
            str = "DROP";
            break;
        case ACTION_WAKEUP:
            str = "WAKEUP";
            break;
        case ACTION_RUN:
            str = "RUN";
            break;
    }
    return str;
}

static const char *state_str(uint32_t state)
{
    const char *str = "";
    switch (state) {
        case 0x00: str = "R"; break;
        case 0x01: str = "S"; break;
        case 0x02: str = "D"; break;
        case 0x04: str = "T"; break;
        case 0x08: str = "t"; break;
        case 0x10: str = "X"; break;
        case 0x20: str = "Z"; break;
        case 0x40: str = "P"; break;
        case 0x80: str = "I"; break;
    }
    return str;
}

static const char *debug_str(int debugid)
{
    const char *str = "";
    switch (debugid) {
        case __DEBUG_ENQUEUE       : str = "trace_enqueue"; break;
        case __DEBUG_PERF_SAMPLE   : str = "record_perf_sample"; break;
        case __DEBUG_RESCHED_CURR  : str = "record_resched_curr"; break;
        case __DEBUG_ACTION_CLEANUP: str = "record_action_cleanup"; break;
        case __DEBUG_ACTION_DROP   : str = "record_action_drop"; break;
        case __DEBUG_ACTION_RUN    : str = "record_action_run"; break;
        case __DEBUG_ACTION_WAKEUP : str = "record_action_wakeup"; break;
        case __DEBUG_SCHED_SWITCH  : str = "record_sched_switch"; break;
    }
    return str;
}

struct event_ctx {
    int map_fd;
    struct ksyms *ksyms;
};

static void print_stack(struct event_ctx *ctx, u32 key)
{
    u64 stack[STACK_DEPTH];
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
    const struct thread_record *r = data;
    struct tm *tm;
    char ts[32], start[32], now[32];
    time_t t;
    int i;
    u32 key;
    const struct keypoint *kp;

    if (data_sz < offsetof(struct thread_record, keypoint) + r->next * sizeof(struct keypoint)) {
        fprintf(stderr, "error =2=\n");
        return;
    }
    if (env.verbose ||
        r->action != ACTION_DROP_STACKID)
    {
        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        snprintf(start, sizeof(start), "%lu.%09lu", r->ts/1000000000UL, r->ts%1000000000UL);
        snprintf(now, sizeof(now), "%lu.%09lu", r->now/1000000000UL, r->now%1000000000UL);
        printf("%-8s %-16s %-6u %-4u %-7u %s - %s = %lu %s\n",
               ts, r->comm, r->pid, r->cpu, r->next, start, now, r->now - r->ts, action_str(r->action));
    }
    switch (r->action) {
    case ACTION_CLEANUP:
    case ACTION_DROP_STACKID:
        if (!env.verbose) {
            for (i = 0; i < r->next; i++) {
                kp = &r->keypoint[i];
                key = STACKID_NONE;
                switch (kp->type) {
                    case KEYPOINT_PERF_SAMPLE:
                        key = kp->perf.stackid;
                        break;
                    case KEYPOINT_RESCHED_CURR:
                        key = kp->resched_curr.stackid;
                        break;
                    case KEYPOINT_MIGRATE_TASK:
                        key = kp->migrate_task.stackid;
                    default:
                        continue;
                }
                if (key != STACKID_NONE) {
                    bpf_map_delete_elem(ctx->map_fd, &key);
                }
            }
            break;
        }
    case ACTION_WAKEUP:
    case ACTION_RUN:
        for (i = 0; i < r->next; i++) {
            kp = &r->keypoint[i];
            printf(" %2d [%03u] %lu.%09lu: %s: ", i, kp->cpu, kp->ts/1000000000UL, kp->ts%1000000000UL, keypoint_type(kp->type));
            switch (kp->type) {
                case KEYPOINT_PERF_SAMPLE:
                    printf("stackid %-4u %s:%u\n", kp->perf.stackid, kp->perf.comm, kp->perf.pid);
                    print_stack(ctx, kp->perf.stackid);
                    break;
                case KEYPOINT_RESCHED_CURR:
                    printf("stackid %-4u => [%03u] %s:%u\n", kp->resched_curr.stackid, kp->resched_curr.targ_cpu, "", kp->resched_curr.pid);
                    print_stack(ctx, kp->resched_curr.stackid);
                    break;
                case KEYPOINT_MIGRATE_TASK:
                    printf("[%03u] => [%03u]\n", kp->migrate_task.old_cpu, kp->migrate_task.new_cpu);
                    print_stack(ctx, kp->migrate_task.stackid);
                    break;
                case KEYPOINT_SCHED_SWITCH:
                    printf("%s:%u [%u] %s => %s:%u [%u]\n", kp->sched_switch.prev_comm, kp->sched_switch.prev_pid, kp->sched_switch.prev_prio,
                            state_str(kp->sched_switch.prev_state),
                            kp->sched_switch.next_comm, kp->sched_switch.next_pid, kp->sched_switch.next_prio);
                    break;
                case KEYPOINT_DEBUG:
                    printf("debug in %s\n", debug_str(kp->debug.debugid));
                    print_stack(ctx, kp->debug.stackid);
                    break;
            }
        }
        break;
    default:
        break;
    }
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

unsigned int get_possible_cpus(void)
{
	int cpus = libbpf_num_possible_cpus();

	if (cpus < 0) {
		fprintf(stderr, "Can't get # of possible cpus: %s", strerror(-cpus));
		exit(-1);
	}
	return cpus;
}

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
                                struct bpf_link ***plinks)
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .freq = 1,
        .sample_period = freq,
        .config = PERF_COUNT_SW_CPU_CLOCK,
    };
    int i, fd, nr_cpus;
    struct bpf_link **links;

    nr_cpus = get_possible_cpus();
    links = calloc(nr_cpus, sizeof(struct bpf_link *));
    if (!links) {
        fprintf(stderr, "failed to alloc links\n");
        return 0;
    }
    for (i = 0; i < nr_cpus; i++) {
        fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
        if (fd < 0) {
            fprintf(stderr, "failed to init perf sampling: %s\n",
                    strerror(errno));
            return -1;
        }
        links[i] = bpf_program__attach_perf_event(prog, fd);
        if (libbpf_get_error(links[i])) {
            fprintf(stderr, "failed to attach perf event on cpu: "
                    "%d\n", i);
            links[i] = NULL;
            close(fd);
            return -1;
        }
    }
    if (plinks)
        *plinks = links;
    return 0;
}

struct sleepinfo {
    uint32_t cpu;
    uint64_t *tid;
    uint32_t *nr;
};

void *sleep1ms(void *arg)
{
    struct sleepinfo *slp = arg;
    cpu_set_t mask;
    uint32_t us = 10000;
    //struct sched_param param;
    //int maxpri;

    CPU_ZERO(&mask);
    CPU_SET(slp->cpu, &mask);

    if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        printf("warning: could not set CPU affinity, continuing...\n");
    }
    if (nice(-19) == -1) {
        printf("warning: could not set nice -19, continuing...\n");
    }
    /*
    maxpri = sched_get_priority_max(SCHED_FIFO);
    if(maxpri == -1) {
        perror("sched_get_priority_max() failed");
    }
    param.sched_priority = maxpri;
    if (sched_setscheduler(getpid(), SCHED_FIFO, &param) == -1)
    {
        perror("sched_setscheduler() failed");
    }*/

    *slp->tid = gettid();
    __sync_fetch_and_add(slp->nr, 1);

    if (env.frequency)
        us = 1000000 * 2 / env.frequency;
    while (!exiting)
        usleep(us);

    return NULL;
}


int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = argp_program_args_doc,
		.doc = argp_program_doc,
	};
	struct rundelay_bpf *obj = NULL;
    struct rundelay_cpu_bpf *objc = NULL;
    struct bpf_link **links = NULL;
    int nr_cpus = get_possible_cpus();
    struct event_ctx ctx = {};
    int i;
	int err;
    pthread_t id;
    uint64_t *tids;
    struct sleepinfo *slps;
    uint32_t nr_ready = 0, key = 0;
    struct perf_buffer_opts pb_opts;
    struct perf_buffer *pb = NULL;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

    if (!env.latency) {
		fprintf(stderr, "need latency\n");
		return 1;
	}

    ctx.ksyms = ksyms__load();
    pb_opts.sample_cb = handle_event;
    pb_opts.lost_cb = handle_lost_events;
    pb_opts.ctx = &ctx;

    if (!env.pid) {
        objc = rundelay_cpu_bpf__open();
        if (!objc) {
    		fprintf(stderr, "failed to open and/or load BPF object\n");
    		return 1;
    	}

        objc->rodata->targ_latency = env.latency;
        objc->rodata->ctrl_do_sample = env.frequency > 0;
        objc->rodata->ctrl_sample_accuracy = env.frequency > 0 ? 1000000000UL / env.frequency / 2 : 0;
        objc->rodata->ctrl_do_callchain = env.callgraph;
        objc->rodata->ctrl_do_resched_curr = env.resched_curr;
        memset(objc->bss->threads, 0, sizeof(objc->bss->threads));

        err = rundelay_cpu_bpf__load(objc);
    	if (err) {
    		fprintf(stderr, "failed to load BPF object: %d\n", err);
    		goto cleanup;
    	}

        tids = calloc(nr_cpus, sizeof(*tids));
        slps = calloc(nr_cpus, sizeof(*slps));
        for (i = 0; i < nr_cpus; i++, slps++) {
            slps->cpu = i;
            slps->tid = tids + i;
            slps->nr = &nr_ready;
            err = pthread_create(&id, NULL, sleep1ms, slps);
            if(err) {
                fprintf(stderr, "create thread failed\n");
                return 1;
            }
        }
        while (nr_ready != nr_cpus)
            usleep(1000);

        key = 0;
        err = bpf_map_update_elem(bpf_map__fd(objc->maps.percpu_thread), &key, tids, 0);
        if (err < 0) {
            fprintf(stderr, "failed to update percpu_thread %d\n", errno);
    		goto cleanup;
        }

        ctx.map_fd = bpf_map__fd(objc->maps.stacks);
        pb = perf_buffer__new(bpf_map__fd(objc->maps.events), PERF_BUFFER_PAGES,
                              &pb_opts);
        err = libbpf_get_error(pb);
        if (err) {
                pb = NULL;
                fprintf(stderr, "failed to open perf buffer: %d\n", err);
                goto cleanup;
        }

        err = rundelay_cpu_bpf__attach(objc);
    	if (err) {
    		fprintf(stderr, "failed to attach BPF programs\n");
    		goto cleanup;
    	}

        if (env.frequency) {
            if (open_and_attach_perf_event(env.frequency, objc->progs.do_sample, &links))
                goto cleanup;
        }
    } else {
        obj = rundelay_bpf__open();
        if (!obj) {
    		fprintf(stderr, "failed to open and/or load BPF object\n");
    		return 1;
    	}

        obj->rodata->targ_tgid = env.pid;
        obj->rodata->targ_latency = env.latency;
        obj->rodata->targ_pid = env.tid;
        obj->rodata->ctrl_do_sample = env.frequency > 0;
        obj->rodata->ctrl_sample_accuracy = env.frequency > 0 ? 1000000000UL / env.frequency / 2 : 0;
        obj->rodata->ctrl_do_callchain = env.callgraph;
        obj->rodata->ctrl_do_resched_curr = env.resched_curr;

        err = rundelay_bpf__load(obj);
    	if (err) {
    		fprintf(stderr, "failed to load BPF object: %d\n", err);
    		goto cleanup;
    	}

        ctx.map_fd = bpf_map__fd(obj->maps.stacks);
        pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                              &pb_opts);
        err = libbpf_get_error(pb);
        if (err) {
                pb = NULL;
                fprintf(stderr, "failed to open perf buffer: %d\n", err);
                goto cleanup;
        }

    	err = rundelay_bpf__attach(obj);
    	if (err) {
    		fprintf(stderr, "failed to attach BPF programs\n");
    		goto cleanup;
    	}

        if (env.frequency) {
            if (open_and_attach_perf_event(env.frequency, obj->progs.do_sample, &links))
                goto cleanup;
        }
    }

	printf("Tracing run queue latency... Hit Ctrl-C to end.\n");

	signal(SIGINT, sig_handler);

    printf("%-8s %-16s %-6s %-4s %-7s %s\n", "TIME", "COMM", "TID", "CPU", "EVENTS", "START(ns) - NOW(ns) = DELTA(ns)");

    while ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) >= 0)
        if (exiting) break;
    if (!exiting)
        fprintf(stderr, "error polling perf buffer: %d\n", err);

cleanup:
    if (pb)
        perf_buffer__free(pb);
    if (ctx.ksyms)
        ksyms__free(ctx.ksyms);
    if (links) {
        for (i = 0; i < nr_cpus; i++)
            bpf_link__destroy(links[i]);
        free(links);
    }

    if (!env.pid) {
        rundelay_cpu_bpf__destroy(objc);
    } else {
        rundelay_bpf__destroy(obj);
    }
	return err != 0;
}


/*
TODO:
1. stacks 真正采样了栈才需要传递, 其他情况不需要传递,避免传递大量数据,性能损耗.
  1) 需要考虑未开启-g参数
  2) 考虑加入采样其他事件可能性. vruntime等.
完成
2. ctrl+c 退出后,统计Delay延迟分布信息.
3. 只监控特定CPU.

**/

