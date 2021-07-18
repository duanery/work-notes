// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Yongchao Duan
//
// 10-Dec-2020   Yongchao Duan   Created this.
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
#include <sched.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#include "skbsniffer.h"
#include "skbsniffer.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES       64
#define PERF_POLL_TIMEOUT_MS    100

struct env {
    bool verbose;
    int debug;
    uint32_t netns;
    int ipvx;  // ipv4 ipv6
    int proto; // tcp udp icmp
    int sport;
    int dport;
    int icmpid;
    bool sniff;
    bool disorder;
    bool loss;
    struct {
        int seq_offset;
        int seq_len;
        bool seq_big_endian;
    };
    int goon_second;
    int n_filters;
    struct {
        int offset; // bit offset
        int bits;
        unsigned long value;
    } filters[MAX_FILTERS];
    int statistics;
    double interval;
    int conntracks;
} env = {
    .verbose = 0,
    .debug = 0,
    .ipvx = 4,
    .proto = IPPROTO_IP,
    .sniff = false,
    .goon_second = 3,
    .n_filters = 0,
    .statistics = STATISTICS_DEFAULT,
    .conntracks = NUMBER_OF_CONNTRACK,
};

static volatile bool exiting;


const char *argp_program_version = "skbsniffer V0.1";
const char *argp_program_bug_address = "<yongduan@tencent.com>";
static char doc[] =
"skbsniffer -- sk_buff sniffer, detect network packet loss or disorder\n"
"\n"
"EXAMPLES:\n"
"    skbsniffer --proto udp                    # statistics ICMP traffic\n"
"    skbsniffer --proto icmp --icmpid 6109 -s  # sniff ICMP traffic, id 6109\n"
"    skbsniffer --proto icmp --icmpid 6109 --disorder 6:2.B  # Disorder \n"
"           detection ICMP traffic, sequence number 6:2, big endian\n"
"    skbsniffer --proto icmp --icmpid 6109 --disorder 6:2.B --loss  # Packet\n"
"           loss detection\n"
"    skbsniffer --proto udp  336:16:36975 --disorder 10:2.B --loss  # Loss \n"
"           and disorder detect, RTP type 111"
"\n"
"FILTER:\n"
"    Offset:Bits:Value\n"
"        Offset starts from the beginning of L2 header(MAC).\n"
"        Bits specifies the number of actual bits.\n"
"        Value needs to match, little endian.\n"
;

#define OPT_NETNS 500
#define OPT_PROTO 501
#define OPT_DISORDER  502
#define OPT_LOSS  503
#define OPT_ICMPID 504
#define OPT_GOON_SECOND 505
#define OPT_SPORT 506
#define OPT_DPORT 507


static const struct argp_option opts[] = {
    { "netns", OPT_NETNS, "NETNS", 0, "Filter net namespace" },
    { "ipv4", '4', NULL, 0, "Filter ipv4" },
    { "ipv6", '6', NULL, 0, "Filter ipv6" },
    { "proto", OPT_PROTO, "tcp|udp|icmp", 0, "Filter protocol" },
    { "sport", OPT_SPORT, "PORT", 0, "Filter source port" },
    { "dport", OPT_DPORT, "PORT", 0, "Filter destination port" },
    { "icmpid", OPT_ICMPID, "ID", 0, "Filter icmp echo id" },
    { "sniff", 's', NULL, 0, "Do sniffing" },
    { "disorder", OPT_DISORDER, "Offset:Len[.B]", 0, "Disorder detection, specify the sequence number offset and length. "
                                                     "Offset starts from the beginning of L4 header. "
                                                     "[.B] means big endian, otherwise little endian."},
    { "loss", OPT_LOSS, "Offset:Len[.B]", OPTION_ARG_OPTIONAL, "Packet loss detection" },
    { "goon-second", OPT_GOON_SECOND, "N", 0, "go on N second (dftl: 3)" },
    { "statistics", 'S', "S", 0, "Packets statistics (dftl: 1): 1:default, 2:queue, 3:sendfreq, 4:sendlength, 5:recvfreq, 6:burst" },
    { "interval", 'i', "I", 0, "Statistics display interval, min 0.001 second." },
    { "conntracks", 'c', "N", 0, "Number of connections tracked (dftl: 256)" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "debug", 'd', "LEVEL", 0, "Debug output, debug level: 1:err, 2:warn, 3:info" },
    { "", 'h', NULL, OPTION_HIDDEN, "" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
    case 'h':
        argp_help(state->root_argp, stderr, ARGP_HELP_STD_HELP, "skbsniffer");
        exit(0);
    case 'v':
		env.verbose = true;
		break;
    case 'd':
		env.debug = strtol(arg, NULL, 10);
		break;
    case OPT_NETNS:
        env.netns = strtol(arg, NULL, 10);
        break;
    case '4':
        env.ipvx = 4;
        break;
    case '6':
        env.ipvx = 6;
        break;
    case OPT_PROTO:
        if (strcmp(arg, "tcp") == 0)
            env.proto = IPPROTO_TCP;
        else if(strcmp(arg, "udp") == 0)
            env.proto = IPPROTO_UDP;
        else if(strcmp(arg, "icmp") == 0)
            env.proto = IPPROTO_ICMP;
        break;
    case OPT_SPORT:
        env.sport = strtol(arg, NULL, 10);
        break;
    case OPT_DPORT:
        env.dport = strtol(arg, NULL, 10);
        break;
    case OPT_ICMPID:
        env.icmpid = strtol(arg, NULL, 10);
        break;
    case 's':
        env.sniff = true;
        break;
    case OPT_DISORDER:
        env.disorder = true;
        goto offset;
    case OPT_LOSS:
        env.loss = true;
        if (!arg && !env.disorder)
            argp_usage(state);
    offset:
        if (arg) {
            char c = 0;
            if (sscanf(arg, "%d:%d.%c", &env.seq_offset, &env.seq_len, &c) == 3) {
                if (c == 'B') env.seq_big_endian = true;
                else argp_usage(state);
            } else if (sscanf(arg, "%d:%d", &env.seq_offset, &env.seq_len) == 2)
                env.seq_big_endian = false;
            else
                argp_usage(state);
        }
        break;
    case OPT_GOON_SECOND:
        env.goon_second = strtol(arg, NULL, 10);
        break;
    case 'S':
        env.statistics = strtol(arg, NULL, 10);
        if (env.statistics >= STATISTICS_MAX) {
            argp_help(state->root_argp, stderr, ARGP_HELP_STD_HELP, "skbsniffer");
            exit(0);
        }
        break;
    case 'i':
        env.interval = strtod(arg, NULL);
        if (env.interval < 0.001) {
            argp_help(state->root_argp, stderr, ARGP_HELP_STD_HELP, "skbsniffer");
            exit(0);
        }
        break;
    case 'c':
        env.conntracks = strtol(arg, NULL, 10);
        break;
    case ARGP_KEY_ARG:
        if (env.n_filters >= MAX_FILTERS ||
            (arg && sscanf(arg, "%d:%d:%lu", &env.filters[env.n_filters].offset, 
                        &env.filters[env.n_filters].bits, &env.filters[env.n_filters].value) != 3))
            argp_usage(state);
        env.n_filters++;
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

static char *kpoint_str(int kpoint)
{
    char *str = "";
    switch (kpoint) {
        case KPOINT_NETIF_RECEIVE_SKB_ENTRY:
            str = "netif_receive_skb_entry";
            break;
        case KPOINT_NAPI_GRO_RECEIVE_ENTRY:
            str = "napi_gro_receive_entry";
            break;
        case KPOINT_NETIF_RECEIVE_SKB:
            str = "netif_receive_skb";
            break;
        case KPOINT_NET_DEV_QUEUE:
            str = "net_dev_queue";
            break;
        case KPOINT_NET_DEV_XMIT:
            str = "net_dev_xmit";
            break;
    }
    return str;
}

static char *ipaddr_str(const struct skb_event *e, int a)
{
    static char sbuff[INET6_ADDRSTRLEN];
    static char dbuff[INET6_ADDRSTRLEN];
    static char *buff;
    int domain;
    if (e->base.version == 4) 
        domain = AF_INET;
    else if (e->base.version == 6)
        domain = AF_INET6;
    else
        return "";
    if (a == 0) {
        buff = sbuff;
        inet_ntop(domain, &e->base.saddr, buff, INET6_ADDRSTRLEN);
    } else {
        buff = dbuff;
        inet_ntop(domain, &e->base.daddr, buff, INET6_ADDRSTRLEN);
    }
    return buff;
}

static char *icmp_type_str(const struct skb_event *e)
{
    char *str = "";
    switch (e->base.type) {
        case ICMP_ECHO:
        case ICMPV6_ECHO_REQUEST:
            str = "echo request";
            break;
        case ICMP_ECHOREPLY:
        case ICMPV6_ECHO_REPLY:
            str = "echo reply";
            break;
    }
    return str;
}

static char *pkt_info(const struct skb_event *e, int *pwidth)
{
    static char buff[128];
    int len;
    switch (e->base.protocol) {
    case IPPROTO_ICMPV6:
    case IPPROTO_ICMP: {
            static int width = 0;
            len = snprintf(buff, sizeof(buff), "I:%s->%s [%u] %s id %u", ipaddr_str(e, 0), ipaddr_str(e, 1), e->ipid, icmp_type_str(e), e->base.id);
            if (len > width) width = len;
            if (pwidth) *pwidth = width;
        }
        break;
    case IPPROTO_TCP: {
            static int width = 0;
            len = snprintf(buff, sizeof(buff), "T:%s:%d->%s:%d [%u]", ipaddr_str(e, 0), e->base.sport, ipaddr_str(e, 1), e->base.dport, e->ipid);
            if (len > width) width = len;
            if (pwidth) *pwidth = width;
        }
        break;
    case IPPROTO_UDP: {
            static int width = 0;
            len = snprintf(buff, sizeof(buff), "U:%s:%d->%s:%d [%u]", ipaddr_str(e, 0), e->base.sport, ipaddr_str(e, 1), e->base.dport, e->ipid);
            if (len > width) width = len;
            if (pwidth) *pwidth = width;
        }
        break;
    default: {
            static int width = 0;
            len = snprintf(buff, sizeof(buff), "proto %d [%u]", e->base.protocol, e->ipid);
            if (len > width) width = len;
            if (pwidth) *pwidth = width;
        }
        break;
    }
    return buff;
}

static char *debug_str(int level)
{
    char *str = "";
    switch (level) {
        case DEBUG_INFO:
            str = "INFO";
            break;
        case DEBUG_WARN:
            str = "WARN";
            break;
        case DEBUG_ERR:
            str = "ERR";
            break;
    }
    return str;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    const struct skb_event *e = data;
    struct tm *tm;
    time_t t;
    char ts[32];
    int width = 0;
    char *info = NULL;
    
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    info = pkt_info(e, &width);
    printf("%-8s %-12u %-12s %-4u %20s %-*s  ", ts, e->base.netns, e->ifname, e->cpu, kpoint_str(e->base.kpoint), width, info);

    switch (e->type) {
    case SKB_EVENT_LOSS_DISORDER:
        switch (e->loss_disorder.state) {
            case LOSS_DISORDER_STATE_DEBUG:
                printf("[%s] number %lu count %lu", debug_str(e->loss_disorder.debug_level), e->loss_disorder.number, e->loss_disorder.count);
                break;
            case LOSS_DISORDER_STATE_RAISE:
                if (env.disorder || env.loss)
                    printf("number %lu count %lu", e->loss_disorder.number, e->loss_disorder.count);
                break;
            case LOSS_DISORDER_STATE_DISORDER:
                if (env.disorder)
                    printf("Out of order number %lu count %lu", e->loss_disorder.number, e->loss_disorder.count);
                break;
            case LOSS_DISORDER_STATE_LOSS:
                if (env.loss)
                    printf("Loss number %lu count %lu", e->loss_disorder.number, e->loss_disorder.count);
                break;
            case LOSS_DISORDER_STATE_QUEUE:
                printf("Q %d number %lu count %lu", e->loss_disorder.queue_mapping, e->loss_disorder.number, e->loss_disorder.count);
                break;
            default:
                break;
        }
        break;
    case SKB_EVENT_SNIFFED:
        printf("== skb %p", e->sniffed.skb);
        break;
    }
    printf("\n");
}


static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static int int_cmp(const void *p1, const void *p2)
{
    if (*(int *)p1 == *(int *)p2) return 0;
    return *(int *)p1 < *(int *)p2 ? -1 : 1;
}

static void print_statistics(struct bpf_map *map, bool delete)
{
    int fd = bpf_map__fd(map);
    int kpoint;
    int queue_mapping;
    static int nkey = 0;
    static int *keys = NULL;
    void *key = NULL;
    struct statistics stat;
    int err, i = 0, j = 0, n;
    struct tm *tm;
    time_t t;
    char ts[32];
    char buff[32];
    
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    while (!bpf_map_get_next_key(fd, key, &kpoint)) {
        if (nkey == i) {
            nkey += 32;
            keys = realloc(keys, nkey * sizeof(int));
            if (keys == NULL) {
                nkey = 0;
                return ;
            }
        }
        keys[i++] = kpoint;
        key = &kpoint;
    }
    qsort(keys, i, sizeof(int), int_cmp);

    for (j = 0; j < i; j++) {
        kpoint = keys[j];
        err = bpf_map_lookup_elem(fd, &kpoint, &stat);
        if (err < 0) {
            fprintf(stderr, "failed to lookup statistics: %d\n", err);
            return ;
        }
        n = snprintf(buff, sizeof(buff), "%s", kpoint_str((kpoint>>16)&0xffff));
        queue_mapping = kpoint & 0xffff;
        if (queue_mapping)
            snprintf(buff+n, sizeof(buff)-n, ":%02d", queue_mapping - 1);
        if (env.statistics == STATISTICS_BURST)
            printf("%-8s %-23s %-20u %lu\n", ts, buff, stat.burst_pkts, stat.burst_bytes);
        else
            printf("%-8s %-23s %-20lu %lu\n", ts, buff, stat.pkts, stat.bytes);
        key = &kpoint;
        if (delete)
            bpf_map_delete_elem(fd, key);
    }
}

static int print_log2_hists(struct bpf_map *hists, const char *units)
{
    int err, fd = bpf_map__fd(hists);
    __u16 lookup_key = -2, next_key;
    struct hist hist;
    char ts[32];
    time_t t;
    struct tm *tm;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    printf("\n%-8s", ts);

    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_lookup_elem(fd, &next_key, &hist);
        if (err < 0) {
            fprintf(stderr, "failed to lookup hist: %d\n", err);
            return -1;
        }
        printf("\nqueue = %d\n", next_key);
        print_log2_hist(hist.slots, MAX_SLOTS, units);
        lookup_key = next_key;
    }

    lookup_key = -2;
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_delete_elem(fd, &next_key);
        if (err < 0) {
            fprintf(stderr, "failed to cleanup hist : %d\n", err);
            return -1;
        }
        lookup_key = next_key;
    }
    return 0;
}


int main(int argc, char **argv)
{
    struct skbsniffer_bpf *obj = NULL;
    int err, n, i;
    struct perf_buffer_opts pb_opts;
    struct perf_buffer *pb = NULL;

    static char args_doc[64];
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
        .args_doc = args_doc,
		.doc = doc,
	};
    snprintf(args_doc, sizeof(args_doc), "[FILTER]{0-%d}", MAX_FILTERS);
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

    setvbuf(stdout, NULL, _IOLBF, 0);
    
    libbpf_set_print(libbpf_print_fn);
    
    err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

    obj = skbsniffer_bpf__open();
    if (!obj) {
    	fprintf(stderr, "failed to open and/or load BPF object\n");
    	return 1;
    }

    obj->rodata->ctrl_netns = env.netns;
    n = 0;
    obj->rodata->ctrl_filters[n].offset = sizeof(struct ethhdr) * 8 + 4;
    obj->rodata->ctrl_filters[n].bits = 4;
    obj->rodata->ctrl_filters[n].value = env.ipvx;
    n++;
    if (env.proto) {
        if (env.proto == IPPROTO_ICMP && env.ipvx == 6)
            env.proto = IPPROTO_ICMPV6;
        int proto = env.ipvx == 6 ? offsetof(struct ipv6hdr, nexthdr) : offsetof(struct iphdr, protocol);
        obj->rodata->ctrl_filters[n].offset = (sizeof(struct ethhdr) + proto) * 8;
        obj->rodata->ctrl_filters[n].bits = 8;
        obj->rodata->ctrl_filters[n].value = env.proto;
        n++;
    }
    if (env.sport || env.dport) {
        int iphdr_len = env.ipvx == 6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
        if (env.sport) {
            obj->rodata->ctrl_filters[n].offset = (sizeof(struct ethhdr) + iphdr_len + 0) * 8; //srcport
            obj->rodata->ctrl_filters[n].bits = 16;
            obj->rodata->ctrl_filters[n].value = env.sport;
            n++;
        }
        if (env.dport) {
            obj->rodata->ctrl_filters[n].offset = (sizeof(struct ethhdr) + iphdr_len + 2) * 8; //dstport
            obj->rodata->ctrl_filters[n].bits = 16;
            obj->rodata->ctrl_filters[n].value = env.dport;
            n++;
        }
    }else if (env.icmpid) {
        int iphdr_len = env.ipvx == 6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
        obj->rodata->ctrl_filters[n].offset = (sizeof(struct ethhdr) + iphdr_len + 4) * 8; //icmpid
        obj->rodata->ctrl_filters[n].bits = 16;
        obj->rodata->ctrl_filters[n].value = env.icmpid;
        n++;
    }
    for (i = 0; i < env.n_filters; i++) {
        if (n < MAX_FILTERS) {
            obj->rodata->ctrl_filters[n].offset = env.filters[i].offset;
            obj->rodata->ctrl_filters[n].bits = env.filters[i].bits;
            obj->rodata->ctrl_filters[n].value = env.filters[i].value;
            n++;
        } else 
            fprintf(stderr, "%d:%d:%lu not used\n", env.filters[i].offset, env.filters[i].bits, env.filters[i].value);
    }
    obj->rodata->ctrl_n_filters = n;

    // Detect skb loss or disorder
    if (env.disorder || env.loss) {
        obj->rodata->ctrl_seq_number.offset = env.seq_offset;
        obj->rodata->ctrl_seq_number.len = env.seq_len;
        obj->rodata->ctrl_seq_number.big_endian = env.seq_big_endian;
        obj->rodata->ctrl_seq_number.debug = env.debug;
        obj->rodata->ctrl_goon_second = env.goon_second;
    }
    obj->rodata->ctrl_do_sniffing = env.sniff;

    if (env.disorder || env.loss || env.sniff)
        env.statistics = 0;

    obj->rodata->ctrl_do_statistics = env.statistics;

    // set number of conntracks
    bpf_map__set_max_entries(obj->maps.track_loss_disorder, env.conntracks * KPOINT_MAX);

    err = skbsniffer_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

    if (env.statistics) {
        err = skbsniffer_bpf__attach(obj);
    	if (err) {
    		fprintf(stderr, "failed to attach BPF programs\n");
    		goto cleanup;
    	}

        printf("Tracing run skb sniffer ... Hit Ctrl-C to end.\n");

    	signal(SIGINT, sig_handler);

        switch (env.statistics) {
            case STATISTICS_DEFAULT:
            case STATISTICS_QUEUE:
                printf("%-8s %-23s %-20s %s\n", "TIME", "HOOK", "PKTS", "BYTES");
                break;
            case STATISTICS_BURST:
                printf("%-8s %-23s %-20s %s\n", "TIME", "HOOK", "BURST(pkts_per_ms)", "BURST(bytes_per_ms)");
                break;
        }

        if (!env.interval)
            env.interval = 99999999;
        while (!exiting) {
            u64 s_interval = env.interval;
            u64 us_interval = env.interval * 1000000UL;
            us_interval = us_interval % 1000000UL;
            if (s_interval) sleep(s_interval);
            if (us_interval) usleep(us_interval);
            switch (env.statistics) {
                case STATISTICS_DEFAULT:
                    print_statistics(obj->maps.track_statistics, true);
                    break;
                case STATISTICS_QUEUE:
                    print_statistics(obj->maps.track_statistics, true);
                    break;
                case STATISTICS_SEND_FREQ:
                    print_log2_hists(obj->maps.hists, "usec");
                    break;
                case STATISTICS_SEND_LENGTH:
                    print_log2_hists(obj->maps.hists, "length");
                    break;
                case STATISTICS_RECV_FREQ:
                    print_log2_hists(obj->maps.hists, "usec");
                    break;
                case STATISTICS_BURST:
                    print_statistics(obj->maps.track_statistics, true);
                    break;
            }
        }
    } else {
        pb_opts.sample_cb = handle_event;
        pb_opts.lost_cb = handle_lost_events;
        pb_opts.ctx = NULL;
        pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                              &pb_opts);
        err = libbpf_get_error(pb);
        if (err) {
                pb = NULL;
                fprintf(stderr, "failed to open perf buffer: %d\n", err);
                goto cleanup;
        }

    	err = skbsniffer_bpf__attach(obj);
    	if (err) {
    		fprintf(stderr, "failed to attach BPF programs\n");
    		goto cleanup;
    	}

        printf("Tracing run skb sniffer ... Hit Ctrl-C to end.\n");

    	signal(SIGINT, sig_handler);

        printf("%-8s %-12s %-12s %-4s %20s %-46s %s\n", "TIME", "NETNS", "INTERFACE", "CPU", "HOOK", "PKT_INFO[TUI]:IP[:PORT]->IP[:PORT][IPID]", "SNIFFER_INFO");

        while ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) >= 0)
            if (exiting) break;
        if (!exiting)
            fprintf(stderr, "error polling perf buffer: %d\n", err);
    }
cleanup:
    if (pb)
        perf_buffer__free(pb);
    skbsniffer_bpf__destroy(obj);
    
	return err != 0;
}


/*
1. 粗细粒度流识别.
3. 内核监控点.
2. 识别到流之后
2.1 流级别的流统
2.2 流级别的流量监控, 秒级
2.3 流级别丢包乱序检测.
2.4 流级别日志输出
2.5 流级别

*/

