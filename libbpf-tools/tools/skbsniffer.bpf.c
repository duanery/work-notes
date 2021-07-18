// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 yongchao duan
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "skbsniffer.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define DEBUG

#define NULL 0
#define MAC_HEADER_SIZE 14

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_ECHO		8	/* Echo Request			*/

#define IPPROTO_ICMPV6		58	/* ICMPv6			*/
#define ICMPV6_ECHO_REQUEST		128
#define ICMPV6_ECHO_REPLY		129


// Control feature enable and disable
const volatile unsigned int ctrl_netns = 0;
const volatile unsigned int ctrl_n_filters = 0;
//#define MAX_FILTERS 5  //ipv4/6 proto port payload
                       //ipv4   udp   6000 5
const volatile struct {
    int offset; // bit offset
    int bits;
    unsigned long value;
} ctrl_filters[MAX_FILTERS];
union u8_64{
    u8 u8;
    u16 u16;
    u32 u32;
    u64 u64;
};
const volatile struct {
    int offset;
    int len;
    bool big_endian; //false: little endian, true: big endian
    int debug;
} ctrl_seq_number;
const volatile unsigned int ctrl_goon_second = 0;
const volatile unsigned int ctrl_jitter = 0;
const volatile bool ctrl_dup_detect = 0;
const volatile bool ctrl_do_sniffing = 0;
const volatile int  ctrl_do_statistics = 0;

__kconfig extern bool CONFIG_NET_NS;


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NUMBER_OF_CONNTRACK * KPOINT_MAX);
	__type(key, struct skb_base);
	__type(value, struct loss_disorder);
} track_loss_disorder SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries,   KPOINT_MAX * NUMBER_OF_QUEUES);
	__type(key, int);
	__type(value, struct statistics);
} track_statistics SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct skb_event);
} skb_events SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Packet frequency analysis. on SEC("raw_tp/net_dev_xmit")
// queue_mapping -> hist
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, NUMBER_OF_QUEUES);
        __type(key, u16);
        __type(value, struct hist);
} hists SEC(".maps");


static __always_inline
void skb_event_init(struct sk_buff *skb, struct skb_event *e, int kpoint)
{
    e->base.kpoint = kpoint;
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (dev) {
        bpf_probe_read_kernel_str(&e->ifname, sizeof(e->ifname), BPF_CORE_READ(dev, name));
    } else
        e->ifname[0] = 0;
    e->timestamp = bpf_ktime_get_ns();
    e->cpu = bpf_get_smp_processor_id();
}


static __always_inline
int do_filter(struct sk_buff *skb, struct skb_event *e)
{
    if (CONFIG_NET_NS) {
        struct net_device *dev = BPF_CORE_READ(skb, dev);
        if (dev)
            e->base.netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);

        // maybe the skb->dev is not init, for this situation, we can get ns by sk->__sk_common.skc_net.net->ns.inum
        if (e->base.netns == 0) {            
            struct sock *sk = BPF_CORE_READ(skb, sk);
            if (sk != NULL)
                e->base.netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
        }
        if (ctrl_netns && ctrl_netns != e->base.netns)
            return -1;
    }

    unsigned char *head = BPF_CORE_READ(skb, head);
    u16 mac_header = BPF_CORE_READ(skb, mac_header);
    unsigned char *l2_header_address = head + mac_header;
    
    #pragma unroll
	for (int i = 0; i < MAX_FILTERS && i < ctrl_n_filters; i++) {
        union u8_64 data = {.u64 = 0};
        u32 bit_offset = ctrl_filters[i].offset;
        u32 bits = ctrl_filters[i].bits;
        u32 offset = bit_offset / 8;
        u32 shift = bit_offset % 8;
        u32 len = (bits + 7) / 8;
        switch (len) {
            case 1:
                bpf_probe_read(&data.u8, 1, l2_header_address + offset);
                break;
            case 2:
                bpf_probe_read(&data.u16, 2, l2_header_address + offset);
                data.u16 = bpf_ntohs(data.u16);
                break;
            case 4:
                bpf_probe_read(&data.u32, 4, l2_header_address + offset);
                data.u32 = bpf_ntohl(data.u32);
                break;
            case 8:
                bpf_probe_read(&data.u64, 8, l2_header_address + offset);
                data.u64 = bpf_be64_to_cpu(data.u64);
                break;
            default:
                return -1;
        }
        if (((data.u64 >> shift) & ((1 << bits) - 1)) != ctrl_filters[i].value)
            return -1;
    }

    if (ctrl_do_statistics)
        return 0;
    
    u16 network_header = BPF_CORE_READ(skb, network_header);
    u8 *l3_header_address;
    u8 *l4_header_address;
    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;
    
    if(network_header == 0) {
        network_header = mac_header + MAC_HEADER_SIZE;
    }
    l3_header_address = head + network_header;
    
    bpf_probe_read(&e->base.version, sizeof(u8), l3_header_address);
    e->base.version = e->base.version >> 4 & 0xf;
    if (e->base.version == 4) {
        struct iphdr iphdr;
        bpf_probe_read(&iphdr, sizeof(iphdr), l3_header_address);

        e->base.protocol = iphdr.protocol;
        e->base.saddr = iphdr.saddr;
        e->base.daddr = iphdr.daddr;
        e->ipid = bpf_ntohs(iphdr.id);

        if (e->base.protocol == IPPROTO_ICMP) {
            proto_icmp_echo_request = ICMP_ECHO;
            proto_icmp_echo_reply   = ICMP_ECHOREPLY;
        }

        l4_header_address = l3_header_address + iphdr.ihl * 4;
    } else if (e->base.version == 6) {
        struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)l3_header_address;

        bpf_probe_read(&e->base.protocol,  sizeof(ipv6hdr->nexthdr),  (char*)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
        bpf_probe_read(&e->base.saddr6, sizeof(ipv6hdr->saddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(&e->base.daddr6, sizeof(ipv6hdr->daddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, daddr));

        if (e->base.protocol == IPPROTO_ICMPV6) {
            proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
            proto_icmp_echo_reply   = ICMPV6_ECHO_REPLY;
        }

        l4_header_address = l3_header_address + sizeof(*ipv6hdr);
    } else 
        return -1;

    union {
        struct icmphdr icmphdr;
        union tcp_word_hdr tcphdr;
        struct udphdr udphdr;
    } un;
    switch (e->base.protocol) {
    case IPPROTO_ICMPV6:
    case IPPROTO_ICMP:
        bpf_probe_read(&un.icmphdr, sizeof(un.icmphdr), l4_header_address);
        if (un.icmphdr.type != proto_icmp_echo_request && un.icmphdr.type != proto_icmp_echo_reply) {
            return -1;
        }
        e->base.type = un.icmphdr.type;
        e->base.code = un.icmphdr.code;
        e->base.id   = bpf_ntohs(un.icmphdr.un.echo.id);
        e->sniffed.icmpseq  = bpf_ntohs(un.icmphdr.un.echo.sequence);
        break;
    case IPPROTO_TCP:
        bpf_probe_read(&un.tcphdr, sizeof(un.tcphdr), l4_header_address);
        e->base.sport = bpf_ntohs(un.tcphdr.hdr.source);
        e->base.dport = bpf_ntohs(un.tcphdr.hdr.dest);
        break;
    case IPPROTO_UDP:
        bpf_probe_read(&un.udphdr, sizeof(un.udphdr), l4_header_address);
        e->base.sport = bpf_ntohs(un.udphdr.source);
        e->base.dport = bpf_ntohs(un.udphdr.dest);
        break;
    default:
        return -1;
    }
    e->l4_header_address = l4_header_address;
    return 0;
}

static __always_inline
int detect_loss_disorder(void *ctx, struct sk_buff *skb, struct skb_event *e)
{
    struct loss_disorder zero;
    __builtin_memset(&zero, 0, sizeof(zero));
    struct loss_disorder *info = bpf_map_lookup_or_try_init(&track_loss_disorder, &e->base, &zero);
    if (!info) return -1;
    union u8_64 data = {.u64 = 0};
    unsigned long number;
    u16 queue_mapping;
    int offset = ctrl_seq_number.offset;
    u8 shift = ctrl_seq_number.len * 8;
    u64 now = bpf_ktime_get_ns();
    u64 mask = shift == 64 ? 0xffffffffffffffff : (1UL << shift) - 1;
    
    switch (ctrl_seq_number.len) {
    case 1:
        bpf_probe_read(&data.u8, 1, e->l4_header_address + offset);
        break;
    case 2:
        bpf_probe_read(&data.u16, 2, e->l4_header_address + offset);
        if (ctrl_seq_number.big_endian)
            data.u16 = bpf_ntohs(data.u16);
        break;
    case 4:
        bpf_probe_read(&data.u32, 4, e->l4_header_address + offset);
        if (ctrl_seq_number.big_endian)
            data.u32 = bpf_ntohl(data.u32);
        break;
    case 8:
        bpf_probe_read(&data.u64, 8, e->l4_header_address + offset);
        if (ctrl_seq_number.big_endian)
            data.u64 = bpf_be64_to_cpu(data.u64);
        break;
    default:
        return -1;
    }
    number = data.u64;
    if (number != info->count && 
        (info->ts == 0 || 
         ctrl_goon_second && now - info->ts >= ctrl_goon_second * 1000000000UL)) {
            info->count = number;
            info->problem = 0;
            info->goon = 0;
        }
    if (ctrl_seq_number.debug == DEBUG_INFO) {
        e->type = SKB_EVENT_LOSS_DISORDER;
        e->loss_disorder.state = LOSS_DISORDER_STATE_DEBUG;
        e->loss_disorder.number = number;
        e->loss_disorder.count = info->count;
        e->loss_disorder.debug_level = DEBUG_INFO;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    }
    info->ts = now;
    info->number = number;
    if (info->number != info->count) info->problem++;
    
    if (e->base.kpoint == KPOINT_NET_DEV_QUEUE && ctrl_seq_number.debug == DEBUG_WARN) {
        queue_mapping = BPF_CORE_READ(skb, queue_mapping);
        if (queue_mapping != info->queue_mapping) {
            info->queue_mapping = queue_mapping;

            e->type = SKB_EVENT_LOSS_DISORDER;
            e->loss_disorder.state = LOSS_DISORDER_STATE_QUEUE;
            e->loss_disorder.number = info->number;
            e->loss_disorder.count = info->count;
            e->loss_disorder.queue_mapping = queue_mapping;
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        }
    }
    
    if (info->problem) {
        long ee;
        if (info->goon == 0) {
            info->sum = 0;
            info->problem_ts = now;

            e->type = SKB_EVENT_LOSS_DISORDER;
            e->loss_disorder.state = LOSS_DISORDER_STATE_RAISE;
            e->loss_disorder.number = info->number;
            e->loss_disorder.count = info->count;
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        } else if (ctrl_seq_number.debug == DEBUG_WARN) {
            e->type = SKB_EVENT_LOSS_DISORDER;
            e->loss_disorder.state = LOSS_DISORDER_STATE_DEBUG;
            e->loss_disorder.number = number;
            e->loss_disorder.count = info->count;
            e->loss_disorder.debug_level = DEBUG_WARN;
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        }

        /* Out of order recovery
         * 7 8 10 9 11, 7 8 9 10 11, the sum is equal
         * 1) sequence number overflow
         *    253 255 0 254 1 => 253 255 256 254 257
         *    number += 1UL << shift;
        **/
        if (info->number < info->count) 
            info->number += shift == 64 ? 0 : 1UL << shift;
        ee = info->number - info->count + 1;
        if (ee > 0) info->sum += ee;
        if ((ee+1)*ee/2 == info->sum) {
            e->type = SKB_EVENT_LOSS_DISORDER;
            e->loss_disorder.state = LOSS_DISORDER_STATE_DISORDER;
            e->loss_disorder.number = number;
            e->loss_disorder.count = info->count;
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
            
            info->count = (info->number + 1) & mask;
            info->problem = 0;
            info->goon = 0;
            return 0;
        }
        
        ++info->goon;
        
        /* Packet loss
         * 1) sequence number overflow
         * 2) `ctrl_goon_second' seconds passed
        **/
        if (number == ((info->count - 1) & mask) || 
            ctrl_goon_second && now - info->problem_ts >= ctrl_goon_second * 1000000000UL) {
            e->type = SKB_EVENT_LOSS_DISORDER;
            e->loss_disorder.state = LOSS_DISORDER_STATE_LOSS;
            e->loss_disorder.number = number;
            e->loss_disorder.count = info->count;
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));

            bpf_map_delete_elem(&track_loss_disorder, &e->base);
        }
    } else {
        ++info->count;
        info->count &= mask;
    }
    return 0;
}


static __always_inline
void do_sniffing(void *ctx, struct sk_buff *skb, struct skb_event *e)
{
    e->type = SKB_EVENT_SNIFFED;
    e->sniffed.skb = skb;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
}

static __always_inline
void do_statistics(void *ctx, struct sk_buff *skb, int kpoint, int len)
{
    int key = kpoint << 16;
    u16 queue_mapping;
    union {
        struct statistics s;
        struct hist h;
    } zero;
    struct statistics *stat;
    struct hist *hist;
    u64 ts;
    s64 delta;
    u64 slot;

    __builtin_memset(&zero, 0, sizeof(zero));
    if(!len) len = BPF_CORE_READ(skb, len);
    queue_mapping = BPF_CORE_READ(skb, queue_mapping);

    switch (ctrl_do_statistics) {
        case STATISTICS_DEFAULT:
            stat = bpf_map_lookup_or_try_init(&track_statistics, &key, &zero);
            if (stat) {
                __sync_fetch_and_add(&stat->pkts, 1);
                __sync_fetch_and_add(&stat->bytes, len);
            }
            break;
        case STATISTICS_QUEUE:
            if (kpoint == KPOINT_NET_DEV_XMIT) {
                key += queue_mapping + 1;
                stat = bpf_map_lookup_or_try_init(&track_statistics, &key, &zero);
                if (stat) {
                    __sync_fetch_and_add(&stat->pkts, 1);
                    __sync_fetch_and_add(&stat->bytes, len);
                }
            }
            break;
        case STATISTICS_SEND_FREQ:
            if (kpoint == KPOINT_NET_DEV_XMIT) {
                hist = bpf_map_lookup_or_try_init(&hists, &queue_mapping, &zero);
                if (hist) {
                    ts = bpf_ktime_get_ns();
                    if (hist->ts == 0)
                        goto end;
                    delta = ts - hist->ts;
                    if (delta < 0)
                        goto end;
                    delta /= 1000U;
                    slot = log2l(delta);
                    if (slot >= MAX_SLOTS)
                        slot = MAX_SLOTS - 1;
                    __sync_fetch_and_add(&hist->slots[slot], 1);
                end:
                    hist->ts = ts;
                }
            }
            break;
        case STATISTICS_SEND_LENGTH:
            if (kpoint == KPOINT_NET_DEV_XMIT) {
                hist = bpf_map_lookup_or_try_init(&hists, &queue_mapping, &zero);
                if (hist) {
                    slot = log2l(len);
                    if (slot >= MAX_SLOTS)
                        slot = MAX_SLOTS - 1;
                    __sync_fetch_and_add(&hist->slots[slot], 1);
                }
            }
            break;
        case STATISTICS_RECV_FREQ:
            if (kpoint == KPOINT_NAPI_GRO_RECEIVE_ENTRY) {
                u16 cpu = bpf_get_smp_processor_id();
                hist = bpf_map_lookup_or_try_init(&hists, &cpu, &zero);
                if (hist) {
                    ts = bpf_ktime_get_ns();
                    if (hist->ts == 0)
                        goto end1;
                    delta = ts - hist->ts;
                    if (delta < 0)
                        goto end1;
                    delta /= 1000U;
                    slot = log2l(delta);
                    if (slot >= MAX_SLOTS)
                        slot = MAX_SLOTS - 1;
                    __sync_fetch_and_add(&hist->slots[slot], 1);
                end1:
                    hist->ts = ts;
                }
            }
            break;
        case STATISTICS_BURST:
            if (kpoint == KPOINT_NAPI_GRO_RECEIVE_ENTRY || kpoint == KPOINT_NET_DEV_XMIT) {
                key += queue_mapping + 1;
                stat = bpf_map_lookup_or_try_init(&track_statistics, &key, &zero);
                if (stat) {
                    __sync_fetch_and_add(&stat->pkts, 1);
                    __sync_fetch_and_add(&stat->bytes, len);
                    ts = bpf_ktime_get_ns();
                    if (stat->ts != 0) {
                        delta = ts - stat->ts;
                        if (delta > 1000000UL) {
                            u64 pkts = stat->pkts;
                            u64 bytes = stat->bytes;
                            if (pkts > stat->burst_pkts)
                                stat->burst_pkts = pkts;
                            if (bytes > stat->burst_bytes)
                                stat->burst_bytes = bytes;
                            stat->ts = ts;
                            stat->pkts = 0;
                            stat->bytes = 0;
                        }
                    } else
                        stat->ts = ts;
                }
            }
            break;
        default:
            return ;
    }
}

static __always_inline
int do_trace(void *ctx, struct sk_buff *skb, int kpoint, int len)
{
    u32 key = 0;
    struct skb_event *e = bpf_map_lookup_elem(&skb_events, &key);

    if (!e)
        return 0;
    if (do_filter(skb, e) < 0)
        return 0;
    // Traffic Statistics
    if (ctrl_do_statistics) {
        do_statistics(ctx, skb, kpoint, len);
        return 0;
    }

    skb_event_init(skb, e, kpoint);

    // Detect skb loss or disorder
    if (ctrl_seq_number.len) {
        detect_loss_disorder(ctx, skb, e);
    }
    // Detect network jitter
    if (ctrl_jitter) {
        
    }
    // Detect duplicate packets
    if (ctrl_dup_detect) {
        
    }
    // sniffing
    if (ctrl_do_sniffing) {
        do_sniffing(ctx, skb, e);
    }
    return 0;
}

SEC("raw_tp/netif_receive_skb_entry")
int BPF_PROG(netif_receive_skb_entry, struct sk_buff *skb)
{
    return do_trace(ctx, skb, KPOINT_NETIF_RECEIVE_SKB_ENTRY, 0);
}

SEC("raw_tp/napi_gro_receive_entry")
int BPF_PROG(napi_gro_receive_entry, struct sk_buff *skb)
{
    return do_trace(ctx, skb, KPOINT_NAPI_GRO_RECEIVE_ENTRY, 0);
}

SEC("raw_tp/netif_receive_skb")
int BPF_PROG(netif_receive_skb, struct sk_buff *skb)
{
    return do_trace(ctx, skb, KPOINT_NETIF_RECEIVE_SKB, 0);
}

SEC("raw_tp/net_dev_queue")
int BPF_PROG(net_dev_queue, struct sk_buff *skb)
{
    return do_trace(ctx, skb, KPOINT_NET_DEV_QUEUE, 0);
}

SEC("raw_tp/net_dev_xmit")
int BPF_PROG(net_dev_xmit, struct sk_buff *skb, int rc, struct net_device *dev, int len)
{
    return do_trace(ctx, skb, KPOINT_NET_DEV_XMIT, len);
}

char LICENSE[] SEC("license") = "GPL";

