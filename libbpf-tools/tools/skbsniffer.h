/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SKBSNIFFER_H
#define __SKBSNIFFER_H

#define IFNAMSIZ 16

#define MAX_FILTERS 6  //ipv4/6 proto sport dport payload1 payload2
                       //ipv4   udp   6000  6000  5
#define NUMBER_OF_CONNTRACK 256

#define NUMBER_OF_QUEUES 256

#define DEBUG_INFO 3 
#define DEBUG_WARN 2
#define DEBUG_ERR  1

enum {
    KPOINT_NETIF_RECEIVE_SKB_ENTRY,
    KPOINT_NAPI_GRO_RECEIVE_ENTRY,
    KPOINT_NETIF_RECEIVE_SKB,
    KPOINT_NET_DEV_QUEUE,
    KPOINT_NET_DEV_XMIT,
    KPOINT_MAX,
};
struct skb_base {
    u32 netns;
    u16 kpoint;  //kernel checkpoint
    u8  version; //ipv4 ipv6
    u8  protocol;//udp tcp icmp icmpv6
    union {
        u32 saddr;
        u64 saddr6[2];
    };
    union {
        u32 daddr;
        u64 daddr6[2];
    };
    union {
        // tcp udp
        struct {
            u16 sport;
            u16 dport;
        };
        // icmp echo
        struct {
            u8 type;
            u8 code;
            u16 id;
        };
    };
};

// Detect skb loss or disorder
#define LOSS_DISORDER_STATE_DEBUG 0
#define LOSS_DISORDER_STATE_RAISE 1
#define LOSS_DISORDER_STATE_DISORDER 2
#define LOSS_DISORDER_STATE_LOSS 3
#define LOSS_DISORDER_STATE_QUEUE 4
struct loss_disorder {
    u64 ts, problem_ts;
    u64 count;
    u64 number, sum;
    u64 goon;
    int problem;
    u16 queue_mapping;
};


// Traffic Statistics
#define STATISTICS_DEFAULT 1
#define STATISTICS_QUEUE   2
#define STATISTICS_SEND_FREQ 3
#define STATISTICS_SEND_LENGTH  4
#define STATISTICS_RECV_FREQ 5
#define STATISTICS_BURST 6
#define STATISTICS_MAX  7


#define MAX_SLOTS       26
struct hist {
    __u32 slots[MAX_SLOTS];
    u64 ts;
};
struct statistics {
    u64 pkts;
    u64 bytes;
    u64 ts;
    u32 burst_pkts;
    u64 burst_bytes;
};


#define SKB_EVENT_NONE 0
#define SKB_EVENT_LOSS_DISORDER  1
#define SKB_EVENT_JITTER 2
#define SKB_EVENT_DUP_PACKET 3
#define SKB_EVENT_PACKET_STATISTICS 4
#define SKB_EVENT_SNIFFED 5


struct skb_event {
    struct skb_base base;
    u16 ipid;   //iphdr:id
    char ifname[IFNAMSIZ];
    u64 timestamp;
    u16 cpu;
    u16 type;  //SKB_EVENT_*
    union {
        u8 *l4_header_address;
        struct {
            u16 state; //LOSS_DISORDER_STATE_*
            u64 number;
            u64 count;
            union {
            u16 queue_mapping;
            u16 debug_level;
            };
        } loss_disorder;
        
        struct {
            u64 jit; //ns
        } jitter;

        struct {
            u64 number;
        } dup_packet;

        struct {
            u64 pkts;
            u64 bytes;
        } statistics;

        struct {
            void *skb;
            u16 icmpseq;
        } sniffed;
    };
    
};



#endif

