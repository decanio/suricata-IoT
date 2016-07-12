/* Copyright (C) 2007-2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DECODE_H__
#define __DECODE_H__

//#define DBG_THREADS
#define COUNTERS

#include "suricata-common.h"
#include "threadvars.h"
#include "decode-events.h"
#include "flow-worker.h"

#ifdef __SC_CUDA_SUPPORT__
#include "util-cuda-buffer.h"
#include "util-cuda-vars.h"
#endif /* __SC_CUDA_SUPPORT__ */

typedef enum {
    CHECKSUM_VALIDATION_DISABLE,
    CHECKSUM_VALIDATION_ENABLE,
    CHECKSUM_VALIDATION_AUTO,
    CHECKSUM_VALIDATION_RXONLY,
    CHECKSUM_VALIDATION_KERNEL,
} ChecksumValidationMode;

enum PktSrcEnum {
    PKT_SRC_WIRE = 1,
    PKT_SRC_DECODER_GRE,
    PKT_SRC_DECODER_IPV4,
    PKT_SRC_DECODER_IPV6,
    PKT_SRC_DECODER_TEREDO,
    PKT_SRC_DEFRAG,
    PKT_SRC_STREAM_TCP_STREAM_END_PSEUDO,
    PKT_SRC_FFR,
    PKT_SRC_6LOWPAN,
};

#include "source-nflog.h"
#include "source-nfq.h"
#include "source-ipfw.h"
#include "source-pcap.h"
#include "source-af-packet.h"
#include "source-mpipe.h"
#include "source-netmap.h"

#include "action-globals.h"

#include "decode-6lowpan.h"
#include "decode-erspan.h"
#include "decode-ethernet.h"
#include "decode-gre.h"
#include "decode-ppp.h"
#include "decode-pppoe.h"
#include "decode-sll.h"
#include "decode-ipv4.h"
#include "decode-ipv6.h"
#include "decode-icmpv4.h"
#include "decode-icmpv6.h"
#include "decode-ieee-802dot15dot4.h"
#include "decode-tcp.h"
#include "decode-udp.h"
#include "decode-sctp.h"
#include "decode-raw.h"
#include "decode-null.h"
#include "decode-vlan.h"
#include "decode-mpls.h"
#include "decode-zigbee.h"

#include "detect-reference.h"

#include "app-layer-protos.h"

/* forward declarations */
struct DetectionEngineThreadCtx_;
typedef struct AppLayerThreadCtx_ AppLayerThreadCtx;

struct PktPool_;

/* declare these here as they are called from the
 * PACKET_RECYCLE and PACKET_CLEANUP macro's. */
typedef struct AppLayerDecoderEvents_ AppLayerDecoderEvents;
void AppLayerDecoderEventsResetEvents(AppLayerDecoderEvents *events);
void AppLayerDecoderEventsFreeEvents(AppLayerDecoderEvents **events);

/* Address */
typedef struct Address_ {
    char family;
    union {
        uint32_t       address_un_data32[4]; /* type-specific field */
        uint16_t       address_un_data16[8]; /* type-specific field */
        uint8_t        address_un_data8[16]; /* type-specific field */
    } address;
} Address;

#define addr_data32 address.address_un_data32
#define addr_data16 address.address_un_data16
#define addr_data8  address.address_un_data8

#define COPY_ADDRESS(a, b) do {                    \
        (b)->family = (a)->family;                 \
        (b)->addr_data32[0] = (a)->addr_data32[0]; \
        (b)->addr_data32[1] = (a)->addr_data32[1]; \
        (b)->addr_data32[2] = (a)->addr_data32[2]; \
        (b)->addr_data32[3] = (a)->addr_data32[3]; \
    } while (0)

/* Set the IPv4 addresses into the Addrs of the Packet.
 * Make sure p->ip4h is initialized and validated.
 *
 * We set the rest of the struct to 0 so we can
 * prevent using memset. */
#define SET_IPV4_SRC_ADDR(p, a) do {                              \
        (a)->family = AF_INET;                                    \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_src.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)

#define SET_IPV4_DST_ADDR(p, a) do {                              \
        (a)->family = AF_INET;                                    \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_dst.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)

/* clear the address structure by setting all fields to 0 */
#define CLEAR_ADDR(a) do {       \
        (a)->family = 0;         \
        (a)->addr_data32[0] = 0; \
        (a)->addr_data32[1] = 0; \
        (a)->addr_data32[2] = 0; \
        (a)->addr_data32[3] = 0; \
    } while (0)

/* Set the IPv6 addressesinto the Addrs of the Packet.
 * Make sure p->ip6h is initialized and validated. */
#define SET_IPV6_SRC_ADDR(p, a) do {                    \
        (a)->family = AF_INET6;                         \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_src[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_src[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_src[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_src[3];  \
    } while (0)

#define SET_IPV6_DST_ADDR(p, a) do {                    \
        (a)->family = AF_INET6;                         \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_dst[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_dst[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_dst[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_dst[3];  \
    } while (0)

/* Set the TCP ports into the Ports of the Packet.
 * Make sure p->tcph is initialized and validated. */
#define SET_TCP_SRC_PORT(pkt, prt) do {            \
        SET_PORT(TCP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)

#define SET_TCP_DST_PORT(pkt, prt) do {            \
        SET_PORT(TCP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)

/* Set the UDP ports into the Ports of the Packet.
 * Make sure p->udph is initialized and validated. */
#define SET_UDP_SRC_PORT(pkt, prt) do {            \
        SET_PORT(UDP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)
#define SET_UDP_DST_PORT(pkt, prt) do {            \
        SET_PORT(UDP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)

/* Set the SCTP ports into the Ports of the Packet.
 * Make sure p->sctph is initialized and validated. */
#define SET_SCTP_SRC_PORT(pkt, prt) do {            \
        SET_PORT(SCTP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)

#define SET_SCTP_DST_PORT(pkt, prt) do {            \
        SET_PORT(SCTP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)



#define GET_IPV4_SRC_ADDR_U32(p) ((p)->src.addr_data32[0])
#define GET_IPV4_DST_ADDR_U32(p) ((p)->dst.addr_data32[0])
#define GET_IPV4_SRC_ADDR_PTR(p) ((p)->src.addr_data32)
#define GET_IPV4_DST_ADDR_PTR(p) ((p)->dst.addr_data32)

#define GET_IPV6_SRC_ADDR(p) ((p)->src.addr_data32)
#define GET_IPV6_DST_ADDR(p) ((p)->dst.addr_data32)
#define GET_TCP_SRC_PORT(p)  ((p)->sp)
#define GET_TCP_DST_PORT(p)  ((p)->dp)

#define GET_PKT_LEN(p) ((p)->pktlen)
#define GET_PKT_DATA(p) ((((p)->ext_pkt) == NULL ) ? (uint8_t *)((p) + 1) : (p)->ext_pkt)
#define GET_PKT_DIRECT_DATA(p) (uint8_t *)((p) + 1)
#define GET_PKT_DIRECT_MAX_SIZE(p) (default_packet_size)

#define SET_PKT_LEN(p, len) do { \
    (p)->pktlen = (len); \
    } while (0)


/* Port is just a uint16_t */
typedef uint16_t Port;
#define SET_PORT(v, p) ((p) = (v))
#define COPY_PORT(a,b) ((b) = (a))

#define CMP_ADDR(a1, a2) \
    (((a1)->addr_data32[3] == (a2)->addr_data32[3] && \
      (a1)->addr_data32[2] == (a2)->addr_data32[2] && \
      (a1)->addr_data32[1] == (a2)->addr_data32[1] && \
      (a1)->addr_data32[0] == (a2)->addr_data32[0]))
#define CMP_PORT(p1, p2) \
    ((p1) == (p2))

/*Given a packet pkt offset to the start of the ip header in a packet
 *We determine the ip version. */
#define IP_GET_RAW_VER(pkt) ((((pkt)[0] & 0xf0) >> 4))

#define PKT_IS_IPV4(p)      (((p)->ip4h != NULL))
#define PKT_IS_IPV6(p)      (((p)->ip6h != NULL))
#define PKT_IS_TCP(p)       (((p)->tcph != NULL))
#define PKT_IS_UDP(p)       (((p)->udph != NULL))
#define PKT_IS_ICMPV4(p)    (((p)->icmpv4h != NULL))
#define PKT_IS_ICMPV6(p)    (((p)->icmpv6h != NULL))
#define PKT_IS_TOSERVER(p)  (((p)->flowflags & FLOW_PKT_TOSERVER))
#define PKT_IS_TOCLIENT(p)  (((p)->flowflags & FLOW_PKT_TOCLIENT))
#define PKT_IS_ZIGBEE(p)    (((p)->zigbeeh != NULL))

#define IPH_IS_VALID(p) (PKT_IS_IPV4((p)) || PKT_IS_IPV6((p)))

/* Retrieve proto regardless of IP version */
#define IP_GET_IPPROTO(p) \
    (p->proto ? p->proto : \
    (PKT_IS_IPV4((p))? IPV4_GET_IPPROTO((p)) : (PKT_IS_IPV6((p))? IPV6_GET_L4PROTO((p)) : 0)))

/* structure to store the sids/gids/etc the detection engine
 * found in this packet */
typedef struct PacketAlert_ {
    SigIntId num; /* Internal num, used for sorting */
    uint8_t action; /* Internal num, used for sorting */
    uint8_t flags;
    struct Signature_ *s;
    uint64_t tx_id;
} PacketAlert;

/** After processing an alert by the thresholding module, if at
 *  last it gets triggered, we might want to stick the drop action to
 *  the flow on IPS mode */
#define PACKET_ALERT_FLAG_DROP_FLOW     0x01
/** alert was generated based on state */
#define PACKET_ALERT_FLAG_STATE_MATCH   0x02
/** alert was generated based on stream */
#define PACKET_ALERT_FLAG_STREAM_MATCH  0x04
/** alert is in a tx, tx_id set */
#define PACKET_ALERT_FLAG_TX            0x08

#define PACKET_ALERT_MAX 15

typedef struct PacketAlerts_ {
    uint16_t cnt;
    PacketAlert alerts[PACKET_ALERT_MAX];
    /* single pa used when we're dropping,
     * so we can log it out in the drop log. */
    PacketAlert drop;
} PacketAlerts;

/** number of decoder events we support per packet. Power of 2 minus 1
 *  for memory layout */
#define PACKET_ENGINE_EVENT_MAX 15

/** data structure to store decoder, defrag and stream events */
typedef struct PacketEngineEvents_ {
    uint8_t cnt;                                /**< number of events */
    uint8_t events[PACKET_ENGINE_EVENT_MAX];   /**< array of events */
} PacketEngineEvents;

typedef struct PktVar_ {
    char *name;
    struct PktVar_ *next; /* right now just implement this as a list,
                           * in the long run we have thing of something
                           * faster. */
    uint8_t *value;
    uint16_t value_len;
} PktVar;

#ifdef PROFILING

/** \brief Per TMM stats storage */
typedef struct PktProfilingTmmData_ {
    uint64_t ticks_start;
    uint64_t ticks_end;
#ifdef PROFILE_LOCKING
    uint64_t mutex_lock_cnt;
    uint64_t mutex_lock_wait_ticks;
    uint64_t mutex_lock_contention;
    uint64_t spin_lock_cnt;
    uint64_t spin_lock_wait_ticks;
    uint64_t spin_lock_contention;
    uint64_t rww_lock_cnt;
    uint64_t rww_lock_wait_ticks;
    uint64_t rww_lock_contention;
    uint64_t rwr_lock_cnt;
    uint64_t rwr_lock_wait_ticks;
    uint64_t rwr_lock_contention;
#endif
} PktProfilingTmmData;

typedef struct PktProfilingData_ {
    uint64_t ticks_start;
    uint64_t ticks_end;
} PktProfilingData;

typedef struct PktProfilingDetectData_ {
    uint64_t ticks_start;
    uint64_t ticks_end;
    uint64_t ticks_spent;
} PktProfilingDetectData;

typedef struct PktProfilingAppData_ {
    uint64_t ticks_spent;
} PktProfilingAppData;

/** \brief Per pkt stats storage */
typedef struct PktProfiling_ {
    uint64_t ticks_start;
    uint64_t ticks_end;

    PktProfilingTmmData tmm[TMM_SIZE];
    PktProfilingData flowworker[PROFILE_FLOWWORKER_SIZE];
    PktProfilingAppData app[ALPROTO_MAX];
    PktProfilingDetectData detect[PROF_DETECT_SIZE];
    uint64_t proto_detect;
} PktProfiling;

#endif /* PROFILING */

/* forward declartion since Packet struct definition requires this */
struct PacketQueue_;

/* sizes of the members:
 * src: 17 bytes
 * dst: 17 bytes
 * sp/type: 1 byte
 * dp/code: 1 byte
 * proto: 1 byte
 * recurs: 1 byte
 *
 * sum of above: 38 bytes
 *
 * flow ptr: 4/8 bytes
 * flags: 1 byte
 * flowflags: 1 byte
 *
 * sum of above 44/48 bytes
 */
typedef struct Packet_
{
    /* Addresses, Ports and protocol
     * these are on top so we can use
     * the Packet as a hash key */
    Address src;
    Address dst;
    union {
        Port sp;
        uint8_t type;
    };
    union {
        Port dp;
        uint8_t code;
    };
    uint8_t proto;
    /* make sure we can't be attacked on when the tunneled packet
     * has the exact same tuple as the lower levels */
    uint8_t recursion_level;

    uint16_t vlan_id[2];
    uint8_t vlan_idx;

    /* flow */
    uint8_t flowflags;
    /* coccinelle: Packet:flowflags:FLOW_PKT_ */

    /* Pkt Flags */
    uint32_t flags;

    struct Flow_ *flow;

    /* raw hash value for looking up the flow, will need to modulated to the
     * hash size still */
    uint32_t flow_hash;

    struct timeval ts;

    union {
        /* nfq stuff */
#ifdef HAVE_NFLOG
        NFLOGPacketVars nflog_v;
#endif /* HAVE_NFLOG */
#ifdef NFQ
        NFQPacketVars nfq_v;
#endif /* NFQ */
#ifdef IPFW
        IPFWPacketVars ipfw_v;
#endif /* IPFW */
#ifdef AF_PACKET
        AFPPacketVars afp_v;
#endif
#ifdef HAVE_MPIPE
        /* tilegx mpipe stuff */
        MpipePacketVars mpipe_v;
#endif
#ifdef HAVE_NETMAP
        NetmapPacketVars netmap_v;
#endif

        /** libpcap vars: shared by Pcap Live mode and Pcap File mode */
        PcapPacketVars pcap_v;
    };

    /** The release function for packet structure and data */
    void (*ReleasePacket)(struct Packet_ *);

    /* pkt vars */
    PktVar *pktvar;

    /* header pointers */
    EthernetHdr *ethh;

    /* Checksum for IP packets. */
    int32_t level3_comp_csum;
    /* Check sum for TCP, UDP or ICMP packets */
    int32_t level4_comp_csum;

    IPV4Hdr *ip4h;

    IPV6Hdr *ip6h;

    /* IPv4 and IPv6 are mutually exclusive */
    union {
        IPV4Vars ip4vars;
        struct {
            IPV6Vars ip6vars;
            IPV6ExtHdrs ip6eh;
        };
    };
    /* Can only be one of TCP, UDP, ICMP at any given time */
    union {
        TCPVars tcpvars;
        UDPVars udpvars;
        ICMPV4Vars icmpv4vars;
        ICMPV6Vars icmpv6vars;
    };

    TCPHdr *tcph;

    UDPHdr *udph;

    SCTPHdr *sctph;

    ICMPV4Hdr *icmpv4h;

    ICMPV6Hdr *icmpv6h;

    PPPHdr *ppph;
    PPPOESessionHdr *pppoesh;
    PPPOEDiscoveryHdr *pppoedh;

    GREHdr *greh;

    VLANHdr *vlanh[2];
    
    ZigBeeHdr *zigbeeh;

    IEEE802154Vars ieee802154vars;
    ZigBeeVars zigbeevars;
    /* 6LoWPAN fragment reassembly map. 1 bit per 8 bytes */
    uint32_t sixlowpan_frag_map[5];

    /* ptr to the payload of the packet
     * with it's length. */
    uint8_t *payload;
    uint16_t payload_len;

    /* IPS action to take */
    uint8_t action;

    uint8_t pkt_src;

    /* storage: set to pointer to heap and extended via allocation if necessary */
    uint32_t pktlen;
    uint8_t *ext_pkt;

    /* Incoming interface */
    struct LiveDevice_ *livedev;

    PacketAlerts alerts;

    struct Host_ *host_src;
    struct Host_ *host_dst;

    /** packet number in the pcap file, matches wireshark */
    uint64_t pcap_cnt;


    /* engine events */
    PacketEngineEvents events;

    AppLayerDecoderEvents *app_layer_events;

    /* double linked list ptrs */
    struct Packet_ *next;
    struct Packet_ *prev;

    /** data linktype in host order */
    int datalink;

    /* used to hold flowbits only if debuglog is enabled */
    int debuglog_flowbits_names_len;
    const char **debuglog_flowbits_names;

    /* tunnel/encapsulation handling */
    struct Packet_ *root; /* in case of tunnel this is a ptr
                           * to the 'real' packet, the one we
                           * need to set the verdict on --
                           * It should always point to the lowest
                           * packet in a encapsulated packet */

    /** mutex to protect access to:
     *  - tunnel_rtv_cnt
     *  - tunnel_tpr_cnt
     */
    SCMutex tunnel_mutex;
    /* ready to set verdict counter, only set in root */
    uint16_t tunnel_rtv_cnt;
    /* tunnel packet ref count */
    uint16_t tunnel_tpr_cnt;

    /** tenant id for this packet, if any. If 0 then no tenant was assigned. */
    uint32_t tenant_id;

    /* The Packet pool from which this packet was allocated. Used when returning
     * the packet to its owner's stack. If NULL, then allocated with malloc.
     */
    struct PktPool_ *pool;

#ifdef PROFILING
    PktProfiling *profile;
#endif
#ifdef __SC_CUDA_SUPPORT__
    CudaPacketVars cuda_pkt_vars;
#endif
}
#ifdef HAVE_MPIPE
    /* mPIPE requires packet buffers to be aligned to 128 byte boundaries. */
    __attribute__((aligned(128)))
#endif
Packet;

#define DEFAULT_PACKET_SIZE (1500 + ETHERNET_HEADER_LEN)
/* storage: maximum ip packet size + link header */
#define MAX_PAYLOAD_SIZE (IPV6_HEADER_LEN + 65536 + 28)
uint32_t default_packet_size;
#define SIZE_OF_PACKET (default_packet_size + sizeof(Packet))

typedef struct PacketQueue_ {
    Packet *top;
    Packet *bot;
    uint32_t len;
#ifdef DBG_PERF
    uint32_t dbg_maxlen;
#endif /* DBG_PERF */
    SCMutex mutex_q;
    SCCondT cond_q;
} PacketQueue;

/** \brief Structure to hold thread specific data for all decode modules */
typedef struct DecodeThreadVars_
{
    /** Specific context for udp protocol detection (here atm) */
    AppLayerThreadCtx *app_tctx;

    int vlan_disabled;

    /** stats/counters */
    uint16_t counter_pkts;
    uint16_t counter_bytes;
    uint16_t counter_avg_pkt_size;
    uint16_t counter_max_pkt_size;

    uint16_t counter_invalid;

    uint16_t counter_eth;
    uint16_t counter_ipv4;
    uint16_t counter_ipv6;
    uint16_t counter_tcp;
    uint16_t counter_udp;
    uint16_t counter_icmpv4;
    uint16_t counter_icmpv6;

    uint16_t counter_sll;
    uint16_t counter_raw;
    uint16_t counter_null;
    uint16_t counter_ieee802154;
    uint16_t counter_6lowpan;
    uint16_t counter_6lowpan_uncompressed;
    uint16_t counter_6lowpan_fragment;
    uint16_t counter_6lowpan_reassembled;
    uint16_t counter_zigbee;
    uint16_t counter_sctp;
    uint16_t counter_ppp;
    uint16_t counter_gre;
    uint16_t counter_vlan;
    uint16_t counter_vlan_qinq;
    uint16_t counter_pppoe;
    uint16_t counter_teredo;
    uint16_t counter_mpls;
    uint16_t counter_ipv4inipv6;
    uint16_t counter_ipv6inipv6;
    uint16_t counter_erspan;

    /** frag stats - defrag runs in the context of the decoder. */
    uint16_t counter_defrag_ipv4_fragments;
    uint16_t counter_defrag_ipv4_reassembled;
    uint16_t counter_defrag_ipv4_timeouts;
    uint16_t counter_defrag_ipv6_fragments;
    uint16_t counter_defrag_ipv6_reassembled;
    uint16_t counter_defrag_ipv6_timeouts;
    uint16_t counter_defrag_max_hit;

    uint16_t counter_flow_memcap;

     uint16_t counter_invalid_events[DECODE_EVENT_PACKET_MAX];
    /* thread data for flow logging api: only used at forced
     * flow recycle during lookups */
    void *output_flow_thread_data;

#ifdef __SC_CUDA_SUPPORT__
    CudaThreadVars cuda_vars;
#endif
} DecodeThreadVars;

typedef struct CaptureStats_ {

    uint16_t counter_ips_accepted;
    uint16_t counter_ips_blocked;
    uint16_t counter_ips_rejected;
    uint16_t counter_ips_replaced;

} CaptureStats;

void CaptureStatsUpdate(ThreadVars *tv, CaptureStats *s, const Packet *p);
void CaptureStatsSetup(ThreadVars *tv, CaptureStats *s);

/**
 *  \brief reset these to -1(indicates that the packet is fresh from the queue)
 */
#define PACKET_RESET_CHECKSUMS(p) do { \
        (p)->level3_comp_csum = -1;   \
        (p)->level4_comp_csum = -1;   \
    } while (0)

/* if p uses extended data, free them */
#define PACKET_FREE_EXTDATA(p) do {                 \
        if ((p)->ext_pkt) {                         \
            if (!((p)->flags & PKT_ZERO_COPY)) {    \
                SCFree((p)->ext_pkt);               \
            }                                       \
            (p)->ext_pkt = NULL;                    \
        }                                           \
    } while(0)

/**
 *  \brief Initialize a packet structure for use.
 */
#ifdef __SC_CUDA_SUPPORT__
#include "util-cuda-handlers.h"
#include "util-mpm.h"

#define PACKET_INITIALIZE(p) do {                                       \
        memset((p), 0x00, SIZE_OF_PACKET);                              \
        SCMutexInit(&(p)->tunnel_mutex, NULL);                          \
        PACKET_RESET_CHECKSUMS((p));                                    \
        (p)->livedev = NULL;                                            \
        SCMutexInit(&(p)->cuda_pkt_vars.cuda_mutex, NULL);            \
        SCCondInit(&(p)->cuda_pkt_vars.cuda_cond, NULL);                \
    } while (0)
#else
#define PACKET_INITIALIZE(p) {         \
    SCMutexInit(&(p)->tunnel_mutex, NULL); \
    PACKET_RESET_CHECKSUMS((p)); \
    (p)->livedev = NULL; \
}
#endif

#define PACKET_RELEASE_REFS(p) do {              \
        FlowDeReference(&((p)->flow));          \
        HostDeReference(&((p)->host_src));      \
        HostDeReference(&((p)->host_dst));      \
    } while (0)

/**
 *  \brief Recycle a packet structure for reuse.
 */
#define PACKET_REINIT(p) do {             \
        CLEAR_ADDR(&(p)->src);                  \
        CLEAR_ADDR(&(p)->dst);                  \
        (p)->sp = 0;                            \
        (p)->dp = 0;                            \
        (p)->proto = 0;                         \
        (p)->recursion_level = 0;               \
        PACKET_FREE_EXTDATA((p));               \
        (p)->flags = (p)->flags & PKT_ALLOC;    \
        (p)->flowflags = 0;                     \
        (p)->pkt_src = 0;                       \
        (p)->vlan_id[0] = 0;                    \
        (p)->vlan_id[1] = 0;                    \
        (p)->vlan_idx = 0;                      \
        (p)->ts.tv_sec = 0;                     \
        (p)->ts.tv_usec = 0;                    \
        (p)->datalink = 0;                      \
        (p)->action = 0;                        \
        if ((p)->pktvar != NULL) {              \
            PktVarFree((p)->pktvar);            \
            (p)->pktvar = NULL;                 \
        }                                       \
        (p)->ethh = NULL;                       \
        if ((p)->ip4h != NULL) {                \
            CLEAR_IPV4_PACKET((p));             \
        }                                       \
        if ((p)->ip6h != NULL) {                \
            CLEAR_IPV6_PACKET((p));             \
        }                                       \
        if ((p)->tcph != NULL) {                \
            CLEAR_TCP_PACKET((p));              \
        }                                       \
        if ((p)->udph != NULL) {                \
            CLEAR_UDP_PACKET((p));              \
        }                                       \
        if ((p)->sctph != NULL) {               \
            CLEAR_SCTP_PACKET((p));             \
        }                                       \
        if ((p)->icmpv4h != NULL) {             \
            CLEAR_ICMPV4_PACKET((p));           \
        }                                       \
        if ((p)->icmpv6h != NULL) {             \
            CLEAR_ICMPV6_PACKET((p));           \
        }                                       \
        (p)->ppph = NULL;                       \
        (p)->pppoesh = NULL;                    \
        (p)->pppoedh = NULL;                    \
        (p)->greh = NULL;                       \
        (p)->vlanh[0] = NULL;                   \
        (p)->vlanh[1] = NULL;                   \
        (p)->payload = NULL;                    \
        (p)->payload_len = 0;                   \
        (p)->pktlen = 0;                        \
        (p)->alerts.cnt = 0;                    \
        (p)->alerts.drop.action = 0;            \
        (p)->pcap_cnt = 0;                      \
        (p)->tunnel_rtv_cnt = 0;                \
        (p)->tunnel_tpr_cnt = 0;                \
        (p)->events.cnt = 0;                    \
        AppLayerDecoderEventsResetEvents((p)->app_layer_events); \
        (p)->next = NULL;                       \
        (p)->prev = NULL;                       \
        (p)->root = NULL;                       \
        (p)->livedev = NULL;                    \
        PACKET_RESET_CHECKSUMS((p));            \
        PACKET_PROFILING_RESET((p));            \
        p->tenant_id = 0;                       \
    } while (0)

#define PACKET_RECYCLE(p) do { \
        PACKET_RELEASE_REFS((p)); \
        PACKET_REINIT((p)); \
    } while (0)

/**
 *  \brief Cleanup a packet so that we can free it. No memset needed..
 */
#define PACKET_DESTRUCTOR(p) do {                  \
        if ((p)->pktvar != NULL) {              \
            PktVarFree((p)->pktvar);            \
        }                                       \
        PACKET_FREE_EXTDATA((p));               \
        SCMutexDestroy(&(p)->tunnel_mutex);     \
        AppLayerDecoderEventsFreeEvents(&(p)->app_layer_events); \
        PACKET_PROFILING_RESET((p));            \
    } while (0)


/* macro's for setting the action
 * handle the case of a root packet
 * for tunnels */

#define PACKET_SET_ACTION(p, a) do { \
    ((p)->root ? \
     ((p)->root->action = a) : \
     ((p)->action = a)); \
} while (0)

#define PACKET_ALERT(p) PACKET_SET_ACTION(p, ACTION_ALERT)

#define PACKET_ACCEPT(p) PACKET_SET_ACTION(p, ACTION_ACCEPT)

#define PACKET_DROP(p) PACKET_SET_ACTION(p, ACTION_DROP)

#define PACKET_REJECT(p) PACKET_SET_ACTION(p, (ACTION_REJECT|ACTION_DROP))

#define PACKET_REJECT_DST(p) PACKET_SET_ACTION(p, (ACTION_REJECT_DST|ACTION_DROP))

#define PACKET_REJECT_BOTH(p) PACKET_SET_ACTION(p, (ACTION_REJECT_BOTH|ACTION_DROP))

#define PACKET_PASS(p) PACKET_SET_ACTION(p, ACTION_PASS)

#define PACKET_TEST_ACTION(p, a) \
    ((p)->root ? \
     ((p)->root->action & a) : \
     ((p)->action & a))

#define PACKET_UPDATE_ACTION(p, a) do { \
    ((p)->root ? \
     ((p)->root->action |= a) : \
     ((p)->action |= a)); \
} while (0)

#define TUNNEL_INCR_PKT_RTV(p) do {                                                 \
        SCMutexLock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);     \
        ((p)->root ? (p)->root->tunnel_rtv_cnt++ : (p)->tunnel_rtv_cnt++);          \
        SCMutexUnlock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);   \
    } while (0)

#define TUNNEL_INCR_PKT_TPR(p) do {                                                 \
        SCMutexLock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);     \
        ((p)->root ? (p)->root->tunnel_tpr_cnt++ : (p)->tunnel_tpr_cnt++);          \
        SCMutexUnlock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);   \
    } while (0)

#define TUNNEL_DECR_PKT_TPR(p) do {                                                 \
        SCMutexLock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);     \
        ((p)->root ? (p)->root->tunnel_tpr_cnt-- : (p)->tunnel_tpr_cnt--);          \
        SCMutexUnlock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);   \
    } while (0)

#define TUNNEL_DECR_PKT_TPR_NOLOCK(p) do {                                          \
        ((p)->root ? (p)->root->tunnel_tpr_cnt-- : (p)->tunnel_tpr_cnt--);          \
    } while (0)

#define TUNNEL_PKT_RTV(p) ((p)->root ? (p)->root->tunnel_rtv_cnt : (p)->tunnel_rtv_cnt)
#define TUNNEL_PKT_TPR(p) ((p)->root ? (p)->root->tunnel_tpr_cnt : (p)->tunnel_tpr_cnt)

#define IS_TUNNEL_PKT(p)            (((p)->flags & PKT_TUNNEL))
#define SET_TUNNEL_PKT(p)           ((p)->flags |= PKT_TUNNEL)
#define UNSET_TUNNEL_PKT(p)         ((p)->flags &= ~PKT_TUNNEL)
#define IS_TUNNEL_ROOT_PKT(p)       (IS_TUNNEL_PKT(p) && (p)->root == NULL)

#define IS_TUNNEL_PKT_VERDICTED(p)  (((p)->flags & PKT_TUNNEL_VERDICTED))
#define SET_TUNNEL_PKT_VERDICTED(p) ((p)->flags |= PKT_TUNNEL_VERDICTED)

enum DecodeTunnelProto {
    DECODE_TUNNEL_ETHERNET,
    DECODE_TUNNEL_ERSPAN,
    DECODE_TUNNEL_VLAN,
    DECODE_TUNNEL_IPV4,
    DECODE_TUNNEL_IPV6,
    DECODE_TUNNEL_PPP,
};

Packet *PacketTunnelPktSetup(ThreadVars *tv, DecodeThreadVars *dtv, Packet *parent,
                             uint8_t *pkt, uint16_t len, enum DecodeTunnelProto proto, PacketQueue *pq);
Packet *PacketDefragPktSetup(Packet *parent, uint8_t *pkt, uint16_t len, uint8_t proto);
void PacketDefragPktSetupParent(Packet *parent);
Packet *Packet6LoWPANPktSetup(Packet *parent, uint8_t *pkt, uint16_t len);
void DecodeRegisterPerfCounters(DecodeThreadVars *, ThreadVars *);
Packet *PacketGetFromQueueOrAlloc(void);
Packet *PacketGetFromAlloc(void);
void PacketDecodeFinalize(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p);
void PacketFree(Packet *p);
void PacketFreeOrRelease(Packet *p);
int PacketCallocExtPkt(Packet *p, int datalen);
int PacketCopyData(Packet *p, uint8_t *pktdata, int pktlen);
int PacketSetData(Packet *p, uint8_t *pktdata, int pktlen);
int PacketCopyDataOffset(Packet *p, int offset, uint8_t *data, int datalen);
const char *PktSrcToString(enum PktSrcEnum pkt_src);

DecodeThreadVars *DecodeThreadVarsAlloc(ThreadVars *);
void DecodeThreadVarsFree(ThreadVars *, DecodeThreadVars *);
void DecodeUpdatePacketCounters(ThreadVars *tv,
                                const DecodeThreadVars *dtv, const Packet *p);

/* decoder functions */
int DecodeEthernet(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeIEEE802Dot15Dot4(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeSll(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodePPP(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodePPPOESession(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodePPPOEDiscovery(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeTunnel(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *, enum DecodeTunnelProto) __attribute__ ((warn_unused_result));
int DecodeNull(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeRaw(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeIPV4(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeIPV6(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int Decode6LoWPAN(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeZigBee(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeICMPV4(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeICMPV6(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeTCP(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeUDP(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeSCTP(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeGRE(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeVLAN(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeMPLS(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
int DecodeERSPAN(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);

void AddressDebugPrint(Address *);

#ifdef AFLFUZZ_DECODER
typedef int (*DecoderFunc)(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
         uint8_t *pkt, uint16_t len, PacketQueue *pq);

int DecoderParseDataFromFile(char *filename, DecoderFunc Decoder);
#endif

/** \brief Set the No payload inspection Flag for the packet.
 *
 * \param p Packet to set the flag in
 */
#define DecodeSetNoPayloadInspectionFlag(p) do { \
        (p)->flags |= PKT_NOPAYLOAD_INSPECTION;  \
    } while (0)

#define DecodeUnsetNoPayloadInspectionFlag(p) do { \
        (p)->flags &= ~PKT_NOPAYLOAD_INSPECTION;  \
    } while (0)

/** \brief Set the No packet inspection Flag for the packet.
 *
 * \param p Packet to set the flag in
 */
#define DecodeSetNoPacketInspectionFlag(p) do { \
        (p)->flags |= PKT_NOPACKET_INSPECTION;  \
    } while (0)
#define DecodeUnsetNoPacketInspectionFlag(p) do { \
        (p)->flags &= ~PKT_NOPACKET_INSPECTION;  \
    } while (0)


#define ENGINE_SET_EVENT(p, e) do { \
    SCLogDebug("p %p event %d", (p), e); \
    if ((p)->events.cnt < PACKET_ENGINE_EVENT_MAX) { \
        (p)->events.events[(p)->events.cnt] = e; \
        (p)->events.cnt++; \
    } \
} while(0)

#define ENGINE_SET_INVALID_EVENT(p, e) do { \
    p->flags |= PKT_IS_INVALID; \
    ENGINE_SET_EVENT(p, e); \
} while(0)



#define ENGINE_ISSET_EVENT(p, e) ({ \
    int r = 0; \
    uint8_t u; \
    for (u = 0; u < (p)->events.cnt; u++) { \
        if ((p)->events.events[u] == (e)) { \
            r = 1; \
            break; \
        } \
    } \
    r; \
})

/* older libcs don't contain a def for IPPROTO_DCCP
 * inside of <netinet/in.h>
 * if it isn't defined let's define it here.
 */
#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif

/* older libcs don't contain a def for IPPROTO_SCTP
 * inside of <netinet/in.h>
 * if it isn't defined let's define it here.
 */
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif

/* Host Identity Protocol (rfc 5201) */
#ifndef IPPROTO_HIP
#define IPPROTO_HIP 139
#endif

#ifndef IPPROTO_SHIM6
#define IPPROTO_SHIM6 140
#endif

/* define a constant to ZigBee.  Not an IPPROTO_ */
#define PROTO_ZIGBEE 255

/* pcap provides this, but we don't want to depend on libpcap */
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

/* taken from pcap's bpf.h */
#ifndef DLT_RAW
#ifdef __OpenBSD__
#define DLT_RAW     14  /* raw IP */
#else
#define DLT_RAW     12  /* raw IP */
#endif
#endif

#ifndef DLT_NULL
#define DLT_NULL 0
#endif

/** libpcap shows us the way to linktype codes
 * \todo we need more & maybe put them in a separate file? */
#define LINKTYPE_NULL       DLT_NULL
#define LINKTYPE_ETHERNET   DLT_EN10MB
#define LINKTYPE_IEEE802_15_4 DLT_IEEE802_15_4
#define LINKTYPE_IEEE802_15_4_NOFCS DLT_IEEE802_15_4_NOFCS
#define LINKTYPE_LINUX_SLL  113
#define LINKTYPE_PPP        9
#define LINKTYPE_RAW        DLT_RAW
#define PPP_OVER_GRE        11
#define VLAN_OVER_GRE       13

/*Packet Flags*/
#define PKT_NOPACKET_INSPECTION         (1)         /**< Flag to indicate that packet header or contents should not be inspected*/
#define PKT_NOPAYLOAD_INSPECTION        (1<<2)      /**< Flag to indicate that packet contents should not be inspected*/
#define PKT_ALLOC                       (1<<3)      /**< Packet was alloc'd this run, needs to be freed */
#define PKT_HAS_TAG                     (1<<4)      /**< Packet has matched a tag */
#define PKT_STREAM_ADD                  (1<<5)      /**< Packet payload was added to reassembled stream */
#define PKT_STREAM_EST                  (1<<6)      /**< Packet is part of establised stream */
#define PKT_STREAM_EOF                  (1<<7)      /**< Stream is in eof state */
#define PKT_HAS_FLOW                    (1<<8)
#define PKT_PSEUDO_STREAM_END           (1<<9)      /**< Pseudo packet to end the stream */
#define PKT_STREAM_MODIFIED             (1<<10)     /**< Packet is modified by the stream engine, we need to recalc the csum and reinject/replace */
#define PKT_MARK_MODIFIED               (1<<11)     /**< Packet mark is modified */
#define PKT_STREAM_NOPCAPLOG            (1<<12)     /**< Exclude packet from pcap logging as it's part of a stream that has reassembly depth reached. */

#define PKT_TUNNEL                      (1<<13)
#define PKT_TUNNEL_VERDICTED            (1<<14)

#define PKT_IGNORE_CHECKSUM             (1<<15)     /**< Packet checksum is not computed (TX packet for example) */
#define PKT_ZERO_COPY                   (1<<16)     /**< Packet comes from zero copy (ext_pkt must not be freed) */

#define PKT_HOST_SRC_LOOKED_UP          (1<<17)
#define PKT_HOST_DST_LOOKED_UP          (1<<18)

#define PKT_IS_FRAGMENT                 (1<<19)     /**< Packet is a fragment */
#define PKT_IS_INVALID                  (1<<20)
#define PKT_PROFILE                     (1<<21)

/** indication by decoder that it feels the packet should be handled by
 *  flow engine: Packet::flow_hash will be set */
#define PKT_WANTS_FLOW                  (1<<22)

/** \brief return 1 if the packet is a pseudo packet */
#define PKT_IS_PSEUDOPKT(p) ((p)->flags & PKT_PSEUDO_STREAM_END)

#define PKT_SET_SRC(p, src_val) ((p)->pkt_src = src_val)

#endif /* __DECODE_H__ */

