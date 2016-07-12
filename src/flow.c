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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Flow implementation.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "conf.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "runmodes.h"

#include "util-random.h"
#include "util-time.h"

#include "flow.h"
#include "flow-queue.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-var.h"
#include "flow-private.h"
#include "flow-timeout.h"
#include "flow-manager.h"
#include "flow-storage.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-byte.h"
#include "util-misc.h"

#include "util-debug.h"
#include "util-privs.h"

#include "detect.h"
#include "detect-engine-state.h"
#include "stream.h"

#include "app-layer-parser.h"

#define FLOW_DEFAULT_EMERGENCY_RECOVERY 30

//#define FLOW_DEFAULT_HASHSIZE    262144
#define FLOW_DEFAULT_HASHSIZE    65536
//#define FLOW_DEFAULT_MEMCAP      128 * 1024 * 1024 /* 128 MB */
#define FLOW_DEFAULT_MEMCAP      (32 * 1024 * 1024) /* 32 MB */

#define FLOW_DEFAULT_PREALLOC    10000

/** atomic int that is used when freeing a flow from the hash. In this
 *  case we walk the hash to find a flow to free. This var records where
 *  we left off in the hash. Without this only the top rows of the hash
 *  are freed. This isn't just about fairness. Under severe presure, the
 *  hash rows on top would be all freed and the time to find a flow to
 *  free increased with every run. */
SC_ATOMIC_DECLARE(unsigned int, flow_prune_idx);

/** atomic flags */
SC_ATOMIC_DECLARE(unsigned int, flow_flags);

void FlowRegisterTests(void);
void FlowInitFlowProto();
int FlowSetProtoTimeout(uint8_t , uint32_t ,uint32_t ,uint32_t);
int FlowSetProtoEmergencyTimeout(uint8_t , uint32_t ,uint32_t ,uint32_t);
int FlowSetProtoFreeFunc(uint8_t, void (*Free)(void *));

/* Run mode selected at suricata.c */
extern int run_mode;

void FlowCleanupAppLayer(Flow *f)
{
    if (f == NULL || f->proto == 0)
        return;

    AppLayerParserStateCleanup(f->proto, f->alproto, f->alstate, f->alparser);
    f->alstate = NULL;
    f->alparser = NULL;
    return;
}

/** \brief Make sure we have enough spare flows. 
 *
 *  Enforce the prealloc parameter, so keep at least prealloc flows in the
 *  spare queue and free flows going over the limit.
 *
 *  \retval 1 if the queue was properly updated (or if it already was in good shape)
 *  \retval 0 otherwise.
 */
int FlowUpdateSpareFlows(void)
{
    SCEnter();
    uint32_t toalloc = 0, tofree = 0, len;

    FQLOCK_LOCK(&flow_spare_q);
    len = flow_spare_q.len;
    FQLOCK_UNLOCK(&flow_spare_q);

    if (len < flow_config.prealloc) {
        toalloc = flow_config.prealloc - len;

        uint32_t i;
        for (i = 0; i < toalloc; i++) {
            Flow *f = FlowAlloc();
            if (f == NULL)
                return 0;

            FlowEnqueue(&flow_spare_q,f);
        }
    } else if (len > flow_config.prealloc) {
        tofree = len - flow_config.prealloc;

        uint32_t i;
        for (i = 0; i < tofree; i++) {
            /* FlowDequeue locks the queue */
            Flow *f = FlowDequeue(&flow_spare_q);
            if (f == NULL)
                return 1;

            FlowFree(f);
        }
    }

    return 1;
}

/** \brief Set the IPOnly scanned flag for 'direction'.
  *
  * \param f Flow to set the flag in
  * \param direction direction to set the flag in
  */
void FlowSetIPOnlyFlag(Flow *f, int direction)
{
    direction ? (f->flags |= FLOW_TOSERVER_IPONLY_SET) :
        (f->flags |= FLOW_TOCLIENT_IPONLY_SET);
    return;
}

/**
 *  \brief determine the direction of the packet compared to the flow
 *  \retval 0 to_server
 *  \retval 1 to_client
 */
int FlowGetPacketDirection(const Flow *f, const Packet *p)
{
    if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP || p->proto == IPPROTO_SCTP) {
        if (!(CMP_PORT(p->sp,p->dp))) {
            /* update flags and counters */
            if (CMP_PORT(f->sp,p->sp)) {
                return TOSERVER;
            } else {
                return TOCLIENT;
            }
        } else {
            if (CMP_ADDR(&f->src,&p->src)) {
                return TOSERVER;
            } else {
                return TOCLIENT;
            }
        }
    } else if (p->proto == IPPROTO_ICMP || p->proto == IPPROTO_ICMPV6) {
        if (CMP_ADDR(&f->src,&p->src)) {
            return TOSERVER;
        } else {
            return TOCLIENT;
        }
    } else if (p->proto == PROTO_ZIGBEE) {
        if (f->src.addr_data32[0] == (uint32_t)p->zigbeevars.source_address) {
            return TOSERVER;
        } else {
            return TOCLIENT;
        }
    }

    /* default to toserver */
    return TOSERVER;
}

/**
 *  \brief Check to update "seen" flags
 *
 *  \param p packet
 *
 *  \retval 1 true
 *  \retval 0 false
 */
static inline int FlowUpdateSeenFlag(const Packet *p)
{
    if (PKT_IS_ICMPV4(p)) {
        if (ICMPV4_IS_ERROR_MSG(p)) {
            return 0;
        }
    }

    return 1;
}

/** \brief Update Packet and Flow
 *
 *  Updates packet and flow based on the new packet.
 *
 *  \param f locked flow
 *  \param p packet
 *
 *  \note overwrites p::flowflags
 */
void FlowHandlePacketUpdate(Flow *f, Packet *p)
{
    SCLogDebug("packet %"PRIu64" -- flow %p", p->pcap_cnt, f);

    /* update flags and counters */
    if (FlowGetPacketDirection(f, p) == TOSERVER) {
        f->todstpktcnt++;
        f->todstbytecnt += GET_PKT_LEN(p);
        p->flowflags = FLOW_PKT_TOSERVER;
        if (!(f->flags & FLOW_TO_DST_SEEN)) {
            if (FlowUpdateSeenFlag(p)) {
                f->flags |= FLOW_TO_DST_SEEN;
                p->flowflags |= FLOW_PKT_TOSERVER_FIRST;
            }
        }
    } else {
        f->tosrcpktcnt++;
        f->tosrcbytecnt += GET_PKT_LEN(p);
        p->flowflags = FLOW_PKT_TOCLIENT;
        if (!(f->flags & FLOW_TO_SRC_SEEN)) {
            if (FlowUpdateSeenFlag(p)) {
                f->flags |= FLOW_TO_SRC_SEEN;
                p->flowflags |= FLOW_PKT_TOCLIENT_FIRST;
            }
        }
    }

    if ((f->flags & (FLOW_TO_DST_SEEN|FLOW_TO_SRC_SEEN)) == (FLOW_TO_DST_SEEN|FLOW_TO_SRC_SEEN)) {
        SCLogDebug("pkt %p FLOW_PKT_ESTABLISHED", p);
        p->flowflags |= FLOW_PKT_ESTABLISHED;

        if (f->proto != IPPROTO_TCP) {
            SC_ATOMIC_SET(f->flow_state, FLOW_STATE_ESTABLISHED);
        }
    }

    /*set the detection bypass flags*/
    if (f->flags & FLOW_NOPACKET_INSPECTION) {
        SCLogDebug("setting FLOW_NOPACKET_INSPECTION flag on flow %p", f);
        DecodeSetNoPacketInspectionFlag(p);
    }
    if (f->flags & FLOW_NOPAYLOAD_INSPECTION) {
        SCLogDebug("setting FLOW_NOPAYLOAD_INSPECTION flag on flow %p", f);
        DecodeSetNoPayloadInspectionFlag(p);
    }
}

/** \brief Entry point for packet flow handling
 *
 * This is called for every packet.
 *
 *  \param tv threadvars
 *  \param dtv decode thread vars (for flow output api thread data)
 *  \param p packet to handle flow for
 */
void FlowHandlePacket(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{
    /* Get this packet's flow from the hash. FlowHandlePacket() will setup
     * a new flow if nescesary. If we get NULL, we're out of flow memory.
     * The returned flow is locked. */
    Flow *f = FlowGetFlowFromHash(tv, dtv, p, &p->flow);
    if (f == NULL)
        return;

    /* set the flow in the packet */
    p->flags |= PKT_HAS_FLOW;
    return;
}

/** \brief initialize the configuration
 *  \warning Not thread safe */
void FlowInitConfig(char quiet)
{
    SCLogDebug("initializing flow engine...");

    memset(&flow_config,  0, sizeof(flow_config));
    SC_ATOMIC_INIT(flow_flags);
    SC_ATOMIC_INIT(flow_memuse);
    SC_ATOMIC_INIT(flow_prune_idx);
    FlowQueueInit(&flow_spare_q);
    FlowQueueInit(&flow_recycle_q);

#ifndef AFLFUZZ_NO_RANDOM
    unsigned int seed = RandomTimePreseed();
    /* set defaults */
    flow_config.hash_rand   = (int)( FLOW_DEFAULT_HASHSIZE * (rand_r(&seed) / RAND_MAX + 1.0));
#endif
    flow_config.hash_size   = FLOW_DEFAULT_HASHSIZE;
    flow_config.memcap      = FLOW_DEFAULT_MEMCAP;
    flow_config.prealloc    = FLOW_DEFAULT_PREALLOC;

    /* If we have specific config, overwrite the defaults with them,
     * otherwise, leave the default values */
    intmax_t val = 0;
    if (ConfGetInt("flow.emergency-recovery", &val) == 1) {
        if (val <= 100 && val >= 1) {
            flow_config.emergency_recovery = (uint8_t)val;
        } else {
            SCLogError(SC_ERR_INVALID_VALUE, "flow.emergency-recovery must be in the range of 1 and 100 (as percentage)");
            flow_config.emergency_recovery = FLOW_DEFAULT_EMERGENCY_RECOVERY;
        }
    } else {
        SCLogDebug("flow.emergency-recovery, using default value");
        flow_config.emergency_recovery = FLOW_DEFAULT_EMERGENCY_RECOVERY;
    }

    /* Check if we have memcap and hash_size defined at config */
    char *conf_val;
    uint32_t configval = 0;

    /** set config values for memcap, prealloc and hash_size */
    if ((ConfGet("flow.memcap", &conf_val)) == 1)
    {
        if (ParseSizeStringU64(conf_val, &flow_config.memcap) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing flow.memcap "
                       "from conf file - %s.  Killing engine",
                       conf_val);
            exit(EXIT_FAILURE);
        }
    }
    if ((ConfGet("flow.hash-size", &conf_val)) == 1)
    {
        if (ByteExtractStringUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0) {
            flow_config.hash_size = configval;
        }
    }
    if ((ConfGet("flow.prealloc", &conf_val)) == 1)
    {
        if (ByteExtractStringUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0) {
            flow_config.prealloc = configval;
        }
    }
    SCLogDebug("Flow config from suricata.yaml: memcap: %"PRIu64", hash-size: "
               "%"PRIu32", prealloc: %"PRIu32, flow_config.memcap,
               flow_config.hash_size, flow_config.prealloc);

    /* alloc hash memory */
    uint64_t hash_size = flow_config.hash_size * sizeof(FlowBucket);
    if (!(FLOW_CHECK_MEMCAP(hash_size))) {
        SCLogError(SC_ERR_FLOW_INIT, "allocating flow hash failed: "
                "max flow memcap is smaller than projected hash size. "
                "Memcap: %"PRIu64", Hash table size %"PRIu64". Calculate "
                "total hash size by multiplying \"flow.hash-size\" with %"PRIuMAX", "
                "which is the hash bucket size.", flow_config.memcap, hash_size,
                (uintmax_t)sizeof(FlowBucket));
        exit(EXIT_FAILURE);
    }
    flow_hash = SCMallocAligned(flow_config.hash_size * sizeof(FlowBucket), CLS);
    if (unlikely(flow_hash == NULL)) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in FlowInitConfig. Exiting...");
        exit(EXIT_FAILURE);
    }
    memset(flow_hash, 0, flow_config.hash_size * sizeof(FlowBucket));

    uint32_t i = 0;
    for (i = 0; i < flow_config.hash_size; i++) {
        FBLOCK_INIT(&flow_hash[i]);
    }
    (void) SC_ATOMIC_ADD(flow_memuse, (flow_config.hash_size * sizeof(FlowBucket)));

    if (quiet == FALSE) {
        SCLogConfig("allocated %llu bytes of memory for the flow hash... "
                  "%" PRIu32 " buckets of size %" PRIuMAX "",
                  SC_ATOMIC_GET(flow_memuse), flow_config.hash_size,
                  (uintmax_t)sizeof(FlowBucket));
    }

    /* pre allocate flows */
    for (i = 0; i < flow_config.prealloc; i++) {
        if (!(FLOW_CHECK_MEMCAP(sizeof(Flow) + FlowStorageSize()))) {
            SCLogError(SC_ERR_FLOW_INIT, "preallocating flows failed: "
                    "max flow memcap reached. Memcap %"PRIu64", "
                    "Memuse %"PRIu64".", flow_config.memcap,
                    ((uint64_t)SC_ATOMIC_GET(flow_memuse) + (uint64_t)sizeof(Flow)));
            exit(EXIT_FAILURE);
        }

        Flow *f = FlowAlloc();
        if (f == NULL) {
            SCLogError(SC_ERR_FLOW_INIT, "preallocating flow failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        FlowEnqueue(&flow_spare_q,f);
    }

    if (quiet == FALSE) {
        SCLogConfig("preallocated %" PRIu32 " flows of size %" PRIuMAX "",
                flow_spare_q.len, (uintmax_t)(sizeof(Flow) + + FlowStorageSize()));
        SCLogConfig("flow memory usage: %llu bytes, maximum: %"PRIu64,
                SC_ATOMIC_GET(flow_memuse), flow_config.memcap);
    }

    FlowInitFlowProto();

    return;
}

/** \brief print some flow stats
 *  \warning Not thread safe */
static void FlowPrintStats (void)
{
    return;
}

/** \brief shutdown the flow engine
 *  \warning Not thread safe */
void FlowShutdown(void)
{
    Flow *f;
    uint32_t u;

    FlowPrintStats();

    /* free queues */
    while((f = FlowDequeue(&flow_spare_q))) {
        FlowFree(f);
    }
    while((f = FlowDequeue(&flow_recycle_q))) {
        FlowFree(f);
    }

    /* clear and free the hash */
    if (flow_hash != NULL) {
        /* clean up flow mutexes */
        for (u = 0; u < flow_config.hash_size; u++) {
            Flow *f = flow_hash[u].head;
            while (f) {
#ifdef DEBUG_VALIDATION
                BUG_ON(SC_ATOMIC_GET(f->use_cnt) != 0);
#endif
                Flow *n = f->hnext;
                uint8_t proto_map = FlowGetProtoMapping(f->proto);
                FlowClearMemory(f, proto_map);
                FlowFree(f);
                f = n;
            }

            FBLOCK_DESTROY(&flow_hash[u]);
        }
        SCFreeAligned(flow_hash);
        flow_hash = NULL;
    }
    (void) SC_ATOMIC_SUB(flow_memuse, flow_config.hash_size * sizeof(FlowBucket));
    FlowQueueDestroy(&flow_spare_q);
    FlowQueueDestroy(&flow_recycle_q);

    SC_ATOMIC_DESTROY(flow_prune_idx);
    SC_ATOMIC_DESTROY(flow_memuse);
    SC_ATOMIC_DESTROY(flow_flags);
    return;
}

/**
 *  \brief  Function to set the default timeout, free function and flow state
 *          function for all supported flow_proto.
 */

void FlowInitFlowProto(void)
{
    /*Default*/
    flow_proto[FLOW_PROTO_DEFAULT].new_timeout = FLOW_DEFAULT_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].est_timeout = FLOW_DEFAULT_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].closed_timeout =
        FLOW_DEFAULT_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].emerg_new_timeout =
        FLOW_DEFAULT_EMERG_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].emerg_est_timeout =
        FLOW_DEFAULT_EMERG_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].emerg_closed_timeout =
        FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].Freefunc = NULL;
    /*TCP*/
    flow_proto[FLOW_PROTO_TCP].new_timeout = FLOW_IPPROTO_TCP_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].est_timeout = FLOW_IPPROTO_TCP_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].closed_timeout = FLOW_DEFAULT_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].emerg_new_timeout =
        FLOW_IPPROTO_TCP_EMERG_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].emerg_est_timeout =
        FLOW_IPPROTO_TCP_EMERG_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].emerg_closed_timeout =
        FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].Freefunc = NULL;
    /*UDP*/
    flow_proto[FLOW_PROTO_UDP].new_timeout = FLOW_IPPROTO_UDP_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].est_timeout = FLOW_IPPROTO_UDP_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].closed_timeout = FLOW_DEFAULT_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].emerg_new_timeout =
        FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].emerg_est_timeout =
        FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].emerg_closed_timeout =
        FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].Freefunc = NULL;
    /*ICMP*/
    flow_proto[FLOW_PROTO_ICMP].new_timeout = FLOW_IPPROTO_ICMP_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].est_timeout = FLOW_IPPROTO_ICMP_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].closed_timeout = FLOW_DEFAULT_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].emerg_new_timeout =
        FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].emerg_est_timeout =
        FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].emerg_closed_timeout =
        FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].Freefunc = NULL;
   /*ZigBee*/
    flow_proto[FLOW_PROTO_ZIGBEE].new_timeout = FLOW_DEFAULT_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_ZIGBEE].est_timeout = FLOW_DEFAULT_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_ZIGBEE].closed_timeout =
        FLOW_DEFAULT_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_ZIGBEE].emerg_new_timeout =
        FLOW_DEFAULT_EMERG_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_ZIGBEE].emerg_est_timeout =
        FLOW_DEFAULT_EMERG_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_ZIGBEE].emerg_closed_timeout =
        FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_ZIGBEE].Freefunc = NULL;
    /* Let's see if we have custom timeouts defined from config */
    const char *new = NULL;
    const char *established = NULL;
    const char *closed = NULL;
    const char *emergency_new = NULL;
    const char *emergency_established = NULL;
    const char *emergency_closed = NULL;

    ConfNode *flow_timeouts = ConfGetNode("flow-timeouts");
    if (flow_timeouts != NULL) {
        ConfNode *proto = NULL;
        uint32_t configval = 0;

        /* Defaults. */
        proto = ConfNodeLookupChild(flow_timeouts, "default");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            closed = ConfNodeLookupChildValue(proto, "closed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency-established");
            emergency_closed = ConfNodeLookupChildValue(proto,
                "emergency-closed");

            if (new != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(new), new) > 0) {

                    flow_proto[FLOW_PROTO_DEFAULT].new_timeout = configval;
            }
            if (established != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(established),
                                        established) > 0) {

                flow_proto[FLOW_PROTO_DEFAULT].est_timeout = configval;
            }
            if (closed != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(closed),
                                        closed) > 0) {

                flow_proto[FLOW_PROTO_DEFAULT].closed_timeout = configval;
            }
            if (emergency_new != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(emergency_new),
                                        emergency_new) > 0) {

                flow_proto[FLOW_PROTO_DEFAULT].emerg_new_timeout = configval;
            }
            if (emergency_established != NULL &&
                    ByteExtractStringUint32(&configval, 10,
                                            strlen(emergency_established),
                                            emergency_established) > 0) {

                flow_proto[FLOW_PROTO_DEFAULT].emerg_est_timeout= configval;
            }
            if (emergency_closed != NULL &&
                    ByteExtractStringUint32(&configval, 10,
                                            strlen(emergency_closed),
                                            emergency_closed) > 0) {

                flow_proto[FLOW_PROTO_DEFAULT].emerg_closed_timeout = configval;
            }
        }

        /* TCP. */
        proto = ConfNodeLookupChild(flow_timeouts, "tcp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            closed = ConfNodeLookupChildValue(proto, "closed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency-established");
            emergency_closed = ConfNodeLookupChildValue(proto,
                "emergency-closed");

            if (new != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(new), new) > 0) {

                flow_proto[FLOW_PROTO_TCP].new_timeout = configval;
            }
            if (established != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(established),
                                        established) > 0) {

                flow_proto[FLOW_PROTO_TCP].est_timeout = configval;
            }
            if (closed != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(closed),
                                        closed) > 0) {

                flow_proto[FLOW_PROTO_TCP].closed_timeout = configval;
            }
            if (emergency_new != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(emergency_new),
                                        emergency_new) > 0) {

                flow_proto[FLOW_PROTO_TCP].emerg_new_timeout = configval;
            }
            if (emergency_established != NULL &&
                ByteExtractStringUint32(&configval, 10,
                                        strlen(emergency_established),
                                        emergency_established) > 0) {

                flow_proto[FLOW_PROTO_TCP].emerg_est_timeout = configval;
            }
            if (emergency_closed != NULL &&
                ByteExtractStringUint32(&configval, 10,
                                        strlen(emergency_closed),
                                        emergency_closed) > 0) {

                flow_proto[FLOW_PROTO_TCP].emerg_closed_timeout = configval;
            }
        }

        /* UDP. */
        proto = ConfNodeLookupChild(flow_timeouts, "udp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency-established");
            if (new != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(new), new) > 0) {

                flow_proto[FLOW_PROTO_UDP].new_timeout = configval;
            }
            if (established != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(established),
                                        established) > 0) {

                flow_proto[FLOW_PROTO_UDP].est_timeout = configval;
            }
            if (emergency_new != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(emergency_new),
                                        emergency_new) > 0) {

                flow_proto[FLOW_PROTO_UDP].emerg_new_timeout = configval;
            }
            if (emergency_established != NULL &&
                ByteExtractStringUint32(&configval, 10,
                                        strlen(emergency_established),
                                        emergency_established) > 0) {

                flow_proto[FLOW_PROTO_UDP].emerg_est_timeout = configval;
            }
        }

        /* ICMP. */
        proto = ConfNodeLookupChild(flow_timeouts, "icmp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency-established");

            if (new != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(new), new) > 0) {

                flow_proto[FLOW_PROTO_ICMP].new_timeout = configval;
            }
            if (established != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(established),
                                        established) > 0) {

                flow_proto[FLOW_PROTO_ICMP].est_timeout = configval;
            }
            if (emergency_new != NULL &&
                ByteExtractStringUint32(&configval, 10, strlen(emergency_new),
                                        emergency_new) > 0) {

                flow_proto[FLOW_PROTO_ICMP].emerg_new_timeout = configval;
            }
            if (emergency_established != NULL &&
                ByteExtractStringUint32(&configval, 10,
                                        strlen(emergency_established),
                                        emergency_established) > 0) {

                flow_proto[FLOW_PROTO_ICMP].emerg_est_timeout = configval;
            }
        }
    }

    return;
}

/**
 *  \brief  Function clear the flow memory before queueing it to spare flow
 *          queue.
 *
 *  \param  f           pointer to the flow needed to be cleared.
 *  \param  proto_map   mapped value of the protocol to FLOW_PROTO's.
 */

int FlowClearMemory(Flow* f, uint8_t proto_map)
{
    SCEnter();

    /* call the protocol specific free function if we have one */
    if (flow_proto[proto_map].Freefunc != NULL) {
        flow_proto[proto_map].Freefunc(f->protoctx);
    }

    FlowFreeStorage(f);

    FLOW_RECYCLE(f);

    SCReturnInt(1);
}

/**
 *  \brief  Function to set the function to get protocol specific flow state.
 *
 *  \param   proto  protocol of which function is needed to be set.
 *  \param   Free   Function pointer which will be called to free the protocol
 *                  specific memory.
 */

int FlowSetProtoFreeFunc (uint8_t proto, void (*Free)(void *))
{
    uint8_t proto_map;
    proto_map = FlowGetProtoMapping(proto);

    flow_proto[proto_map].Freefunc = Free;
    return 1;
}

/**
 *  \brief   Function to set the timeout values for the specified protocol.
 *
 *  \param   proto            protocol of which timeout value is needed to be set.
 *  \param   new_timeout      timeout value for the new flows.
 *  \param   est_timeout      timeout value for the established flows.
 *  \param   closed_timeout   timeout value for the closed flows.
 */

int FlowSetProtoTimeout(uint8_t proto, uint32_t new_timeout,
                        uint32_t est_timeout, uint32_t closed_timeout)
{
    uint8_t proto_map;
    proto_map = FlowGetProtoMapping(proto);

    flow_proto[proto_map].new_timeout = new_timeout;
    flow_proto[proto_map].est_timeout = est_timeout;
    flow_proto[proto_map].closed_timeout = closed_timeout;

    return 1;
}

/**
 *  \brief   Function to set the emergency timeout values for the specified
 *           protocol.
 *
 *  \param   proto                  protocol of which timeout value is needed to be set.
 *  \param   emerg_new_timeout      timeout value for the new flows.
 *  \param   emerg_est_timeout      timeout value for the established flows.
 *  \param   emerg_closed_timeout   timeout value for the closed flows.
 */

int FlowSetProtoEmergencyTimeout(uint8_t proto, uint32_t emerg_new_timeout,
                                 uint32_t emerg_est_timeout,
                                 uint32_t emerg_closed_timeout)
{

    uint8_t proto_map;
    proto_map = FlowGetProtoMapping(proto);

    flow_proto[proto_map].emerg_new_timeout = emerg_new_timeout;
    flow_proto[proto_map].emerg_est_timeout = emerg_est_timeout;
    flow_proto[proto_map].emerg_closed_timeout = emerg_closed_timeout;

    return 1;
}

AppProto FlowGetAppProtocol(const Flow *f)
{
    return f->alproto;
}

void *FlowGetAppState(const Flow *f)
{
    return f->alstate;
}

/**
 *  \brief get 'disruption' flags: GAP/DEPTH/PASS
 *  \param f locked flow
 *  \param flags existing flags to be ammended
 *  \retval flags original flags + disrupt flags (if any)
 *  \TODO handle UDP
 */
uint8_t FlowGetDisruptionFlags(const Flow *f, uint8_t flags)
{
    if (f->proto != IPPROTO_TCP) {
        return flags;
    }
    if (f->protoctx == NULL) {
        return flags;
    }

    uint8_t newflags = flags;
    TcpSession *ssn = f->protoctx;
    TcpStream *stream = flags & STREAM_TOSERVER ? &ssn->client : &ssn->server;

    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
        newflags |= STREAM_DEPTH;
    }
    if (stream->flags & STREAMTCP_STREAM_FLAG_GAP) {
        newflags |= STREAM_GAP;
    }
    /* todo: handle pass case (also for UDP!) */

    return newflags;
}

/************************************Unittests*******************************/

#ifdef UNITTESTS
#include "threads.h"

/**
 *  \test   Test the setting of the per protocol timeouts.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest01 (void)
{
    uint8_t proto_map;

    FlowInitFlowProto();
    proto_map = FlowGetProtoMapping(IPPROTO_TCP);

    if ((flow_proto[proto_map].new_timeout != FLOW_IPPROTO_TCP_NEW_TIMEOUT) && (flow_proto[proto_map].est_timeout != FLOW_IPPROTO_TCP_EST_TIMEOUT)
            && (flow_proto[proto_map].emerg_new_timeout != FLOW_IPPROTO_TCP_EMERG_NEW_TIMEOUT) && (flow_proto[proto_map].emerg_est_timeout != FLOW_IPPROTO_TCP_EMERG_EST_TIMEOUT)){
        printf ("failed in setting TCP flow timeout");
        return 0;
    }

    proto_map = FlowGetProtoMapping(IPPROTO_UDP);
    if ((flow_proto[proto_map].new_timeout != FLOW_IPPROTO_UDP_NEW_TIMEOUT) && (flow_proto[proto_map].est_timeout != FLOW_IPPROTO_UDP_EST_TIMEOUT)
            && (flow_proto[proto_map].emerg_new_timeout != FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT) && (flow_proto[proto_map].emerg_est_timeout != FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT)){
        printf ("failed in setting UDP flow timeout");
        return 0;
    }

    proto_map = FlowGetProtoMapping(IPPROTO_ICMP);
    if ((flow_proto[proto_map].new_timeout != FLOW_IPPROTO_ICMP_NEW_TIMEOUT) && (flow_proto[proto_map].est_timeout != FLOW_IPPROTO_ICMP_EST_TIMEOUT)
            && (flow_proto[proto_map].emerg_new_timeout != FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT) && (flow_proto[proto_map].emerg_est_timeout != FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT)){
        printf ("failed in setting ICMP flow timeout");
        return 0;
    }

    proto_map = FlowGetProtoMapping(IPPROTO_DCCP);
    if ((flow_proto[proto_map].new_timeout != FLOW_DEFAULT_NEW_TIMEOUT) && (flow_proto[proto_map].est_timeout != FLOW_DEFAULT_EST_TIMEOUT)
            && (flow_proto[proto_map].emerg_new_timeout != FLOW_DEFAULT_EMERG_NEW_TIMEOUT) && (flow_proto[proto_map].emerg_est_timeout != FLOW_DEFAULT_EMERG_EST_TIMEOUT)){
        printf ("failed in setting default flow timeout");
        return 0;
    }

    return 1;
}

/*Test function for the unit test FlowTest02*/

void test(void *f) {}

/**
 *  \test   Test the setting of the per protocol free function to free the
 *          protocol specific memory.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest02 (void)
{
    FlowSetProtoFreeFunc(IPPROTO_DCCP, test);
    FlowSetProtoFreeFunc(IPPROTO_TCP, test);
    FlowSetProtoFreeFunc(IPPROTO_UDP, test);
    FlowSetProtoFreeFunc(IPPROTO_ICMP, test);

    if (flow_proto[FLOW_PROTO_DEFAULT].Freefunc != test) {
        printf("Failed in setting default free function\n");
        return 0;
    }
    if (flow_proto[FLOW_PROTO_TCP].Freefunc != test) {
        printf("Failed in setting TCP free function\n");
        return 0;
    }
    if (flow_proto[FLOW_PROTO_UDP].Freefunc != test) {
        printf("Failed in setting UDP free function\n");
        return 0;
    }
    if (flow_proto[FLOW_PROTO_ICMP].Freefunc != test) {
        printf("Failed in setting ICMP free function\n");
        return 0;
    }
    return 1;
}

/**
 *  \test   Test flow allocations when it reach memcap
 *
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest07 (void)
{
    int result = 0;

    FlowInitConfig(FLOW_QUIET);
    FlowConfig backup;
    memcpy(&backup, &flow_config, sizeof(FlowConfig));

    uint32_t ini = 0;
    uint32_t end = flow_spare_q.len;
    flow_config.memcap = 10000;
    flow_config.prealloc = 100;

    /* Let's get the flow_spare_q empty */
    UTHBuildPacketOfFlows(ini, end, 0);

    /* And now let's try to reach the memcap val */
    while (FLOW_CHECK_MEMCAP(sizeof(Flow))) {
        ini = end + 1;
        end = end + 2;
        UTHBuildPacketOfFlows(ini, end, 0);
    }

    /* should time out normal */
    TimeSetIncrementTime(2000);
    ini = end + 1;
    end = end + 2;;
    UTHBuildPacketOfFlows(ini, end, 0);

    /* This means that the engine entered emerg mode: should happen as easy
     * with flow mgr activated */
    if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)
        result = 1;

    memcpy(&flow_config, &backup, sizeof(FlowConfig));
    FlowShutdown();

    return result;
}

/**
 *  \test   Test flow allocations when it reach memcap
 *
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest08 (void)
{
    int result = 0;

    FlowInitConfig(FLOW_QUIET);
    FlowConfig backup;
    memcpy(&backup, &flow_config, sizeof(FlowConfig));

    uint32_t ini = 0;
    uint32_t end = flow_spare_q.len;
    flow_config.memcap = 10000;
    flow_config.prealloc = 100;

    /* Let's get the flow_spare_q empty */
    UTHBuildPacketOfFlows(ini, end, 0);

    /* And now let's try to reach the memcap val */
    while (FLOW_CHECK_MEMCAP(sizeof(Flow))) {
        ini = end + 1;
        end = end + 2;
        UTHBuildPacketOfFlows(ini, end, 0);
    }

    /* By default we use 30  for timing out new flows. This means
     * that the Emergency mode should be set */
    TimeSetIncrementTime(20);
    ini = end + 1;
    end = end + 2;
    UTHBuildPacketOfFlows(ini, end, 0);

    /* This means that the engine released 5 flows by emergency timeout */
    if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)
        result = 1;

    memcpy(&flow_config, &backup, sizeof(FlowConfig));
    FlowShutdown();

    return result;
}

/**
 *  \test   Test flow allocations when it reach memcap
 *
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest09 (void)
{
    int result = 0;

    FlowInitConfig(FLOW_QUIET);
    FlowConfig backup;
    memcpy(&backup, &flow_config, sizeof(FlowConfig));

    uint32_t ini = 0;
    uint32_t end = flow_spare_q.len;
    flow_config.memcap = 10000;
    flow_config.prealloc = 100;

    /* Let's get the flow_spare_q empty */
    UTHBuildPacketOfFlows(ini, end, 0);

    /* And now let's try to reach the memcap val */
    while (FLOW_CHECK_MEMCAP(sizeof(Flow))) {
        ini = end + 1;
        end = end + 2;
        UTHBuildPacketOfFlows(ini, end, 0);
    }

    /* No timeout will work */
    TimeSetIncrementTime(5);
    ini = end + 1;
    end = end + 2;
    UTHBuildPacketOfFlows(ini, end, 0);

    /* engine in emerg mode */
    if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)
        result = 1;

    memcpy(&flow_config, &backup, sizeof(FlowConfig));
    FlowShutdown();

    return result;
}

#endif /* UNITTESTS */

/**
 *  \brief   Function to register the Flow Unitests.
 */
void FlowRegisterTests (void)
{
#ifdef UNITTESTS
    UtRegisterTest("FlowTest01 -- Protocol Specific Timeouts", FlowTest01);
    UtRegisterTest("FlowTest02 -- Setting Protocol Specific Free Function",
                   FlowTest02);
    UtRegisterTest("FlowTest07 -- Test flow Allocations when it reach memcap",
                   FlowTest07);
    UtRegisterTest("FlowTest08 -- Test flow Allocations when it reach memcap",
                   FlowTest08);
    UtRegisterTest("FlowTest09 -- Test flow Allocations when it reach memcap",
                   FlowTest09);

    FlowMgrRegisterTests();
    RegisterFlowStorageTests();
#endif /* UNITTESTS */
}
