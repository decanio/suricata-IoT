/* Copyright (C) 2011,2012 Open Information Security Foundation
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
 * \ingroup afppacket
 *
 * @{
 */

/**
 * \file
 *
 * \author Eric Leblond <eric@regit.org>
 *
 * AF_PACKET socket runmode
 *
 */


#include "suricata-common.h"
#include "config.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-af-packet.h"
#include "log-httplog.h"
#include "output.h"
#include "detect-engine-mpm.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"
#include "util-ioctl.h"

#include "source-af-packet.h"

extern int max_pending_packets;

static const char *default_mode_workers = NULL;

const char *RunModeAFPGetDefaultMode(void)
{
    return default_mode_workers;
}

void RunModeIdsAFPRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "single",
                              "Single threaded af-packet mode",
                              RunModeIdsAFPSingle);
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "workers",
                              "Workers af-packet mode, each thread does all"
                              " tasks from acquisition to logging",
                              RunModeIdsAFPWorkers);
    default_mode_workers = "workers";
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "autofp",
                              "Multi socket AF_PACKET mode.  Packets from "
                              "each flow are assigned to a single detect "
                              "thread.",
                              RunModeIdsAFPAutoFp);
    return;
}


#ifdef HAVE_AF_PACKET

void AFPDerefConfig(void *conf)
{
    AFPIfaceConfig *pfp = (AFPIfaceConfig *)conf;
    /* Pcap config is used only once but cost of this low. */
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 0) {
        SCFree(pfp);
    }
}

/* if cluster id is not set, assign it automagically, uniq value per
 * interface. */
static int cluster_id_auto = 1;

/**
 * \brief extract information from config file
 *
 * The returned structure will be freed by the thread init function.
 * This is thus necessary to or copy the structure before giving it
 * to thread or to reparse the file for each thread (and thus have
 * new structure.
 *
 * \return a AFPIfaceConfig corresponding to the interface name
 */
void *ParseAFPConfig(const char *iface)
{
    char *threadsstr = NULL;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *af_packet_node;
    char *tmpclusterid;
    char *tmpctype;
    char *copymodestr;
    intmax_t value;
    int boolval;
    char *bpf_filter = NULL;
    char *out_iface = NULL;
    int cluster_type = PACKET_FANOUT_HASH;

    if (iface == NULL) {
        return NULL;
    }

    AFPIfaceConfig *aconf = SCCalloc(1, sizeof(*aconf));
    if (unlikely(aconf == NULL)) {
        return NULL;
    }

    strlcpy(aconf->iface, iface, sizeof(aconf->iface));
    aconf->threads = 0;
    SC_ATOMIC_INIT(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, 1);
    aconf->buffer_size = 0;
    aconf->cluster_id = 1;
    aconf->cluster_type = cluster_type | PACKET_FANOUT_FLAG_DEFRAG;
    aconf->promisc = 1;
    aconf->checksum_mode = CHECKSUM_VALIDATION_KERNEL;
    aconf->DerefFunc = AFPDerefConfig;
    aconf->itronriva = 0;
    aconf->flags = AFP_RING_MODE;
    aconf->bpf_filter = NULL;
    aconf->out_iface = NULL;
    aconf->copy_mode = AFP_COPY_MODE_NONE;
    aconf->block_timeout = 10;
    aconf->block_size = getpagesize() << AFP_BLOCK_SIZE_DEFAULT_ORDER;

    if (ConfGet("bpf-filter", &bpf_filter) == 1) {
        if (strlen(bpf_filter) > 0) {
            aconf->bpf_filter = bpf_filter;
            SCLogConfig("Going to use command-line provided bpf filter '%s'",
                       aconf->bpf_filter);
        }
    }

    /* Find initial node */
    af_packet_node = ConfGetNode("af-packet");
    if (af_packet_node == NULL) {
        SCLogInfo("unable to find af-packet config using default values");
        goto finalize;
    }

    if_root = ConfFindDeviceConfig(af_packet_node, iface);
    if_default = ConfFindDeviceConfig(af_packet_node, "default");

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("unable to find af-packet config for "
                  "interface \"%s\" or \"default\", using default values",
                  iface);
        goto finalize;
    }

    /* If there is no setting for current interface use default one as main iface */
    if (if_root == NULL) {
        if_root = if_default;
        if_default = NULL;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "threads", &threadsstr) != 1) {
        aconf->threads = 0;
    } else {
        if (threadsstr != NULL) {
            if (strcmp(threadsstr, "auto") == 0) {
                aconf->threads = 0;
            } else {
                aconf->threads = (uint8_t)atoi(threadsstr);
            }
        }
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-iface", &out_iface) == 1) {
        if (strlen(out_iface) > 0) {
            aconf->out_iface = out_iface;
        }
    }

    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "use-mmap", (int *)&boolval) == 1) {
        if (!boolval) {
            SCLogConfig("Disabling mmaped capture on iface %s",
                    aconf->iface);
            aconf->flags &= ~(AFP_RING_MODE|AFP_TPACKET_V3);
        }
    }

    if (aconf->flags & AFP_RING_MODE) {
        (void)ConfGetChildValueBoolWithDefault(if_root, if_default,
                                               "mmap-locked", (int *)&boolval);
        if (boolval) {
            SCLogConfig("Enabling locked memory for mmap on iface %s",
                    aconf->iface);
            aconf->flags |= AFP_MMAP_LOCKED;
        }

        if (ConfGetChildValueBoolWithDefault(if_root, if_default,
                                             "tpacket-v3", (int *)&boolval) == 1)
        {
            if (boolval) {
                if (strcasecmp(RunmodeGetActive(), "workers") == 0) {
#ifdef HAVE_TPACKET_V3
                    SCLogConfig("Enabling tpacket v3 capture on iface %s",
                            aconf->iface);
                    aconf->flags |= AFP_TPACKET_V3;
#else
                    SCLogNotice("System too old for tpacket v3 switching to v2");
                    aconf->flags &= ~AFP_TPACKET_V3;
#endif
                } else {
                    SCLogWarning(SC_ERR_RUNMODE,
                            "tpacket v3 is only implemented for 'workers' runmode."
                            " Switching to tpacket v2.");
                    aconf->flags &= ~AFP_TPACKET_V3;
                }
            } else {
                aconf->flags &= ~AFP_TPACKET_V3;
            }
        }

        (void)ConfGetChildValueBoolWithDefault(if_root, if_default,
                                               "use-emergency-flush", (int *)&boolval);
        if (boolval) {
            SCLogConfig("Enabling ring emergency flush on iface %s",
                    aconf->iface);
            aconf->flags |= AFP_EMERGENCY_MODE;
        }
    }

    aconf->copy_mode = AFP_COPY_MODE_NONE;
    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) {
        if (aconf->out_iface == NULL) {
            SCLogInfo("Copy mode activated but no destination"
                      " iface. Disabling feature");
        } else if (!(aconf->flags & AFP_RING_MODE)) {
            SCLogInfo("Copy mode activated but use-mmap "
                      "set to no. Disabling feature");
        } else if (strlen(copymodestr) <= 0) {
            aconf->out_iface = NULL;
        } else if (strcmp(copymodestr, "ips") == 0) {
            SCLogInfo("AF_PACKET IPS mode activated %s->%s",
                    iface,
                    aconf->out_iface);
            aconf->copy_mode = AFP_COPY_MODE_IPS;
        } else if (strcmp(copymodestr, "tap") == 0) {
            SCLogInfo("AF_PACKET TAP mode activated %s->%s",
                    iface,
                    aconf->out_iface);
            aconf->copy_mode = AFP_COPY_MODE_TAP;
        } else {
            SCLogInfo("Invalid mode (not in tap, ips)");
        }
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-id", &tmpclusterid) != 1) {
        aconf->cluster_id = (uint16_t)(cluster_id_auto++);
    } else {
        aconf->cluster_id = (uint16_t)atoi(tmpclusterid);
        SCLogDebug("Going to use cluster-id %" PRId32, aconf->cluster_id);
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-type", &tmpctype) != 1) {
        /* default to our safest choice: flow hashing + defrag enabled */
        aconf->cluster_type = PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG;
        cluster_type = PACKET_FANOUT_HASH;
    } else if (strcmp(tmpctype, "cluster_round_robin") == 0) {
        SCLogConfig("Using round-robin cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_LB;
        cluster_type = PACKET_FANOUT_LB;
    } else if (strcmp(tmpctype, "cluster_flow") == 0) {
        /* In hash mode, we also ask for defragmentation needed to
         * compute the hash */
        uint16_t defrag = 0;
        int conf_val = 0;
        SCLogConfig("Using flow cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        ConfGetChildValueBoolWithDefault(if_root, if_default, "defrag", &conf_val);
        if (conf_val) {
            SCLogConfig("Using defrag kernel functionality for AF_PACKET (iface %s)",
                    aconf->iface);
            defrag = PACKET_FANOUT_FLAG_DEFRAG;
        }
        aconf->cluster_type = PACKET_FANOUT_HASH | defrag;
        cluster_type = PACKET_FANOUT_HASH;
    } else if (strcmp(tmpctype, "cluster_cpu") == 0) {
        SCLogConfig("Using cpu cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_CPU;
        cluster_type = PACKET_FANOUT_CPU;
    } else if (strcmp(tmpctype, "cluster_qm") == 0) {
        SCLogConfig("Using queue based cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_QM;
        cluster_type = PACKET_FANOUT_QM;
    } else if (strcmp(tmpctype, "cluster_random") == 0) {
        SCLogConfig("Using random based cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_RND;
        cluster_type = PACKET_FANOUT_RND;
    } else if (strcmp(tmpctype, "cluster_rollover") == 0) {
        SCLogConfig("Using rollover based cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_ROLLOVER;
        cluster_type = PACKET_FANOUT_ROLLOVER;

    } else {
        SCLogWarning(SC_ERR_INVALID_CLUSTER_TYPE,"invalid cluster-type %s",tmpctype);
    }

    int conf_val = 0;
    ConfGetChildValueBoolWithDefault(if_root, if_default, "rollover", &conf_val);
    if (conf_val) {
        SCLogConfig("Using rollover kernel functionality for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type |= PACKET_FANOUT_FLAG_ROLLOVER;
    }

    /*load af_packet bpf filter*/
    /* command line value has precedence */
    if (ConfGet("bpf-filter", &bpf_filter) != 1) {
        if (ConfGetChildValueWithDefault(if_root, if_default, "bpf-filter", &bpf_filter) == 1) {
            if (strlen(bpf_filter) > 0) {
                aconf->bpf_filter = bpf_filter;
                SCLogConfig("Going to use bpf filter %s", aconf->bpf_filter);
            }
        }
    }

    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "buffer-size", &value)) == 1) {
        aconf->buffer_size = value;
    } else {
        aconf->buffer_size = 0;
    }
    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "ring-size", &value)) == 1) {
        aconf->ring_size = value;
    }

    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "block-size", &value)) == 1) {
        if (value % getpagesize()) {
            SCLogError(SC_ERR_INVALID_VALUE, "Block-size must be a multiple of pagesize.");
        } else {
            aconf->block_size = value;
        }
    }

    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "block-timeout", &value)) == 1) {
        aconf->block_timeout = value;
    } else {
        aconf->block_timeout = 10;
    }

    (void)ConfGetChildValueBoolWithDefault(if_root, if_default, "disable-promisc", (int *)&boolval);
    if (boolval) {
        SCLogConfig("Disabling promiscuous mode on iface %s",
                aconf->iface);
        aconf->promisc = 0;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "checksum-checks", &tmpctype) == 1) {
        if (strcmp(tmpctype, "auto") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (ConfValIsTrue(tmpctype)) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (ConfValIsFalse(tmpctype)) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else if (strcmp(tmpctype, "kernel") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_KERNEL;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid value for checksum-checks for %s", aconf->iface);
        }
    }

    aconf->itronriva = 0;
    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "itronriva", &boolval) != 1) {
        SCLogDebug("could not get itronriva or none specified");
    } else {
        aconf->itronriva = boolval;
    }

finalize:

    /* if the number of threads is not 1, we need to first check if fanout
     * functions on this system. */
    if (aconf->threads != 1) {
        if (AFPIsFanoutSupported() == 0) {
            if (aconf->threads != 0) {
                SCLogNotice("fanout not supported on this system, falling "
                        "back to 1 capture thread");
            }
            aconf->threads = 1;
        }
    }

    /* try to automagically set the proper number of threads */
    if (aconf->threads == 0) {
        /* for cluster_flow use core count */
        if (cluster_type == PACKET_FANOUT_HASH) {
            aconf->threads = (int)UtilCpuGetNumProcessorsOnline();
            SCLogPerf("%u cores, so using %u threads", aconf->threads, aconf->threads);

        /* for cluster_qm use RSS queue count */
        } else if (cluster_type == PACKET_FANOUT_QM) {
            int rss_queues = GetIfaceRSSQueuesNum(iface);
            if (rss_queues > 0) {
                aconf->threads = rss_queues;
                SCLogPerf("%d RSS queues, so using %u threads", rss_queues, aconf->threads);
            }
        }

        if (aconf->threads) {
            SCLogPerf("Using %d AF_PACKET threads for interface %s",
                    aconf->threads, iface);
        }
    }
    if (aconf->threads <= 0) {
        aconf->threads = 1;
    }
    SC_ATOMIC_RESET(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, aconf->threads);

    if (aconf->ring_size != 0) {
        if (aconf->ring_size * aconf->threads < max_pending_packets) {
            aconf->ring_size = max_pending_packets / aconf->threads + 1;
            SCLogWarning(SC_ERR_AFP_CREATE, "Inefficient setup: ring-size < max_pending_packets. "
                         "Resetting to decent value %d.", aconf->ring_size);
            /* We want at least that max_pending_packets packets can be handled by the
             * interface. This is generous if we have multiple interfaces listening. */
        }
    } else {
        /* We want that max_pending_packets packets can be handled by suricata
         * for this interface. To take burst into account we multiply the obtained
         * size by 2. */
        aconf->ring_size = max_pending_packets * 2 / aconf->threads;
    }

    int ltype = AFPGetLinkType(iface);
    switch (ltype) {
        case LINKTYPE_ETHERNET:
            /* af-packet can handle csum offloading */
            if (GetIfaceOffloading(iface, 0, 1) == 1) {
                SCLogWarning(SC_ERR_AFP_CREATE,
                    "Using AF_PACKET with offloading activated leads to capture problems");
            }
        case -1:
        default:
            break;
    }

    char *active_runmode = RunmodeGetActive();
    if (active_runmode && !strcmp("workers", active_runmode)) {
        aconf->flags |= AFP_ZERO_COPY;
    } else {
        /* If we are using copy mode we need a lock */
        aconf->flags |= AFP_SOCK_PROTECT;
    }

    /* If we are in RING mode, then we can use ZERO copy
     * by using the data release mechanism */
    if (aconf->flags & AFP_RING_MODE) {
        aconf->flags |= AFP_ZERO_COPY;
    }

    if (aconf->flags & AFP_ZERO_COPY) {
        SCLogConfig("%s: enabling zero copy mode by using data release call", iface);
    }

    return aconf;
}

int AFPConfigGeThreadsCount(void *conf)
{
    AFPIfaceConfig *afp = (AFPIfaceConfig *)conf;
    return afp->threads;
}

int AFPRunModeIsIPS()
{
    int nlive = LiveGetDeviceCount();
    int ldev;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *af_packet_node;
    int has_ips = 0;
    int has_ids = 0;

    /* Find initial node */
    af_packet_node = ConfGetNode("af-packet");
    if (af_packet_node == NULL) {
        return 0;
    }

    if_default = ConfNodeLookupKeyValue(af_packet_node, "interface", "default");

    for (ldev = 0; ldev < nlive; ldev++) {
        const char *live_dev = LiveGetDeviceName(ldev);
        if (live_dev == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
            return 0;
        }
        char *copymodestr = NULL;
        if_root = ConfFindDeviceConfig(af_packet_node, live_dev);

        if (if_root == NULL) {
            if (if_default == NULL) {
                SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
                return 0;
            }
            if_root = if_default;
        }

        if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) {
            if (strcmp(copymodestr, "ips") == 0) {
                has_ips = 1;
            } else {
                has_ids = 1;
            }
        } else {
            has_ids = 1;
        }
    }

    if (has_ids && has_ips) {
        SCLogInfo("AF_PACKET mode using IPS and IDS mode");
        for (ldev = 0; ldev < nlive; ldev++) {
            const char *live_dev = LiveGetDeviceName(ldev);
            if (live_dev == NULL) {
                SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
                return 0;
            }
            if_root = ConfNodeLookupKeyValue(af_packet_node, "interface", live_dev);
            char *copymodestr = NULL;

            if (if_root == NULL) {
                if (if_default == NULL) {
                    SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
                    return 0;
                }
                if_root = if_default;
            }

            if (! ((ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) &&
                        (strcmp(copymodestr, "ips") == 0))) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "AF_PACKET IPS mode used and interface '%s' is in IDS or TAP mode. "
                        "Sniffing '%s' but expect bad result as stream-inline is activated.",
                        live_dev, live_dev);
            }
        }
    }

    return has_ips;
}

#endif


int RunModeIdsAFPAutoFp(void)
{
    SCEnter();

/* We include only if AF_PACKET is enabled */
#ifdef HAVE_AF_PACKET
    int ret;
    char *live_dev = NULL;

    RunModeInitialize();

    TimeModeSetLive();

    (void)ConfGet("af-packet.live-interface", &live_dev);

    SCLogDebug("live_dev %s", live_dev);

    if (AFPPeersListInit() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Unable to init peers list.");
        exit(EXIT_FAILURE);
    }

    ret = RunModeSetLiveCaptureAutoFp(ParseAFPConfig,
                              AFPConfigGeThreadsCount,
                              "ReceiveAFP",
                              "DecodeAFP", thread_name_autofp,
                              live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    /* In IPS mode each threads must have a peer */
    if (AFPPeersListCheck() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Some IPS capture threads did not peer.");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("RunModeIdsAFPAutoFp initialised");
#endif /* HAVE_AF_PACKET */

    SCReturnInt(0);
}

/**
 * \brief Single thread version of the AF_PACKET processing.
 */
int RunModeIdsAFPSingle(void)
{
    SCEnter();
#ifdef HAVE_AF_PACKET
    int ret;
    char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("af-packet.live-interface", &live_dev);

    if (AFPPeersListInit() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Unable to init peers list.");
        exit(EXIT_FAILURE);
    }

    ret = RunModeSetLiveCaptureSingle(ParseAFPConfig,
                                    AFPConfigGeThreadsCount,
                                    "ReceiveAFP",
                                    "DecodeAFP", thread_name_single,
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    /* In IPS mode each threads must have a peer */
    if (AFPPeersListCheck() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Some IPS capture threads did not peer.");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("RunModeIdsAFPSingle initialised");

#endif /* HAVE_AF_PACKET */
    SCReturnInt(0);
}

/**
 * \brief Workers version of the AF_PACKET processing.
 *
 * Start N threads with each thread doing all the work.
 *
 */
int RunModeIdsAFPWorkers(void)
{
    SCEnter();
#ifdef HAVE_AF_PACKET
    int ret;
    char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("af-packet.live-interface", &live_dev);

    if (AFPPeersListInit() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Unable to init peers list.");
        exit(EXIT_FAILURE);
    }

    ret = RunModeSetLiveCaptureWorkers(ParseAFPConfig,
                                    AFPConfigGeThreadsCount,
                                    "ReceiveAFP",
                                    "DecodeAFP", thread_name_workers,
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    /* In IPS mode each threads must have a peer */
    if (AFPPeersListCheck() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Some IPS capture threads did not peer.");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("RunModeIdsAFPWorkers initialised");

#endif /* HAVE_AF_PACKET */
    SCReturnInt(0);
}

/**
 * @}
 */
