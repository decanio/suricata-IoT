/* Copyright (C) 2015 Open Information Security Foundation
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
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author Tom DeCanio <decanio.tom@gmail.com>
 *
 * Decodes IEEE 802.15.4 Wireless PAN
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-template.h"

#include "util-unittest.h"
#include "util-debug.h"

static void DecodeIEEE802154HasPanId(IEEE802154FCF *fcf, uint32_t *has_src_pan_id, uint32_t *has_dest_pan_id)
{
    uint32_t src_pan_id = 0;
    uint32_t dest_pan_id = 0;

    if(fcf == NULL) {
        return;
    }

    if(fcf->frame_version == IEEE802154_IEEE802154E_2012) {
        if(!fcf->panid_compression) {
            /* Compressed PAN ID == no PAN ID at all */
            if(fcf->dest_addr_mode == fcf->dest_addr_mode) {
                /* No address or both addresses: include destination PAN ID */
                dest_pan_id = 1;
            } else if(fcf->dest_addr_mode) {
                /* Only dest address, include dest PAN ID */
                dest_pan_id = 1;
            } else if(fcf->src_addr_mode) {
                /* Only src address, include src PAN ID */
                src_pan_id = 1;
            }
        }
        if(fcf->dest_addr_mode == 0 && fcf->dest_addr_mode == 1) {
            /* No address included, include dest PAN ID conditionally */
            if(!fcf->panid_compression) {
                dest_pan_id = 1;
            }
        }
        /* Remove the following rule the day rows 2 and 3 from table 2a are fixed: */
        if(fcf->dest_addr_mode == 0 && fcf->dest_addr_mode == 0) {
            /* Not meaningful, we include a PAN ID iff the compress flag is set, but
             * this is what the standard currently stipulates */
            dest_pan_id = fcf->panid_compression;
        }
    } else {
        /* No PAN ID in ACK */
        if(fcf->frame_type != IEEE802154_ACKFRAME) {
            if(!fcf->panid_compression && fcf->src_addr_mode & 3) {
                /* If compressed, don't inclue source PAN ID */
                src_pan_id = 1;
            }
            if(fcf->dest_addr_mode & 3) {
                dest_pan_id = 1;
            }
        }
    }

    if(has_src_pan_id != NULL) {
        *has_src_pan_id = src_pan_id;
    }
    if(has_dest_pan_id != NULL) {
        *has_dest_pan_id = dest_pan_id;
    }
}

/**
 * \brief Function to decode XXX packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

int DecodeIEEE802Dot15Dot4(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    IEEE802154FCF fcf;
    uint16_t hdr_len;
    uint32_t has_src_panid, has_dest_panid;

    StatsIncr(tv, dtv->counter_ieee802154);

    /* Validation: make sure that the input data is big enough to hold
     *             the header */
    if (len < IEEE802_15_4_MIN_HDR_SIZE) {
        /* in case of errors, we set events. Events are defined in
         * decode-events.h, and are then exposed to the detection
         * engine through detect-engine-events.h */
        //ENGINE_SET_EVENT(p,TEMPLATE_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    /* Now we can access the header */
#if 1
    fcf.frame_type = pkt[0] & 7;
    fcf.security_enabled = (pkt[0] >> 3) & 1;
    fcf.frame_pending = (pkt[0] >> 4) & 1;
    fcf.ack_required = (pkt[0] >> 5) & 1;
    fcf.panid_compression = (pkt[0] >> 6) & 1;

    fcf.sequence_number_suppression = pkt[1] & 1;
    fcf.ie_list_present = (pkt[1] >> 1) & 1;
    fcf.dest_addr_mode = (pkt[1] >> 2) & 3;
    fcf.frame_version = (pkt[1] >> 4) & 3;
    fcf.src_addr_mode = (pkt[1] >> 6) & 3;
    
    p->ieee802154vars.fcf = fcf;
    
    uint8_t *ptr = &pkt[2];

    hdr_len = 2;

    if (fcf.sequence_number_suppression == 0) {
        p->ieee802154vars.seq = ptr[0];
        hdr_len += 1;
        ptr++;
    }

    DecodeIEEE802154HasPanId(&fcf, &has_src_panid, &has_dest_panid);
    
    /* clear addresses */
    memset(&p->ieee802154vars.dest_addr, 0, sizeof(p->ieee802154vars.dest_addr));
    memset(&p->ieee802154vars.src_addr, 0, sizeof(p->ieee802154vars.src_addr));

    if (fcf.dest_addr_mode) {
        if (has_dest_panid) {
            p->ieee802154vars.dest_pid = ptr[0] + (ptr[1] << 8);
            ptr += 2;
            hdr_len += 2;
        } else {
            p->ieee802154vars.dest_pid = 0;
        }

        if (fcf.dest_addr_mode == IEEE802154_SHORTADDRMODE) {
            p->ieee802154vars.dest_addr[0] = ptr[1];
            p->ieee802154vars.dest_addr[1] = ptr[0];
            ptr += 2;
            hdr_len += 2;
        } else if (fcf.dest_addr_mode == IEEE802154_LONGADDRMODE) {
            uint32_t c;
            for(c = 0; c < 8; c++) {
                p->ieee802154vars.dest_addr[c] = ptr[7 - c];
            }
            ptr += 8;            
            hdr_len += 8;
        }
    } else {
        p->ieee802154vars.dest_pid = 0;
    }

    if (fcf.src_addr_mode) {
        if (has_src_panid) {
            p->ieee802154vars.src_pid = ptr[0] + (ptr[1] << 8);
            ptr += 2;
            hdr_len += 2;
        } else {
            p->ieee802154vars.src_pid = p->ieee802154vars.dest_pid;
        }

        if (fcf.src_addr_mode == IEEE802154_SHORTADDRMODE) {
            p->ieee802154vars.src_addr[0] = ptr[1];
            p->ieee802154vars.src_addr[1] = ptr[0];
            ptr += 2;           
            hdr_len += 2;
        } else if (fcf.src_addr_mode == IEEE802154_LONGADDRMODE) {
            uint32_t c;
            for(c = 0; c < 8; c++) {
                p->ieee802154vars.src_addr[c] = ptr[7 - c];
            }
            ptr += 8;  
            hdr_len += 8;
        }
    } else {
        p->ieee802154vars.src_pid = 0;
    }

    if (fcf.frame_type == IEEE802154_DATAFRAME) {
        if (Decode6LoWPAN(tv, dtv, p, (uint8_t *)pkt + hdr_len, len - hdr_len, pq) == TM_ECODE_OK)
            return TM_ECODE_OK;
        else if (DecodeZigBee(tv, dtv, p, (uint8_t *)pkt + hdr_len, len - hdr_len, pq) == TM_ECODE_OK)
            return TM_ECODE_OK;
        else
            return TM_ECODE_FAILED;
    } else {
        ENGINE_SET_EVENT(p,IEEE802154_UNSUPPORTED_PROTOCOL);
        return TM_ECODE_FAILED;
    }
#else
    const TemplateHdr *hdr = (const TemplateHdr *)pkt;

    /* lets assume we have UDP encapsulated */
    if (hdr->proto == 17) {
        /* we need to pass on the pkt and it's length minus the current
         * header */
        size_t hdr_len = sizeof(TemplateHdr);

        /* in this example it's clear that hdr_len can't be bigger than
         * 'len', but in more complex cases checking that we can't underflow
         * len is very important
        if (hdr_len < len) {
         */

        /* invoke the next decoder on the remainder of the data */
        return DecodeUDP(tv, dtv, p, (uint8_t *)pkt + hdr_len, len - hdr_len, pq);
        //}
    } else {
        //ENGINE_SET_EVENT(p,TEMPLATE_UNSUPPORTED_PROTOCOL);
        return TM_ECODE_FAILED;
    }
#endif

    return TM_ECODE_OK;
}

/**
 * @}
 */
