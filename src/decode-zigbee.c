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
 * \author Tom DeCanio <decanio/tom@gmail.com>
 *
 * Decodes ZigBee over low power wireless
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-zigbee.h"

#include "util-unittest.h"
#include "util-debug.h"

/**
 * \brief Function to decode XXX packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

int DecodeZigBee(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                 uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    int rc = TM_ECODE_FAILED;
    ZigBeeFCF fcf;

    /* Validation: make sure that the input data is big enough to hold
     *             the header */
    if (len < sizeof(ZigBeeHdr)) {
        /* in case of errors, we set events. Events are defined in
         * decode-events.h, and are then exposed to the detection
         * engine through detect-engine-events.h */
        //ENGINE_SET_EVENT(p,TEMPLATE_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    /* Now we can access the header */
    const ZigBeeHdr *hdr = (const ZigBeeHdr *)pkt;
    
    uint16_t frame_control = hdr->frame_control;
    
    fcf.frame_type = frame_control;
    fcf.protocol_version = frame_control >> 2;
    fcf.discover_route = frame_control >> 6;
    fcf.multicast = frame_control >> 8;
    fcf.security = frame_control >> 9;
    fcf.source_route = frame_control >> 10;
    fcf.extended_dest = frame_control >> 11;
    fcf.extended_source = frame_control >> 12;
    
    if (fcf.frame_type == ZIGBEE_FRAMETYPE_DATA ||
        fcf.frame_type == ZIGBEE_FRAMETYPE_NWK_COMMAND ||
        fcf.frame_type == ZIGBEE_FRAMETYPE_INTERPAN) {
        p->zigbeeh = (ZigBeeHdr *)pkt;
        p->zigbeevars.frame_type = fcf.frame_type;
        p->zigbeevars.version = fcf.protocol_version;
        p->zigbeevars.multicast = fcf.multicast;
        p->zigbeevars.security = fcf.security;
        p->zigbeevars.dest_address = p->zigbeeh->dest_address;
        p->zigbeevars.source_address = p->zigbeeh->source_address;
        
        uint8_t *ptr = pkt + sizeof(ZigBeeHdr);
        if (fcf.extended_dest) {
            memcpy(&p->zigbeevars.extended_dest_address, ptr, 
                   sizeof(p->zigbeevars.extended_dest_address));
            ptr += sizeof(p->zigbeevars.extended_dest_address);
        }
        if (fcf.extended_source) {
            memcpy(&p->zigbeevars.extended_source_address, ptr, 
                   sizeof(p->zigbeevars.extended_source_address));   
            ptr += sizeof(p->zigbeevars.extended_source_address);         
        }
        
        if (fcf.security) {
            uint32_t key_id;
            
            key_id = ((*ptr)>>3) & 0x3;
            
            if (key_id == 0x01) {
                memcpy(&p->zigbeevars.extended_source_address_security, 
                       ptr + offsetof(ZigBeeSecurityHdr, extended_source_address), 
                       sizeof(p->zigbeevars.extended_source_address_security));
                p->zigbeevars.extended_source_security = 1;
                pkt += sizeof(ZigBeeSecurityHdr);
                rc = TM_ECODE_OK;
            }
        } else {
            rc = TM_ECODE_OK;
        }
    }
    
    /* if everything about the packet looked like ZigBee then count it */
    if (rc == TM_ECODE_OK) {
        p->proto = PROTO_ZIGBEE;
        FlowHandlePacket(tv, dtv, p);
        StatsIncr(tv, dtv->counter_zigbee);
    }
    
    return rc;
}

/**
 * @}
 */
