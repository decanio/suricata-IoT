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
 * \file
 *
 * \author Tom DeCanio <decanio.tom@gmail.com> 
 *
 */

#ifndef __DECODE_ZIGBEE_H__
#define __DECODE_ZIGBEE_H__

#include "decode.h"
#include "threadvars.h"

#define ZIGBEE_FRAMETYPE_DATA        0x00
#define ZIGBEE_FRAMETYPE_NWK_COMMAND 0x01
#define ZIGBEE_FRAMETYPE_INTERPAN    0x03

/* ZigBee Header Frame Control Field information */
typedef struct ZigBeeFCF_ {
    uint16_t frame_type : 2;
    uint16_t protocol_version : 4;
    uint16_t discover_route : 2;
    uint16_t multicast : 1;
    uint16_t security : 1;
    uint16_t source_route : 1;
    uint16_t extended_dest : 1;
    uint16_t extended_source : 1;
} ZigBeeFCF;

typedef struct ZigBeeHdr_ {
    uint16_t frame_control;
    uint16_t dest_address;
    uint16_t source_address;
    uint8_t radius;
    uint8_t sequence_number;
} __attribute__((__packed__)) ZigBeeHdr;

typedef struct ZigBeeSecurityHdr_ {
    uint8_t  security_control_field;
    uint32_t frame_counter;
    uint8_t  extended_source_address[8];
} __attribute__((__packed__)) ZigBeeSecurityHdr;

typedef struct ZigBeeVars_ {
    uint16_t dest_address;
    uint16_t source_address;
    uint32_t version : 4;
    uint32_t frame_type : 2;
    uint32_t multicast : 1;
    uint32_t security : 1;
    uint32_t extended_source : 1;
    uint32_t extended_source_security : 1;
    uint32_t extended_dest : 1;
    uint8_t  extended_source_address[8];
    uint8_t  extended_dest_address[8];
    uint8_t  extended_source_address_security[8];
} ZigBeeVars;

#endif /* __DECODEZIGBEE_H__ */
