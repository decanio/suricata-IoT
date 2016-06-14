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

#ifndef __DECODE_IEEE_802_15_4_H__
#define __DECODE_IEEE_802_15_4_H__

#include "decode.h"
#include "threadvars.h"

#define ETHERNET_TYPE_802154       0x809a

#define IEEE802154_BEACONFRAME     0x00
#define IEEE802154_DATAFRAME       0x01
#define IEEE802154_ACKFRAME        0x02
#define IEEE802154_CMDFRAME        0x03

#define IEEE802154_BEACONREQ       0x07

#define IEEE802154_RESERVED        0x00
#define IEEE802154_NOADDR          0x00      /**< Only valid for ACK or Beacon frames. */
#define IEEE802154_SHORTADDRMODE   0x02
#define IEEE802154_LONGADDRMODE    0x03

#define IEEE802154_NOBEACONS       0x0F

#define IEEE802154_BROADCASTADDR   0xFFFF
#define IEEE802154_BROADCASTPANDID 0xFFFF

#define IEEE802154_IEEE802154_2003  0x00
#define IEEE802154_IEEE802154_2006  0x01
#define IEEE802154_IEEE802154E_2012 0x02

#define IEEE802154_SECURITY_LEVEL_NONE        0
#define IEEE802154_SECURITY_LEVEL_MIC_32      1
#define IEEE802154_SECURITY_LEVEL_MIC_64      2
#define IEEE802154_SECURITY_LEVEL_MIC_128     3
#define IEEE802154_SECURITY_LEVEL_ENC         4
#define IEEE802154_SECURITY_LEVEL_ENC_MIC_32  5
#define IEEE802154_SECURITY_LEVEL_ENC_MIC_64  6
#define IEEE802154_SECURITY_LEVEL_ENC_MIC_128 7

#define IEEE802154_IMPLICIT_KEY               0
#define IEEE802154_1_BYTE_KEY_ID_MODE         1
#define IEEE802154_5_BYTE_KEY_ID_MODE         2
#define IEEE802154_9_BYTE_KEY_ID_MODE         3

typedef struct IEEE802154FCF_ {
    uint8_t frame_type;        /**< 3 bit. Frame type field, see 802.15.4 */
    uint8_t security_enabled;  /**< 1 bit. True if security is used in this frame */
    uint8_t frame_pending;     /**< 1 bit. True if sender has more data to send */
    uint8_t ack_required;      /**< 1 bit. Is an ack frame required? */
    uint8_t panid_compression; /**< 1 bit. Is this a compressed header? */
    /*   uint8_t reserved; */  /**< 1 bit. Unused bit */
    uint8_t sequence_number_suppression; /**< 1 bit. Does the header omit sequence number?, see 802.15.4e */
    uint8_t ie_list_present;   /**< 1 bit. Does the header contain Information Elements?, see 802.15.4e */
    uint8_t dest_addr_mode;    /**< 2 bit. Destination address mode, see 802.15.4 */
    uint8_t frame_version;     /**< 2 bit. 802.15.4 frame version */
    uint8_t src_addr_mode;     /**< 2 bit. Source address mode, see 802.15.4 */
} IEEE802154FCF;

#if 0
typedef struct IEEE802154Hdr_ {
    uint16_t frame_control;
    uint8_t seq_number;
    uint16_t dest_pan_id;
    uint8_t dest_addr[8];
    uint16_t src_pan_id;
    uint8_t src_addr[8];
} __attribute__((__packed__)) IEEE802154Hdr;
#endif

typedef struct IEEE802154Vars_ {
  uint8_t dest_addr[8];           /**< Destination address */
  uint8_t src_addr[8];            /**< Source address */
  IEEE802154FCF fcf;              /**< Frame control field  */
  uint8_t seq;                    /**< Sequence number */
  uint16_t dest_pid;              /**< Destination PAN ID */
  uint16_t src_pid;               /**< Source PAN ID */    
} IEEE802154Vars;

#define IEEE802_15_4_MIN_HDR_SIZE 2

#endif /* __DECODE_IEEE_802_15_4_H__ */
