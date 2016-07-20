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
#include "util-print.h"

//#define PRINT

/* Precomputed partial CRC table. */
static const uint16_t    crc_tabccitt[256] = {
    0x0000,  0x1021,  0x2042,  0x3063,  0x4084,  0x50a5,  0x60c6,  0x70e7,
    0x8108,  0x9129,  0xa14a,  0xb16b,  0xc18c,  0xd1ad,  0xe1ce,  0xf1ef,
    0x1231,  0x0210,  0x3273,  0x2252,  0x52b5,  0x4294,  0x72f7,  0x62d6,
    0x9339,  0x8318,  0xb37b,  0xa35a,  0xd3bd,  0xc39c,  0xf3ff,  0xe3de,
    0x2462,  0x3443,  0x0420,  0x1401,  0x64e6,  0x74c7,  0x44a4,  0x5485,
    0xa56a,  0xb54b,  0x8528,  0x9509,  0xe5ee,  0xf5cf,  0xc5ac,  0xd58d,
    0x3653,  0x2672,  0x1611,  0x0630,  0x76d7,  0x66f6,  0x5695,  0x46b4,
    0xb75b,  0xa77a,  0x9719,  0x8738,  0xf7df,  0xe7fe,  0xd79d,  0xc7bc,
    0x48c4,  0x58e5,  0x6886,  0x78a7,  0x0840,  0x1861,  0x2802,  0x3823,
    0xc9cc,  0xd9ed,  0xe98e,  0xf9af,  0x8948,  0x9969,  0xa90a,  0xb92b,
    0x5af5,  0x4ad4,  0x7ab7,  0x6a96,  0x1a71,  0x0a50,  0x3a33,  0x2a12,
    0xdbfd,  0xcbdc,  0xfbbf,  0xeb9e,  0x9b79,  0x8b58,  0xbb3b,  0xab1a,
    0x6ca6,  0x7c87,  0x4ce4,  0x5cc5,  0x2c22,  0x3c03,  0x0c60,  0x1c41,
    0xedae,  0xfd8f,  0xcdec,  0xddcd,  0xad2a,  0xbd0b,  0x8d68,  0x9d49,
    0x7e97,  0x6eb6,  0x5ed5,  0x4ef4,  0x3e13,  0x2e32,  0x1e51,  0x0e70,
    0xff9f,  0xefbe,  0xdfdd,  0xcffc,  0xbf1b,  0xaf3a,  0x9f59,  0x8f78,
    0x9188,  0x81a9,  0xb1ca,  0xa1eb,  0xd10c,  0xc12d,  0xf14e,  0xe16f,
    0x1080,  0x00a1,  0x30c2,  0x20e3,  0x5004,  0x4025,  0x7046,  0x6067,
    0x83b9,  0x9398,  0xa3fb,  0xb3da,  0xc33d,  0xd31c,  0xe37f,  0xf35e,
    0x02b1,  0x1290,  0x22f3,  0x32d2,  0x4235,  0x5214,  0x6277,  0x7256,
    0xb5ea,  0xa5cb,  0x95a8,  0x8589,  0xf56e,  0xe54f,  0xd52c,  0xc50d,
    0x34e2,  0x24c3,  0x14a0,  0x0481,  0x7466,  0x6447,  0x5424,  0x4405,
    0xa7db,  0xb7fa,  0x8799,  0x97b8,  0xe75f,  0xf77e,  0xc71d,  0xd73c,
    0x26d3,  0x36f2,  0x0691,  0x16b0,  0x6657,  0x7676,  0x4615,  0x5634,
    0xd94c,  0xc96d,  0xf90e,  0xe92f,  0x99c8,  0x89e9,  0xb98a,  0xa9ab,
    0x5844,  0x4865,  0x7806,  0x6827,  0x18c0,  0x08e1,  0x3882,  0x28a3,
    0xcb7d,  0xdb5c,  0xeb3f,  0xfb1e,  0x8bf9,  0x9bd8,  0xabbb,  0xbb9a,
    0x4a75,  0x5a54,  0x6a37,  0x7a16,  0x0af1,  0x1ad0,  0x2ab3,  0x3a92,
    0xfd2e,  0xed0f,  0xdd6c,  0xcd4d,  0xbdaa,  0xad8b,  0x9de8,  0x8dc9,
    0x7c26,  0x6c07,  0x5c64,  0x4c45,  0x3ca2,  0x2c83,  0x1ce0,  0x0cc1,
    0xef1f,  0xff3e,  0xcf5d,  0xdf7c,  0xaf9b,  0xbfba,  0x8fd9,  0x9ff8,
    0x6e17,  0x7e36,  0x4e55,  0x5e74,  0x2e93,  0x3eb2,  0x0ed1,  0x1ef0
};

/* Table of bytes with reverse bits */
/* Necessary for CRC generation because the CRC is generated from the bits ordered as
 * they are transmitted over the air. But, IEEE 802.15.4 transmits the least signficant
 * bits first. */
static const uint8_t rev_bitorder_table[256] = {
    0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
    0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8, 0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
    0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4, 0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
    0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec, 0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
    0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2, 0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
    0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea, 0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
    0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6, 0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
    0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee, 0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
    0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1, 0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
    0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9, 0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
    0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5, 0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
    0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed, 0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
    0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3, 0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
    0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb, 0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
    0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7, 0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
    0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef, 0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff,
};
#define REV_BITS(byte)    rev_bitorder_table[byte]

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      update_crc_ccitt
 *  DESCRIPTION
 *      Computes the 16-bit CCITT CRC according to the previous CRC, and the byte to add
 *  PARAMETERS
 *      guint16 crc - previous CRC value
 *      guint8  c   - the next byte to calculate with
 *  RETURNS
 *      guint16     - the updated 16-bit CRC.
 *---------------------------------------------------------------
 *  This function was adapted from Lammert Bies's free software library
 *  http://www.lammertbies.nl/comm/software/index.html
 *---------------------------------------------------------------
 *  Also, the crc table this function refers to was generated using
 *  functions from Lammert Bies's free software library and the CCITT
 *  polynomial of x^16 + x^12 + x^5 + x (0x1021)
 *---------------------------------------------------------------
 */
static uint16_t UpdateCrcCCITT( uint16_t crc, uint8_t c ) {

    uint16_t tmp, short_c;

    short_c  = 0x00ff & (uint16_t) c;
    tmp = (crc >> 8) ^ short_c;
    crc = (crc << 8) ^ crc_tabccitt[tmp];

    return crc;
}  /* UpdateCrcCCITT */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      ieee802154_crc16
 *  DESCRIPTION
 *      Computes the 16-bit CRC according to the CCITT/ITU-T Standard
 *
 *      NOTE: bit-reversal within bytes is necessary because IEEE 802.15.4
 *            CRC is calculated on the packet in the order the bits are
 *            being sent, which is least-significan bit first.
 *  PARAMETERS
 *      tvbuff_t *tvb   - pointer to buffer containing raw packet.
 *      guint           - offset to the beginning of where to calculate the CRC from
 *      guint           - number of bytes over which to calculate the CRC
 *  RETURNS
 *      guint16
 *---------------------------------------------------------------
 */
static uint16_t IEEE802154_CRC16(uint8_t *tvb, uint32_t offset, uint32_t len)
{
    uint32_t   i;
    uint16_t crc = 0x0000;
    for(i=0;i<len;i++){
        //crc = update_crc_ccitt(crc, REV_BITS(tvb_get_guint8(tvb, offset+i)));
        crc = UpdateCrcCCITT(crc, REV_BITS(tvb[offset+i]));
    }

    /*  Need to reverse the 16-bit field so that it agrees with the spec. */
    return REV_BITS((crc&0xff00)>>8) + (REV_BITS(crc&0x00ff)<<8);
} /* IEEE802154_CRC16 */

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
 * \brief Function to decode 802.15.4 packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

static int _DecodeIEEE802154(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                             uint8_t *pkt, uint16_t len, PacketQueue *pq, int fcs)
{
    IEEE802154FCF fcf;
    uint16_t hdr_len;
    uint32_t has_src_panid, has_dest_panid;

    StatsIncr(tv, dtv->counter_ieee802154);

#ifdef PRINT
    printf("raw 802.15.4 %s FCS-----(pcap_cnt: %lu)\n", (fcs)?"":"no", p->pcap_cnt);
    PrintRawDataFp(stdout, GET_PKT_DATA(p), GET_PKT_LEN(p));
    printf("-------------------------\n");
#endif

    /* Validation: make sure that the input data is big enough to hold
     *             the header */
    if (len < IEEE802_15_4_MIN_HDR_SIZE) {
        /* in case of errors, we set events. Events are defined in
         * decode-events.h, and are then exposed to the detection
         * engine through detect-engine-events.h */
        //ENGINE_SET_EVENT(p,TEMPLATE_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (fcs) {
        uint16_t expected_crc = IEEE802154_CRC16(pkt, 0, len-2);
        uint16_t packet_crc = pkt[len-1] << 8 | pkt[len-2];

        if (expected_crc != packet_crc) {
            ENGINE_SET_EVENT(p, IEEE802154_BAD_CRC16);
            return TM_ECODE_FAILED;
        }
        len -= 2;
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
 * \brief Function to decode 802.15.4 packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

int DecodeIEEE802154(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                     uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    return _DecodeIEEE802154(tv, dtv, p, pkt, len, pq, TRUE);
}

/**
 * \brief Function to decode 802.15.4 packets without trailing FCS
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

int DecodeIEEE802154NoFCS(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                          uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    return _DecodeIEEE802154(tv, dtv, p, pkt, len, pq, FALSE);
}

/**
 * @}
 */
