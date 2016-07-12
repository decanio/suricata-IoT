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
 * Decodes 6LowPAN IPv6 over low power wireless
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-template.h"

#include "util-unittest.h"
#include "util-debug.h"
#include "util-print.h"

#include "tmqh-packetpool.h"

#define PRINT

typedef struct IPHCHeader_ {
    uint32_t pattern : 3;
    uint32_t tc_flow : 2;
    uint32_t next_hdr : 1;
    uint32_t hop_limit : 2;
    uint32_t ctx_id_ext : 1;
    uint32_t src_comp : 1;
    uint32_t src_mode : 2;
    uint32_t mcast_comp : 1;
    uint32_t dst_comp : 1;
    uint32_t dst_mode : 2;
} IPHCHeader;

typedef struct Frag1Header_ {
    uint32_t type : 5;
    uint32_t dgram_size : 11;
    uint32_t dgram_tag : 16;
} Frag1Header;

typedef struct FragNHeader_ {
    uint32_t type: 5;
    uint32_t dgram_size : 11;
    uint32_t dgram_tag : 16;
    uint32_t dgram_offset : 8;
} FragNHeader;

static int Decode6LoWPANIPv6(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                             uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
#ifdef PRINT
    printf("raw 6LoWPAN-----(pcap_cnt: %lu)\n", p->pcap_cnt);
    PrintRawDataFp(stdout, GET_PKT_DATA(p), GET_PKT_LEN(p));
    printf("-------------------------\n");
#endif
    return DecodeIPV6(tv, dtv, p, pkt, len, pq);
}

static int Decode6LoWPANHC1(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                             uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    return TM_ECODE_OK;
}

#define IPV6_SET_RAW_CLASS(ip6h, value)   {uint32_t t = (ip6h)->s_ip6_flow; t |= (htonl(0x0FF00000 & (value << 20))); (ip6h)->s_ip6_flow = t;}
#define IPV6_SET_RAW_FLOW(ip6h, value)   {uint32_t t = (ip6h)->s_ip6_flow; t |= (htonl(0x000FFFFF) & value); (ip6h)->s_ip6_flow = t;}
#define IPV6_SET_RAW_HLIM(ip6h, value)   ((ip6h)->s_ip6_hlim = value)
#define IPV6_SET_RAW_PLEN(ip6h, value)   ((ip6h)->s_ip6_plen = value)

#if 1
static void breakpoint_6lowpan(void)
{
    printf("breakpoint\n");
}
#endif

static int Decode6LoWPANIPHC(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                             uint8_t *pkt, uint16_t len, uint16_t dgram_len, PacketQueue *pq, Packet *rp)
{
    uint8_t iphc0, iphc1;
    IPHCHeader iphc;
    uint16_t ofs = 2;
    uint16_t payload_len;
    uint32_t from_wire = (rp == NULL);
    
#ifdef PRINT
#if 0
    printf("compressed 6LoWPAN-----(pcap_cnt: %lu)\n", p->pcap_cnt);
    PrintRawDataFp(stdout, pkt, len);
    printf("-------------------------\n");
#endif
#endif    
    if (from_wire)
        payload_len = len - ofs /*- 2 fcs */;    
    else
        payload_len = dgram_len - sizeof(IPV6Hdr);

    if (from_wire) {
        /* Allocate a Packet for the reassembled packet.  On failure we
         * SCFree all the resources held by this tracker. */
        rp = Packet6LoWPANPktSetup(p, NULL, 0);
        if (rp == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate packet for "
                       "6LoWPAN decompression.");
            return TM_ECODE_OK;
        }
    }
    PKT_SET_SRC(rp, PKT_SRC_6LOWPAN);
    rp->recursion_level = p->recursion_level;

    /* at least two byte will be used for the encoding */
    //uint8_t *hc06_ptr = &pkt[2];

    iphc0 = pkt[0];
    iphc1 = pkt[1];

    iphc.pattern = iphc0 >> 5;
    iphc.tc_flow = iphc0 >> 3;
    iphc.next_hdr = iphc0 >> 2;
    iphc.hop_limit = iphc0;
    iphc.ctx_id_ext = iphc1 >> 7;
    iphc.src_comp = iphc1 >> 6;
    iphc.src_mode = iphc1 >> 4;
    iphc.mcast_comp = iphc1 >> 3;
    iphc.dst_comp = iphc1 >> 2;
    iphc.dst_mode = iphc1;

#if 0
    /* another if the CID flag is set */
    if (iphc1 & SICSLOWPAN_IPHC_CID) {
        SCLogDebug("IPHC: CID flag set - increase header with one");
        hc06_ptr++;
    }
#endif

    IPV6Hdr ipv6hdr;
    memset(&ipv6hdr, 0, sizeof(ipv6hdr));

    /*
    if (p->pcap_cnt == 15525)
        breakpoint_6lowpan();
    */
        
    IPV6_SET_RAW_VER(&ipv6hdr, 6);
    
    if (iphc.tc_flow == 0x00) {
        uint32_t tmp;
        
        tmp = pkt[ofs + 1] << 16 |
              pkt[ofs + 2] << 8 |
              pkt[ofs + 3];
        IPV6_SET_RAW_FLOW(&ipv6hdr, htonl(tmp));
        IPV6_SET_RAW_CLASS(&ipv6hdr, pkt[ofs] << 2);
        if (from_wire)
            payload_len -= 4;
        len -= 4;
        ofs += 4;
    } else if (iphc.tc_flow == 0x01) {
        uint32_t tmp;
        
        tmp = pkt[ofs] << 16 |
              pkt[ofs + 1] << 8 |
              pkt[ofs + 2];
        IPV6_SET_RAW_FLOW(&ipv6hdr, htonl(tmp));
        if (from_wire)
            payload_len -= 3;
        len -= 3;
        ofs += 3;
    }
    
    if (iphc.ctx_id_ext) {
        if (from_wire)
            payload_len -= 1;
        len -= 1;
        ofs += 1;
    }
    
    if (iphc.next_hdr == 0) {
        /* inline */
        IPV6_SET_RAW_NH(&ipv6hdr, pkt[ofs]);
        if (from_wire)
            payload_len -= 1;
        len -= 1;
        ofs += 1;
    }
    
    switch (iphc.hop_limit) {
        case 0:
            IPV6_SET_RAW_HLIM(&ipv6hdr, pkt[ofs]);
            if (from_wire)
                payload_len -= 1;
            ofs += 1;
            break;
        case 1:
            IPV6_SET_RAW_HLIM(&ipv6hdr, 1);
            break;
        case 2:
            IPV6_SET_RAW_HLIM(&ipv6hdr, 64);
            break;
        case 3:
            IPV6_SET_RAW_HLIM(&ipv6hdr, 255);
            break;
    }

    if (iphc.dst_comp == 0) {
        if (iphc.dst_mode == 3) {
            if (iphc.mcast_comp == 1) {
                /* inline */
                ipv6hdr.s_ip6_dst[0] = ntohl(0xff020000);
                ipv6hdr.s_ip6_dst[1] = 0;
                ipv6hdr.s_ip6_dst[2] = 0;
                ipv6hdr.s_ip6_dst[3] = ntohl((uint32_t)pkt[ofs]);
                if (from_wire)
                    payload_len -= 1;
                ofs += 1;
            } else {
                if (p->ieee802154vars.fcf.dest_addr_mode == 0x02) {
                    /* short address mode */
                    uint32_t tmp;
                    
                    ipv6hdr.s_ip6_dst[0] = ntohl(0xfe800000);
                    ipv6hdr.s_ip6_dst[1] = 0;
                    ipv6hdr.s_ip6_dst[2] = htonl(0xff);
                    tmp = (0xfe << 24 |
                           0x00 << 16 |
                           p->ieee802154vars.dest_addr[0] << 8 |
                           p->ieee802154vars.dest_addr[1] << 0);
                    ipv6hdr.s_ip6_dst[3] = htonl(tmp);
                } else {
                    uint32_t tmp;
                    ipv6hdr.s_ip6_dst[0] = ntohl(0xfe800000);
                    ipv6hdr.s_ip6_dst[1] = 0;
                    tmp = ((p->ieee802154vars.dest_addr[0] ^ 0x02) << 24 |
                           p->ieee802154vars.dest_addr[1] << 16 |
                           p->ieee802154vars.dest_addr[2] << 8 |
                           p->ieee802154vars.dest_addr[3] << 0);
                    ipv6hdr.s_ip6_dst[2] = htonl(tmp);
                    tmp = (p->ieee802154vars.dest_addr[4] << 24 |
                           p->ieee802154vars.dest_addr[5] << 16 |
                           p->ieee802154vars.dest_addr[6] << 8 |
                           p->ieee802154vars.dest_addr[7] << 0);
                    ipv6hdr.s_ip6_dst[3] = htonl(tmp);
                }  
            }
        } else if (iphc.dst_mode == 1) {
                /* inline */
                uint32_t tmp;
                ipv6hdr.s_ip6_dst[0] = ntohl(0xff020000);
                ipv6hdr.s_ip6_dst[1] = 0;
                tmp = pkt[ofs + 1];
                ipv6hdr.s_ip6_dst[2] = htonl(tmp);
                tmp = pkt[ofs + 2] << 24 |
                      pkt[ofs + 3] << 16 |
                      pkt[ofs + 4] << 8 |
                      pkt[ofs + 5];
                ipv6hdr.s_ip6_dst[3] = htonl(tmp);
                if (from_wire)
                    payload_len -= 6;
                ofs += 6;            
        }
    } else {
        if (iphc.dst_mode == 1) {
            uint32_t tmp;
            ipv6hdr.s_ip6_dst[0] = 0;
            ipv6hdr.s_ip6_dst[1] = 0;
            tmp = (pkt[ofs+0] << 24 |
                   pkt[ofs+1] << 16 |
                   pkt[ofs+2] << 8 |
                   pkt[ofs+3] << 0);
            ipv6hdr.s_ip6_dst[2] = htonl(tmp);
            tmp = (pkt[ofs+4] << 24 |
                   pkt[ofs+5] << 16 |
                   pkt[ofs+6] << 8 |
                   pkt[ofs+7] << 0);
            ipv6hdr.s_ip6_dst[3] = htonl(tmp);
            if (from_wire)  
                payload_len -= 8; 
            ofs += 8;
       } else if (iphc.dst_mode == 3) {
           if (p->ieee802154vars.fcf.dest_addr_mode == 0x02) {
               /* short address mode */
               uint32_t tmp;
               ipv6hdr.s_ip6_dst[0] = 0;
               ipv6hdr.s_ip6_dst[1] = 0;
               ipv6hdr.s_ip6_dst[2] = htonl(0xff);
               tmp = (0xfe << 24 |
                      0x00 << 16 |
                      p->ieee802154vars.dest_addr[0] << 8 |
                      p->ieee802154vars.dest_addr[1] << 0);
               ipv6hdr.s_ip6_dst[3] = htonl(tmp);
           } else {
               uint32_t tmp;
               ipv6hdr.s_ip6_dst[0] = 0;
               ipv6hdr.s_ip6_dst[1] = 0;
               tmp = ((p->ieee802154vars.dest_addr[0] ^ 0x02) << 24 |
                      p->ieee802154vars.dest_addr[1] << 16 |
                      p->ieee802154vars.dest_addr[2] << 8 |
                      p->ieee802154vars.dest_addr[3] << 0);
               ipv6hdr.s_ip6_dst[2] = htonl(tmp);
               tmp = (p->ieee802154vars.dest_addr[4] << 24 |
                      p->ieee802154vars.dest_addr[5] << 16 |
                      p->ieee802154vars.dest_addr[6] << 8 |
                      p->ieee802154vars.dest_addr[7] << 0);
               ipv6hdr.s_ip6_dst[3] = htonl(tmp);
            }
        }
    }

    if (iphc.src_comp == 0) {
        if (iphc.src_mode == 3) {
            if (p->ieee802154vars.fcf.src_addr_mode == 0x02) {
                /* short address mode */
                uint32_t tmp;
                ipv6hdr.s_ip6_src[0] = ntohl(0xfe800000);
                ipv6hdr.s_ip6_src[1] = 0;
                ipv6hdr.s_ip6_src[2] = htonl(0xff);
                tmp = (0xfe << 24 |
                       0x00 << 16 |
                       p->ieee802154vars.src_addr[0] << 8|
                       p->ieee802154vars.src_addr[1] << 0);
                ipv6hdr.s_ip6_src[3] = htonl(tmp);
            } else {
                uint32_t tmp;
                ipv6hdr.s_ip6_src[0] = ntohl(0xfe800000);
                ipv6hdr.s_ip6_src[1] = 0;
                tmp = ((p->ieee802154vars.src_addr[0] ^ 0x02) << 24 |
                       p->ieee802154vars.src_addr[1] << 16 |
                       p->ieee802154vars.src_addr[2] << 8 |
                       p->ieee802154vars.src_addr[3] << 0);
                ipv6hdr.s_ip6_src[2] = htonl(tmp);
                tmp = (p->ieee802154vars.src_addr[4] << 24 |
                       p->ieee802154vars.src_addr[5] << 16 |
                       p->ieee802154vars.src_addr[6] << 8 |
                       p->ieee802154vars.src_addr[7] << 0);
                ipv6hdr.s_ip6_src[3] = htonl(tmp);
            }
        }
    } else {
       if (iphc.src_mode == 1) {
            uint32_t tmp;
            ipv6hdr.s_ip6_src[0] = 0;
            ipv6hdr.s_ip6_src[1] = 0;
            tmp = (pkt[ofs+0] << 24 |
                   pkt[ofs+1] << 16 |
                   pkt[ofs+2] << 8 |
                   pkt[ofs+3] << 0);
            ipv6hdr.s_ip6_src[2] = htonl(tmp);
            tmp = (pkt[ofs+4] << 24 |
                   pkt[ofs+5] << 16 |
                   pkt[ofs+6] << 8 |
                   pkt[ofs+7] << 0);
            ipv6hdr.s_ip6_src[3] = htonl(tmp);
            if (from_wire)  
                payload_len -= 8; 
            ofs += 8;
       } else if (iphc.src_mode == 3) {
           if (p->ieee802154vars.fcf.src_addr_mode == 0x02) {
               /* short address mode */
               uint32_t tmp;
               ipv6hdr.s_ip6_src[0] = 0;
               ipv6hdr.s_ip6_src[1] = 0;
               ipv6hdr.s_ip6_src[2] = htonl(0xff);
               tmp = (0xfe << 24 |
                      0x00 << 16 |
                      p->ieee802154vars.src_addr[0] << 8 |
                      p->ieee802154vars.src_addr[1] << 0);
               ipv6hdr.s_ip6_src[3] = htonl(tmp);
           } else {
               uint32_t tmp;
               ipv6hdr.s_ip6_src[0] = 0;
               ipv6hdr.s_ip6_src[1] = 0;
               tmp = ((p->ieee802154vars.src_addr[0] ^ 0x02) << 24 |
                      p->ieee802154vars.src_addr[1] << 16 |
                      p->ieee802154vars.src_addr[2] << 8 |
                      p->ieee802154vars.src_addr[3] << 0);
               ipv6hdr.s_ip6_src[2] = htonl(tmp);
               tmp = (p->ieee802154vars.src_addr[4] << 24 |
                      p->ieee802154vars.src_addr[5] << 16 |
                      p->ieee802154vars.src_addr[6] << 8 |
                      p->ieee802154vars.src_addr[7] << 0);
               ipv6hdr.s_ip6_src[3] = htonl(tmp);
           }
       }
    }
    IPV6_SET_RAW_PLEN(&ipv6hdr, htons(payload_len));

    /* header */
    PacketCopyDataOffset(rp,0,(uint8_t *)&ipv6hdr, sizeof(ipv6hdr));
    SET_PKT_LEN(rp, sizeof(ipv6hdr));

    /* payload */
    if (from_wire) {
        PacketCopyDataOffset(rp,GET_PKT_LEN(rp), &pkt[ofs], payload_len);
        SET_PKT_LEN(rp, GET_PKT_LEN(rp) + payload_len);
    } else {
        PacketCopyDataOffset(rp,GET_PKT_LEN(rp), &pkt[ofs], len);
        SET_PKT_LEN(rp, GET_PKT_LEN(rp) + len);   
    }
    rp->ip6h = (IPV6Hdr *)(GET_PKT_DATA(rp));

#ifdef PRINT
    printf("uncompressed 6LoWPAN-----(pcap_cnt: %lu)\n", p->pcap_cnt);
    PrintRawDataFp(stdout, GET_PKT_DATA(rp), GET_PKT_LEN(rp));
    printf("-------------------------\n");
#endif
    StatsIncr(tv, dtv->counter_6lowpan_uncompressed);
    if ((from_wire) && (pq != NULL)) {
        /* send to IPv6 decoder is this came direct from the "ether"
         * if this came from the fragment reassembler hold off sending to
         * the IPv6 decoder until fragment reassembly is complete
         */
        if (DecodeIPV6(tv, dtv, rp, (uint8_t *)rp->ip6h, GET_PKT_LEN(rp), pq) != TM_ECODE_OK) {
            TmqhOutputPacketpool(tv, rp);
        } else {
            PacketEnqueue(pq,rp);
        }
    }
    return TM_ECODE_OK;
}

static Packet *fragment_list = NULL;
static Packet *LookupFragment(Packet *p, uint16_t dgram_size, uint16_t dgram_tag)
{
#ifdef PRINT
    printf("LookupFragment tag: %x\n", dgram_tag);
#endif
    /* temporary hack */
    for (;;) {
    Packet *rp = fragment_list;
    if (rp == NULL) {
        /* Allocate a Packet for the reassembled packet.  On failure we
         * SCFree all the resources held by this tracker. */
        rp = Packet6LoWPANPktSetup(p, NULL, 0);
        if (rp == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate packet for "
                       "6LoWPAN reassembly.");
            return NULL;
        }
        memset(rp->sixlowpan_frag_map, 0, sizeof(rp->sixlowpan_frag_map));
        PKT_SET_SRC(rp, PKT_SRC_6LOWPAN);
        rp->recursion_level = p->recursion_level;
        rp->sixlowpan_frag_tag = dgram_tag;
        rp->flags |= PKT_IGNORE_CHECKSUM; /* HACK dont know why this is */
        fragment_list = rp;
#ifdef PRINT
        printf("returning new frag Packet %p\n", rp);
#endif
        return rp;
    } else {
        if (rp->sixlowpan_frag_tag == dgram_tag) {
            /* tags match */
#ifdef PRINT
            printf("returning existing Packet %p tag: %x\n", rp, dgram_tag);
#endif
            return rp;
        } else {
            /* need to free the old Packet */
#ifdef PRINT
            printf("fragment tag changed list_tag %x tag: %x\n", rp->sixlowpan_frag_tag, dgram_tag);
#endif
            fragment_list = NULL;
       }
    }
    }
}

static void RemoveFragment(Packet *p)
{
#ifdef PRINT
    printf("removing fragment %p\n", p);
    printf("fragment_list %p\n", fragment_list);
#endif
    if (fragment_list == p) {
        fragment_list = NULL;
    }
}

static inline void Set6LoWPANMapBit(Packet *p, uint32_t offset)
{
    if (offset < 1280) {
        uint32_t bitoffset = offset / 8;
        uint32_t word = bitoffset / 32;
        //printf("setting offset %u word %u bit %u mask %x\n", offset, word, bitoffset % 32, 1<<(bitoffset % 32));
        p->sixlowpan_frag_map[word] |= (1<<(bitoffset % 32));   
    }
}

static inline int IsSet6LoWPANMapBit(Packet *p, uint32_t offset)
{
    uint32_t bitoffset = offset / 8;
    uint32_t word = bitoffset / 32;
    //printf("checking offset %u word %u bit %u mask %x\n", offset, word, bitoffset % 32, 1<<(bitoffset % 32));
    //printf("mask %x\n", (p->sixlowpan_frag_map[word] & (1<<(bitoffset % 32))));
    return ((p->sixlowpan_frag_map[word] & (1<<(bitoffset % 32))) != 0);   
}

static int Enqueue6LoWPANReassembledPacket(ThreadVars *tv, DecodeThreadVars *dtv, 
                                           Packet *p, uint32_t dgram_size, PacketQueue *pq)
{
    uint32_t offset;
   
    /* check for fully reassembled packet */
#ifdef PRINT
    printf("checking through %d\n", dgram_size);
    printf("map %08x %08x %08x %08x %08x\n",
            p->sixlowpan_frag_map[0],
            p->sixlowpan_frag_map[1],
            p->sixlowpan_frag_map[2],
            p->sixlowpan_frag_map[3],
            p->sixlowpan_frag_map[4]);
#endif
    for (offset = 0; offset < dgram_size; offset += 8) {
        if (IsSet6LoWPANMapBit(p, offset) == 0) {
            /* not fully reassembled yet */
#ifdef PRINT
            printf("incomplete\n");
#endif
            return TM_ECODE_OK;
        }
    }
#ifdef PRINT
    printf("complete\n");
#endif

    RemoveFragment(p);
    
    if (pq) {
#ifdef PRINT
        printf("reassembled 6LoWPAN-----(pcap_cnt: %lu)\n", p->pcap_cnt);
        PrintRawDataFp(stdout, GET_PKT_DATA(p), GET_PKT_LEN(p));
        printf("-------------------------\n");
#endif
        StatsIncr(tv, dtv->counter_6lowpan_reassembled);
        /* send to IPv6 decoder is this came direct from the "ether"
         * if this came from the fragment reassembler hold off sending to
         * the IPv6 decoder until fragment reassembly is complete
         */
        if (DecodeIPV6(tv, dtv, p, (uint8_t *)p->ip6h, GET_PKT_LEN(p), pq) != TM_ECODE_OK) {
            TmqhOutputPacketpool(tv, p);
        } else {
            PacketEnqueue(pq,p);
        }
    }
    return TM_ECODE_OK;
}

static int Decode6LoWPANFrag1(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                             uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    uint8_t f1h0, f1h1, f1h2, f1h3;
    Frag1Header f1h;
    uint32_t offset;
    Packet *rp = NULL;
    
    StatsIncr(tv, dtv->counter_6lowpan_fragment);
   
    f1h0 = pkt[0];
    f1h1 = pkt[1];
    f1h2 = pkt[2];
    f1h3 = pkt[3];

    f1h.type= f1h0 >> 3;
    f1h.dgram_size = ((f1h0 & 0x7) << 8) | f1h1;
    f1h.dgram_tag = (f1h2 << 8) | f1h3;

#ifdef PRINT       
    printf("6LoWPAN fragment 1 tag: %x size: %d len: %d\n", f1h.dgram_tag, f1h.dgram_size, len); 
    PrintRawDataFp(stdout, pkt, len);
    if (f1h.dgram_tag == 0x31d)
        breakpoint_6lowpan();
#endif
    
    rp = LookupFragment(p, f1h.dgram_size, f1h.dgram_tag);
    
    if (rp == NULL) {
        return TM_ECODE_OK;
    }
 
    const SixLoWPANHdr *hdr = (const SixLoWPANHdr *)&pkt[4];
    if ((hdr->dispatch & 0xe0) ==  SIXLOWPAN_DISPATCH_IPHC) {
#ifdef PRINT       
        printf("6LoWPAN fragment is IPHC\n");
#endif
        Decode6LoWPANIPHC(tv, dtv, p, (uint8_t *)hdr, len, f1h.dgram_size, pq, rp);
        uint32_t pkt_len = GET_PKT_LEN(rp);
#ifdef PRINT
        printf("setting bits %d through %d\n", 0, pkt_len);
        printf("map %08x %08x %08x %08x %08x before\n",
                rp->sixlowpan_frag_map[0],
                rp->sixlowpan_frag_map[1],
                rp->sixlowpan_frag_map[2],
                rp->sixlowpan_frag_map[3],
                rp->sixlowpan_frag_map[4]);
#endif
        for (offset = 0; offset < pkt_len; offset++) {
            Set6LoWPANMapBit(rp, offset);
        }      
#ifdef PRINT
        printf("map %08x %08x %08x %08x %08x after\n",
                rp->sixlowpan_frag_map[0],
                rp->sixlowpan_frag_map[1],
                rp->sixlowpan_frag_map[2],
                rp->sixlowpan_frag_map[3],
                rp->sixlowpan_frag_map[4]);
#endif
    } else if (hdr->dispatch == SIXLOWPAN_DISPATCH_IPV6) {
#ifdef PRINT       
        printf("6LoWPAN fragment is IPV6\n");
#endif
    }
    SET_PKT_LEN(rp, f1h.dgram_size);
    
    Enqueue6LoWPANReassembledPacket(tv, dtv, rp, f1h.dgram_size, pq);
    
    return TM_ECODE_OK;
}

static int Decode6LoWPANFragN(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                             uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    uint8_t fnh0, fnh1, fnh2, fnh3, fnh4;
    FragNHeader fnh;
    Packet *rp = NULL;
    uint32_t offset;
    uint16_t i;
    
    StatsIncr(tv, dtv->counter_6lowpan_fragment);
    
    fnh0 = pkt[0];
    fnh1 = pkt[1];
    fnh2 = pkt[2];
    fnh3 = pkt[3];
    fnh4 = pkt[4];

    fnh.type= fnh0 >> 3;
    fnh.dgram_size = ((fnh0 & 0x7) << 8) | fnh1;
    fnh.dgram_tag = (fnh2 << 8) | fnh3;
    fnh.dgram_offset = fnh4;

#ifdef PRINT    
    printf("6LoWPAN fragment N tag: %x size: %d offset %d\n", fnh.dgram_tag, fnh.dgram_size, fnh.dgram_offset * 8);
    PrintRawDataFp(stdout, &pkt[5], len - 5);
    printf("-------------------------\n");
#endif
    
    rp = LookupFragment(p, fnh.dgram_size, fnh.dgram_tag);
    
    if (rp == NULL) {
        return TM_ECODE_OK;
    }
   
#ifdef PRINT
    printf("setting from %d to %d\n", fnh.dgram_offset * 8, (fnh.dgram_offset * 8) + len - 5);
    printf("map %08x %08x %08x %08x %08x before\n",
            rp->sixlowpan_frag_map[0],
            rp->sixlowpan_frag_map[1],
            rp->sixlowpan_frag_map[2],
            rp->sixlowpan_frag_map[3],
            rp->sixlowpan_frag_map[4]);
#endif 
    //for (offset = fnh.dgram_offset * 8; offset < fnh.dgram_size; offset++) {
    for (offset = fnh.dgram_offset * 8, i = 0; i < len - 5; offset++, i++) {
        Set6LoWPANMapBit(rp, offset);
    }
#ifdef PRINT
    printf("map %08x %08x %08x %08x %08x after\n",
            rp->sixlowpan_frag_map[0],
            rp->sixlowpan_frag_map[1],
            rp->sixlowpan_frag_map[2],
            rp->sixlowpan_frag_map[3],
            rp->sixlowpan_frag_map[4]);
#endif
    PacketCopyDataOffset(rp, fnh.dgram_offset * 8, &pkt[5], len - 5);
    
    Enqueue6LoWPANReassembledPacket(tv, dtv, rp, fnh.dgram_size, pq);

    return TM_ECODE_OK;
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

int Decode6LoWPAN(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    uint32_t hdr_len = sizeof(SixLoWPANHdr);
    int rc;

    /* Validation: make sure that the input data is big enough to hold
     *             the header */
    if (len < sizeof(SixLoWPANHdr)) {
        /* in case of errors, we set events. Events are defined in
         * decode-events.h, and are then exposed to the detection
         * engine through detect-engine-events.h */
        //ENGINE_SET_EVENT(p,TEMPLATE_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    /* Now we can access the header */
    const SixLoWPANHdr *hdr = (const SixLoWPANHdr *)pkt;

    switch (hdr->dispatch) {
        case SIXLOWPAN_DISPATCH_IPV6:
            rc = Decode6LoWPANIPv6(tv, dtv, p, (uint8_t *)pkt + hdr_len, len - hdr_len, pq);
            break;
        case SIXLOWPAN_DISPATCH_HC1:
            rc = Decode6LoWPANHC1(tv, dtv, p, (uint8_t *)pkt + hdr_len, len - hdr_len, pq);
            break;
        default:
            if ((hdr->dispatch & 0xe0) == SIXLOWPAN_DISPATCH_IPHC) {
                rc = Decode6LoWPANIPHC(tv, dtv, p, (uint8_t *)pkt, len, len, pq, NULL);
            } else if ((hdr->dispatch & 0xf8) == SIXLOWPAN_DISPATCH_FRAG1) {
                rc = Decode6LoWPANFrag1(tv, dtv, p, (uint8_t *)pkt, len, pq);
            } else if ((hdr->dispatch & 0xf8) == SIXLOWPAN_DISPATCH_FRAGN) {
                rc = Decode6LoWPANFragN(tv, dtv, p, (uint8_t *)pkt, len, pq);
            } else {
                //ENGINE_SET_EVENT(p,TEMPLATE_UNSUPPORTED_PROTOCOL);
                //SCLogNotice("6LoWPAN unsupported protocol");
                rc = TM_ECODE_FAILED;
            }
    }
    
    if (rc == TM_ECODE_OK)
        StatsIncr(tv, dtv->counter_6lowpan);

    return rc;
}

/**
 * @}
 */
