/*
 * common.h 
 * (C) 2009, all rights reserved,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __COMMON_H
#define __COMMON_H

/*
 * Some standard type definitions and macros that are sadly absent on the
 * windows platform.
 */

/*
 * Boolean type.  This is c99 but not supported in VS.
 */
#define bool        uint8_t
#define true        TRUE
#define false       FALSE

/*
 * Standard c99 types.
 */
typedef signed char             int8_t;
typedef unsigned char           uint8_t;
typedef signed short            int16_t;
typedef unsigned short          uint16_t;
typedef signed int              int32_t;
typedef unsigned int            uint32_t;
typedef long long signed int    int64_t;
typedef long long unsigned int  uint64_t;

/*
 * Ethernet header.
 */
struct ethhdr
{
    uint8_t h_dest[6];
    uint8_t h_source[6];
    uint16_t h_proto;
};

#define ETH_P_IP        0x0800

/*
 * IPv4 header.
 */
struct iphdr
{
    uint8_t  ihl:4;
    uint8_t  version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

#define IPVERSION       4
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

/*
 * TCP header.
 */
struct tcphdr
{
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

/*
 * UDP header
 */
struct udphdr
{
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

/*
 * DNS header
 */
struct dnshdr
{
    uint16_t id;
    uint16_t option;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/* 
 * ICMP header
 */
struct icmphdr
{
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    union
    {
        struct
        {
            uint16_t id;
            uint16_t sequence;
        } echo;
        uint32_t gateway;
        struct
        {
            uint16_t __unused;
            uint16_t mtu;
        } frag;
    } un;
};

#define ICMP_DEST_UNREACH   3
#define ICMP_FRAG_NEEDED    4
#define ICMP_TIME_EXCEEDED  11
#define ICMP_EXC_TTL        0

#define BITS_PER_BYTE       8

#define byte_swap_16(s)     \
    ((((s) >> BITS_PER_BYTE) & 0xFF) | (((s) & 0xFF) << BITS_PER_BYTE))
#define ntohs(s)            byte_swap_16(s)
#define htons(s)            byte_swap_16(s)

#endif      /* __COMMON_H */
