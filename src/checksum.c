/*
 * checksum.c
 * (C) 2011, all rights reserved,
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

#include <stdint.h>
#include <stdlib.h>

#include "checksum.h"
#include "socket.h"

/*
 * Prototypes.
 */
static uint16_t checksum(const void *data, size_t size);
static uint16_t checksum_add(uint16_t a, uint16_t b);
static uint16_t tcp_udp_checksum(struct iphdr *ip_header);

/*
 * Calculate a checksum.
 */
static uint16_t checksum(const void *data, size_t size)
{
    register const uint16_t *data16 = (const uint16_t *)data;
    register size_t size16 = size >> 1;
    register uint32_t sum = 0;

    for (size_t i = 0; i < size16; i++)
    {
        uint16_t val16 = data16[i];
        sum += (uint32_t)ntohs(val16);
    }

    if (size & 0x1)
    {
        const uint8_t *data8 = (const uint8_t *)data;
        uint16_t val16 = (uint16_t)data8[size-1];
        sum += (uint32_t)ntohs(val16);
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    sum = ~sum;
    return htons((uint16_t)sum);
}

/*
 * Add two checksums together.
 */
static uint16_t checksum_add(uint16_t a, uint16_t b)
{
    uint32_t sum = (uint32_t)ntohs(~a) + (uint32_t)ntohs(~b);
    sum += (sum >> 16);
    return htons((uint16_t)sum);
}

/*
 * IPv4 checksum.
 */
extern uint16_t ip_checksum(struct iphdr *ip_header)
{
    return checksum(ip_header, ip_header->ihl*sizeof(uint32_t));
}

/*
 * TCP (IPv4) checksum.
 */
extern uint16_t tcp_checksum(struct iphdr *ip_header)
{
    return tcp_udp_checksum(ip_header);
}

/*
 * UDP (IPv4) checksum.
 */
extern uint16_t udp_checksum(struct iphdr *ip_header)
{
    return tcp_udp_checksum(ip_header);
}

/*
 * TCP/UDP (IPv4) checksum.
 */
static uint16_t tcp_udp_checksum(struct iphdr *ip_header)
{
    struct 
    {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t  zeros;
        uint8_t  protocol;
        uint16_t tcp_size;
    } __attribute__((__packed__)) pseudo_header;

    size_t ip_header_size = ip_header->ihl*sizeof(uint32_t);
    size_t tcp_size = ntohs(ip_header->tot_len) - ip_header_size;

    pseudo_header.saddr    = ip_header->saddr;
    pseudo_header.daddr    = ip_header->daddr;
    pseudo_header.zeros    = 0x0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_size = htons(tcp_size);

    struct tcphdr *tcp_header = (struct tcphdr *)((const uint8_t *)ip_header +
        ip_header_size);

    uint16_t sum1 = checksum(&pseudo_header, sizeof(pseudo_header));
    uint16_t sum2 = checksum(tcp_header, tcp_size);

    return checksum_add(sum1, sum2);
}

/*
 * ICMP (IPv4) checksum.
 */
extern uint16_t icmp_checksum(struct icmphdr *icmp_header, size_t size)
{
    return checksum(icmp_header, size);
}

