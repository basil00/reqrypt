/*
 * packet.c
 * (C) 2010, all rights reserved,
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

#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "packet.h"

/*
 * Initialise various packet information:
 */
void packet_init(uint8_t *packet, bool has_eth_header,
    struct ethhdr **eth_header_ptr, struct iphdr **ip_header_ptr,
    struct ip6_hdr **ip6_header_ptr, struct tcphdr **tcp_header_ptr,
    struct udphdr **udp_header_ptr, uint8_t **data_ptr,
    size_t *header_size_ptr, size_t *data_size_ptr)
{
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    size_t header_size = 0;
    if (has_eth_header)
    {
        eth_header = (struct ethhdr *)packet;
        header_size += sizeof(struct ethhdr);
        ip_header = (struct iphdr *)(eth_header + 1);
    }
    else
    {
        eth_header = NULL;
        ip_header = (struct iphdr *)packet;
    }

    // Network layer
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)ip_header;
    size_t packet_len;
    uint8_t ip_proto;
    uint8_t *ip_header_end;
    switch (ip_header->version)
    {
        case 4:
            ip6_header = NULL;
            packet_len = ntohs(ip_header->tot_len) + header_size;
            header_size += ip_header->ihl*sizeof(uint32_t);
            ip_proto = ip_header->protocol;
            ip_header_end = (uint8_t *)ip_header +
                ip_header->ihl*sizeof(uint32_t);
            break;
        case 6:
            ip_header = NULL;
            packet_len = ntohs(ip6_header->ip6_plen) + header_size +
                sizeof(struct ip6_hdr);
            header_size += sizeof(struct ip6_hdr);
            ip_proto = ip_header->protocol;
            ip_header_end = (uint8_t *)(ip6_header + 1);
            break;
        default:
            panic("expected IP version 4 or 6, found %d", ip_header->version);
    }

    // Transport layer
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    switch (ip_proto)
    {
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *)ip_header_end;
            udp_header = NULL;
            header_size += tcp_header->doff*sizeof(uint32_t);
            break;
        case IPPROTO_UDP:
            tcp_header = NULL;
            udp_header = (struct udphdr *)ip_header_end;
            header_size += sizeof(struct udphdr);
            break;
        default:
            panic("expected IP protocol %d or %d", IPPROTO_TCP, IPPROTO_UDP);
    }

    uint8_t *data = (header_size == packet_len? NULL: packet + header_size);
    size_t data_size = packet_len - header_size;

    // Init the vars:
    if (eth_header_ptr != NULL)
    {
        *eth_header_ptr = eth_header;
    }
    if (ip_header_ptr != NULL)
    {
        *ip_header_ptr = ip_header;
    }
    if (ip6_header_ptr != NULL)
    {
        *ip6_header_ptr = ip6_header;
    }
    if (tcp_header_ptr != NULL)
    {
        *tcp_header_ptr = tcp_header;
    }
    if (udp_header_ptr != NULL)
    {
        *udp_header_ptr = udp_header;
    }
    if (data_ptr != NULL)
    {
        *data_ptr = data;
    }
    if (header_size_ptr != NULL)
    {
        *header_size_ptr = header_size;
    }
    if (data_size_ptr != NULL)
    {
        *data_size_ptr = data_size;
    }
}

