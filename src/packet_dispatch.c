/*
 * packet_dispatch.c
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define __USE_BSD   1
#include <string.h>
#undef __USE_BSD

#include "checksum.h"
#include "config.h"
#include "log.h"
#include "packet.h"
#include "packet_dispatch.h"
#include "packet_protocol.h"
#include "random.h"
#include "socket.h"

/*
 * Prototypes.
 */
static bool is_ipv4_local_address(uint32_t addr);
static uint8_t *ip_fragment(uint8_t *packet, size_t split, uint8_t *buff,
    uint8_t **fragments);
static uint8_t *tcp_fragment(uint8_t *packet, size_t split, uint8_t *buff,
    uint8_t **fragments);
static inline uint8_t split_hash(uint64_t packet_hash);

/*
 * This funcion is the packet dispatch routine.  It will:
 * - Fragment the packet if necessary.
 * - Schedule the packet (or packet fragments) to be tunneled.
 * - Schedule the packet (or packet fragments) *not* to be tunneled.
 * - Create a ghost packet with low TTL for NAT traversal.
 * - Mangle the packet for NAT traversal.
 */
void packet_dispatch(struct config_s *config, random_state_t rng,
    uint8_t *packet, size_t packet_len, uint64_t packet_hash,
    unsigned packet_rep, struct ethhdr **allowed_packets,
    struct iphdr **tunneled_packets, uint8_t *buff)
{
    // Initialise pointers to various packet headers.
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    struct ip6_hdr *ip6_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    uint8_t *data;
    size_t header_size, data_size;
    packet_init(packet, true, &eth_header, &ip_header, &ip6_header,
        &tcp_header, &udp_header, &data, &header_size, &data_size);

    const struct proto_s *protocol;
    bool is_tcp;
    if (tcp_header != NULL)
    {
        is_tcp = true;

        // XXX More NAT hacking:
        if (tcp_header->syn == 1)
        {
            uint8_t *tcp_opts = (uint8_t *)(tcp_header + 1);
            size_t tcp_opts_size = tcp_header->doff*sizeof(uint32_t) -
                sizeof(struct tcphdr);
            for (size_t i = 0; i < tcp_opts_size; i++)
            {
                if (tcp_opts[i] == TCPOPT_EOL)
                {
                    break;
                }
                if (tcp_opts[i] == TCPOPT_NOP)
                {
                    continue;
                }
                if (tcp_opts[i] == TCPOPT_MAXSEG)
                {
                    // memset(tcp_opts + i, TCPOPT_NOP, tcp_opts[i+1]);
                    uint16_t *mss_ptr = (uint16_t *)(tcp_opts + 2);
                    *mss_ptr = htons(1280);
                    break;
                }
                i += tcp_opts[i+1] - 1;
            }
    
            // memset(tcp_header + 1, 0x01, tcp_header->doff*sizeof(uint32_t) -
            //     sizeof(struct tcphdr));
        }
    
        // Get the protocol handlers:
        protocol = protocol_get_def(config->tcp_proto);
    }
    else
    {
        is_tcp = false;
        protocol = protocol_get_def(config->udp_proto);
    }

    // If we are required to split up the packet then do so here.
    unsigned allow_i = 0, tunnel_i = 0;
    if (is_tcp && config->split != SPLIT_NONE)
    {
        size_t split_start = 0, split_end = 0;
        if (protocol->match((uint8_t *)ip_header, &split_start, &split_end))
        {
            size_t split_len;
            if (config->split == SPLIT_PARTIAL)
            {
                size_t split_range = split_end - split_start;
                split_range = (split_range < 4? 0: split_range - 3);
                uint8_t split_rand = split_hash(packet_hash);
                split_len = split_start + 1 + split_rand % (split_range + 1);
            }
            else
            {
                split_len = split_end;
            }
            
            uint8_t *fragments[2];
            switch (config->fragment)
            {
                case FRAG_NETWORK:
                    // IP layer fragmentation is only allowed for IPv4
                    if (ip_header != NULL)
                    {
                        buff = ip_fragment(packet, split_len, buff, fragments);
                        break;
                    }
                    // Fall through
                case FRAG_TRANSPORT:
                    buff = tcp_fragment(packet, split_len, buff, fragments);
                    break;
                default:
                    panic("expected IP or TCP fragmentation method");
            }
            if (fragments[1] != NULL)
            {
                allowed_packets[allow_i++] = (struct ethhdr *)fragments[1];
                allowed_packets[allow_i]   = NULL;
            }
            tunneled_packets[tunnel_i++] = 
                (struct iphdr *)(fragments[0] + sizeof(struct ethhdr));
            tunneled_packets[tunnel_i] = NULL;
        }
        else
        {
            // No URL was found -- packet goes via the normal route.
            allowed_packets[0] = (struct ethhdr *)packet;
            allowed_packets[1] = NULL;
            return;
        }
    }
    else
    {
        // Don't split packet == tunnel the entire packet.
        tunneled_packets[tunnel_i++] = ip_header;
        tunneled_packets[tunnel_i]   = NULL;
    }

    // Check if we need ghost packets or not.
    bool use_ghost = false;
    switch (config->ghost)
    {
        case GHOST_NONE:
            break;
        case GHOST_NAT:
            use_ghost = is_ipv4_local_address(ip_header->saddr);
            break;
        case GHOST_ALWAYS:
            use_ghost = true;
            break;
    }

    // If we need to send ghost packets then do so here.
    if (use_ghost)
    {
        // TODO: handle IPv6
        for (unsigned i = 0; tunneled_packets[i] != NULL; i++)
        {
            size_t tunneled_header_size, tunneled_data_size;
            packet_init((uint8_t *)tunneled_packets[i], false, NULL, NULL,
                NULL, NULL, NULL, NULL, &tunneled_header_size,
                &tunneled_data_size);
            uint8_t *packet_copy = buff;
            buff += tunneled_header_size + tunneled_data_size;
            memcpy(packet_copy, packet, sizeof(struct ethhdr));
            memcpy(packet_copy + sizeof(struct ethhdr), tunneled_packets[i],
                tunneled_header_size);

            protocol->generate(packet_copy + sizeof(struct ethhdr),
                packet_hash);

            struct iphdr *copy_ip_header;
            struct tcphdr *copy_tcp_header;
            struct udphdr *copy_udp_header;
            packet_init(packet_copy, true, NULL, &copy_ip_header, NULL,
                &copy_tcp_header, &copy_udp_header, NULL, NULL, NULL);
            uint16_t checksum;
            if (copy_tcp_header != NULL)
            {
                copy_tcp_header->check = 0;
                checksum = tcp_checksum(copy_ip_header);
            }
            else
            {
                copy_udp_header->check = 0;
                checksum = udp_checksum(copy_ip_header);
            }
            if (!config->ghost_check)
            {
                uint16_t junk_checksum = random_uint16(rng);
                junk_checksum = (junk_checksum == checksum? checksum+1:
                    junk_checksum);
                junk_checksum = (junk_checksum == 0 && copy_udp_header != NULL?
                    ~junk_checksum: junk_checksum);
                checksum = junk_checksum;
            }

            if (copy_tcp_header != NULL)
            {
                copy_tcp_header->check = checksum;
            }
            else
            {
                copy_udp_header->check = checksum;
            }
            if (config->ghost_set_ttl)
            {
                copy_ip_header->ttl = config->ghost_ttl;
            }
            copy_ip_header->check = 0;
            copy_ip_header->check = ip_checksum(copy_ip_header);      

            allowed_packets[allow_i++] = (struct ethhdr *)packet_copy;
            allowed_packets[allow_i]   = NULL;
        }
    }
}

/*
 * Returns 'true' if the given IPv4 is a local address or not.
 */
bool is_ipv4_local_address(uint32_t addr)
{
    switch ((uint8_t)addr)
    {
        case 10:    // Private Network: RFC 1918
            return true;
        case 172:
        {
            uint8_t b = (uint8_t)(addr >> 8);
            if (b >= 16 && b <= 31) // Private Network: RFC 1918
            {
                 return true;
            }
            break;
        }
        case 192:
        {
            uint8_t b = (uint8_t)(addr >> 8);
            if (b == 168) // Private Network: RFC 1918
            {
                return true;
            }
            break;
        }
    }
    return false;
}

/*
 * Do IPv4 fragmentation on a packet.  Notes:
 * - Doesn't handle IPv4 options correctly: instead copies all options to both
 *   fragments.  This shouldn't be a problem since IP options are no longer
 *   used in practice (???)
 *   TODO: handle this better!
 * - Unashamedly ignores the DF "Don't Fragment" flag in violation of RFC791.
 * - Some NAT implementation don't handle IP fragments -- in such cases TCP
 *   fragments should be used instead.
 */
static uint8_t *ip_fragment(uint8_t *packet, size_t split, uint8_t *buff,
    uint8_t **fragments)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    size_t header_size, data_size;
    packet_init(packet, true, NULL, &ip_header, NULL, &tcp_header, NULL, NULL,
        &header_size, &data_size);

    if (ip_header == NULL)
    {
        // IPv6 (obviously) does not support IPv4 fragmentation:
        fragments[0] = packet;
        fragments[1] = NULL;
        return buff;
    }

    // Factor in the TCP header size.
    split += tcp_header->doff*sizeof(uint32_t);

    // Make the split a multiple of 8 (required for IPv4 fragmentation).
    split += 8 - split % 8;
    size_t data_split = split;

    // Factor in the TPv4 header size.
    split += ip_header->ihl*sizeof(uint32_t);

    // Handle the case where we have consumed the entire packet.
    if (split >= ntohs(ip_header->tot_len))
    {
        fragments[0] = packet;
        fragments[1] = NULL;
        return buff;
    }

    // Create the first fragment:
    memcpy(buff, packet, split + sizeof(struct ethhdr));
    struct iphdr *ip_header_1 = (struct iphdr *)(buff + sizeof(struct ethhdr));

    ip_header_1->tot_len  = htons(split);
    ip_header_1->frag_off = htons(IP_MF);       // MF=1, DF=0
    ip_header_1->check    = 0;
    ip_header_1->check    = ip_checksum(ip_header_1);
    fragments[0] = buff;
    buff += split + sizeof(struct ethhdr);

    // Create the second fragment:
    size_t header_size_2 = sizeof(struct ethhdr) +
        ip_header->ihl*sizeof(uint32_t);
    memcpy(buff, packet, header_size_2);
    size_t data_size_2 = ntohs(ip_header->tot_len) - split;
    
    memcpy(buff + header_size_2, packet + split + sizeof(struct ethhdr),
        data_size_2);
    struct iphdr *ip_header_2 = (struct iphdr *)(buff + sizeof(struct ethhdr));
    ip_header_2->tot_len = htons(header_size_2 + data_size_2 -
        sizeof(struct ethhdr));
    ip_header_2->frag_off = htons(data_split / 8);   // MF=0, DF=0
    ip_header_2->check = 0;
    ip_header_2->check = ip_checksum(ip_header_2);
    fragments[1] = buff;
    buff += header_size_2 + data_size_2;

    return buff;
}

/*
 * Do TCP fragmentation on a packet.  Notes:
 * - The local TCP/IP stack doesn't know the packet is being split.  It might
 *   not handle the acknowledgement of the first fragment gracefully.
 * - IP and TCP options are copied to both fragments:  This might not be
 *   the best (or even the correct) solution.
 *   TODO: handle this better!
 * - TODO: HANDLE IPv6!
 */
static uint8_t *tcp_fragment(uint8_t *packet, size_t split, uint8_t *buff,
    uint8_t **fragments)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    uint8_t *data;
    size_t header_size, data_size;
    packet_init(packet, true, NULL, &ip_header, NULL, &tcp_header, NULL, &data,
        &header_size, &data_size);

    // Handle the case where we have consumed the entire packet.
    if (split >= data_size)
    {
        fragments[0] = packet;
        fragments[1] = NULL;
        return buff;
    }

    // Create the first fragment.  We make a few "alterations":
    // - PSH & FIN bits are zeroed.  These will be set on the next fragment.
    // - window size is set to 0.  Server should only start sending data
    //   after the second fragment was arrived.
    memcpy(buff, packet, header_size + split);
    struct iphdr *ip_header_1;
    struct tcphdr *tcp_header_1;
    packet_init(buff, true, NULL, &ip_header_1, NULL, &tcp_header_1, NULL,
        NULL, NULL, NULL);
    ip_header_1->tot_len = htons(header_size + split - sizeof(struct ethhdr));
    ip_header_1->check   = 0;
    ip_header_1->check   = ip_checksum(ip_header_1);
    tcp_header_1->psh    = 0;
    tcp_header_1->fin    = 0;
    tcp_header_1->window = 0;
    tcp_header_1->check  = 0;
    tcp_header_1->check  = tcp_checksum(ip_header_1);
    fragments[0] = buff;
    buff += split + header_size;

    // Create the second fragment.  We only change the TCP sequence number
    // accordingly.
    memcpy(buff, packet, header_size);
    memcpy(buff + header_size, data + split, data_size - split);
    struct iphdr *ip_header_2;
    struct tcphdr *tcp_header_2;
    packet_init(buff, true, NULL, &ip_header_2, NULL, &tcp_header_2, NULL,
        NULL, NULL, NULL);
    ip_header_2->tot_len = htons(ntohs(ip_header_2->tot_len) - split);
    ip_header_2->check   = 0;
    ip_header_2->check   = ip_checksum(ip_header_2);
    tcp_header_2->seq    = htonl(ntohl(tcp_header->seq) + split);
    tcp_header_2->check  = 0;
    tcp_header_2->check  = tcp_checksum(ip_header_2);
    fragments[1] = buff;
    buff += header_size + data_size - split;

    return buff;
}

/*
 * Convert a packet hash value into an 8-bit URL hash value.
 */
static inline uint8_t split_hash(uint64_t packet_hash)
{
    uint32_t h32 = (uint32_t)packet_hash;
    h32 ^= (uint32_t)(packet_hash >> 32);
    uint16_t h16 = (uint16_t)h32;
    h16 ^= (uint16_t)(h32 >> 16);
    uint8_t h8 = (uint8_t)h16;
    h8 ^= (uint8_t)(h16 >> 8);
    return h8;
}

