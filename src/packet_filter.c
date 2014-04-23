/*
 * packet_filter.c
 * (C) 2014, all rights reserved,
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
#include <string.h>

#include "config.h"
#include "packet_filter.h"
#include "socket.h"

/*
 * Returns true if the packet is valid and some part of the packet needs to be
 * tunneled.
 */
bool packet_filter(struct config_s *config, const uint8_t *packet,
    size_t packet_len)
{
    // Do we even need to do anything?
    if (!config->enabled)
    {
        return false;
    }

    // ETHERNET:
    if (packet_len < sizeof(struct ethhdr))
    {
        return false;
    }
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    if (ntohs(eth_header->h_proto) != ETH_P_IP)
    {
        return false;
    }
    packet_len -= sizeof(struct ethhdr);
    
    // IPv4/IPv6:
    if (packet_len < sizeof(struct iphdr))
    {
        return false;
    }
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp_header = NULL;
    struct udphdr *udp_header = NULL;
    switch (ip_header->version)
    {
        case 4:
            if (ntohs(ip_header->tot_len) != packet_len)
            {
                return false;
            }
            switch ((uint8_t)ip_header->daddr)
            {
                case 0:     // Current Network: RFC 1700
                    return false;
                case 10:    // Private Network: RFC 1918
                    return false;
                case 127:   // Loopback: RFC 3330
                    return false;
                case 172:
                {
                    uint8_t b = (uint8_t)(ip_header->daddr >> 8);
                    if (b >= 16 && b <= 31) // Private Network: RFC 1918
                    {
                         return false;
                    }
                    break;
                }
                case 192:
                {
                    uint8_t b = (uint8_t)(ip_header->daddr >> 8);
                    if (b == 168) // Private Network: RFC 1918
                    {
                        return false;
                    }
                    break;
                }
            }
            if (ip_header->ihl*sizeof(uint32_t) < sizeof(struct iphdr))
            {
                return false;
            }
            switch (ip_header->protocol)
            {
                case IPPROTO_TCP:
                    if (packet_len < ip_header->ihl*sizeof(uint32_t) +
                        sizeof(struct tcphdr))
                    {
                        return false;
                    }
                    tcp_header = (struct tcphdr *)((uint8_t *)ip_header + 
                        ip_header->ihl*sizeof(uint32_t));
                    break;
                case IPPROTO_UDP:
                    if (packet_len < ip_header->ihl*sizeof(uint32_t) +
                        sizeof(struct udphdr))
                    {
                        return false;
                    }
                    udp_header = (struct udphdr *)((uint8_t *)ip_header +
                        ip_header->ihl*sizeof(uint32_t));
                    break;
                default:
                    return false;
            }
            break;
        case 6:
        {
            struct ip6_hdr *ip6_header = (struct ip6_hdr *)ip_header;
            if (ntohs(ip6_header->ip6_plen) != packet_len)
            {
                return false;
            }
            // Check the IP address is a global address.  This is not yet as
            // comprehensive as the IPv4 case:
            static const struct in6_addr local_addr = IN6ADDR_LOOPBACK_INIT;
            if (memcmp(&ip6_header->ip6_dst, &local_addr, 
                sizeof(struct in6_addr)) == 0) // Loopback
            {
                return false;
            }
            if (ip6_header->ip6_dst.s6_addr[0] == 0xFC &&
                (ip6_header->ip6_dst.s6_addr[1] == 0x00 ||
                 ip6_header->ip6_dst.s6_addr[1] == 0x01)) // Local address.
            {
                return false;
            }
            switch (ip6_header->ip6_nxt)
            {
                case IPPROTO_TCP:
                    if (packet_len < sizeof(struct ip6_hdr) +
                        sizeof(struct tcphdr))
                    {
                        return false;
                    }
                    tcp_header = (struct tcphdr *)(ip6_header + 1);
                    break;
                case IPPROTO_UDP:
                    if (packet_len < sizeof(struct ip6_hdr) +
                        sizeof(struct udphdr))
                    {
                        return false;
                    }
                    udp_header = (struct udphdr *)(ip6_header + 1);
                    break;
                default:
                    return false;
            }
            break;
        }
        default:
            return false;
    }

    // TCP/UDP:
    bool should_tunnel = false;
    if (tcp_header != NULL)
    {
        if (tcp_header->dest != htons(80))
        {
            return false;
        }

        // Check the user configuration:
        should_tunnel =
            config->hide_tcp && (
            (tcp_header->syn? config->hide_tcp_syn == FLAG_SET:
                              config->hide_tcp_syn == FLAG_UNSET) ||
            (tcp_header->ack? config->hide_tcp_ack == FLAG_SET:
                              config->hide_tcp_ack == FLAG_UNSET) ||
            (tcp_header->psh? config->hide_tcp_psh == FLAG_SET:
                              config->hide_tcp_psh == FLAG_UNSET) ||
            (tcp_header->fin? config->hide_tcp_fin == FLAG_SET:
                              config->hide_tcp_fin == FLAG_UNSET) ||
            (tcp_header->rst? config->hide_tcp_rst == FLAG_SET:
                              config->hide_tcp_rst == FLAG_UNSET));
        if (should_tunnel && config->hide_tcp_data)
        {
            should_tunnel =
                ((uint8_t *)tcp_header + tcp_header->doff*sizeof(uint32_t) < 
                 (uint8_t *)ip_header + packet_len);
        }
    }
    else if (udp_header != NULL)
    {
        if (udp_header->dest != htons(53))
        {
            return false;
        }

        should_tunnel = config->hide_udp;
    }

    return should_tunnel;
}

