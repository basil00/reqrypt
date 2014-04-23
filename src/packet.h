/*
 * packet.h
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

#ifndef __PACKET_H
#define __PACKET_H

#include <stdbool.h>
#include <stdint.h>

#include "socket.h"

/*
 * Prototypes.
 */
void packet_init(uint8_t *packet, bool has_eth_header,
    struct ethhdr **eth_header_ptr, struct iphdr **ip_header_ptr,
    struct ip6_hdr **ip6_header_ptr, struct tcphdr **tcp_header_ptr,
    struct udphdr **udp_header_ptr, uint8_t **data_ptr,
    size_t *header_size_ptr, size_t *data_size_ptr);

#endif      /* __PACKET_H */
