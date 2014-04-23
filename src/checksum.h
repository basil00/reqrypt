/*
 * checksum.h
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

#ifndef __CHECKSUM_H
#define __CHECKSUM_H

#include <stdlib.h>

#include "socket.h"

extern uint16_t ip_checksum(struct iphdr *ip_header);
extern uint16_t tcp_checksum(struct iphdr *ip_header);
extern uint16_t udp_checksum(struct iphdr *ip_header);
extern uint16_t icmp_checksum(struct icmphdr *icmp_header, size_t size);

#endif      /* __CHECKSUM_H */
