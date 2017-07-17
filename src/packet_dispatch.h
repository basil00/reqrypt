/*
 * packet_dispatch.h
 * (C) 2017, all rights reserved,
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

#ifndef __PACKET_DISPATCH_H
#define __PACKET_DISPATCH_H

#include "cktp.h"
#include "config.h"
#include "random.h"
#include "socket.h"

/*
 * Minimum size of 'buff' for 'packet_dispatch'.
 */
#define PACKET_BUFF_SIZE        (2*CKTP_MAX_PACKET_SIZE+256)

/*
 * Maximum number of fragments packet_dispatch can generate.
 */
#define DISPATCH_MAX_FRAGMENTS    8

/*
 * Prototypes.
 */
void packet_dispatch(struct config_s *config, random_state_t rng,
    uint8_t *packet, size_t packet_len, uint64_t packet_hash,
    unsigned packet_rep, struct ethhdr **allowed_packets,
    struct ethhdr **tunneled_packets, uint8_t *buff);

#endif      /* __PACKET_DISPATCH_H */
