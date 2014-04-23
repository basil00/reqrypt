/*
 * packet_protocol.h
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
#ifndef __PACKET_PROTOCOL_H
#define __PACKET_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>

typedef uint8_t proto_t;
typedef bool (*proto_match_t)(uint8_t *packet, size_t *start, size_t *end);
typedef void (*proto_gen_t)(uint8_t *packet, uint64_t hash);

#define PROTOCOL_TCP_DEFAULT    0
#define PROTOCOL_UDP_DEFAULT    1
#define PROTOCOL_DEFAULT        PROTOCOL_TCP_DEFAULT

struct proto_s
{
    const char    *name; 
    proto_match_t  match;
    proto_gen_t    generate;
};

proto_t protocol_get(const char *name);
const struct proto_s *protocol_get_def(proto_t proto);

#define protocol_get_name(proto)    (protocol_get_def(proto)->name)

#endif      /* __PACKET_PROTOCOL_H */
