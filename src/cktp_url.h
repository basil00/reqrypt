/*
 * cktp_url.h
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

#ifndef __CKTP_URL_H
#define __CKTP_URL_H

#include <stdbool.h>

#include "cktp_encoding.h"
#include "socket.h"

#define CKTP_PROTO_IP       0
#define CKTP_PROTO_UDP      1
#define CKTP_PROTO_UDPLITE  2
#define CKTP_PROTO_PING     3
#define CKTP_PROTO_TCP      4

/*
 * Parse a tunnel url.
 */
bool cktp_parse_url(const char *url, int *transport, char *server,
    uint16_t *port, struct cktp_enc_s *encodings);

#endif      /* __CKTP_URL_H */
