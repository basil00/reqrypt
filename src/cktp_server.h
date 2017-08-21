/*
 * cktp_server.h
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

#ifndef __CKTP_SERVER_H
#define __CKTP_SERVER_H

#include <stdbool.h>

/*
 * An open CKTP tunnel.
 */
typedef struct cktp_tunnel_s *cktp_tunnel_t;

/*
 * Prototypes.
 */
bool cktp_init(void);
cktp_tunnel_t cktp_open_tunnel(const char *url, size_t bps);
void cktp_close_tunnel(cktp_tunnel_t tunnel);
void cktp_listen(cktp_tunnel_t tunnel, int socket_out, int socket_icmp,
    unsigned threads);
bool cktp_is_ipv4_addr_public(uint32_t addr);

#endif      /* __CKTP_SERVER_H */
