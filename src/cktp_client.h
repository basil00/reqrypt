/*
 * cktp_client.h
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

#ifndef __CKTP_CLIENT_H
#define __CKTP_CLIENT_H

#include <stdint.h>
#include <stdlib.h>

/*
 * An open CKTP tunnel.
 */
typedef struct cktp_tunnel_s *cktp_tunnel_t;
#define CKTP_TUNNEL_NULL    ((cktp_tunnel_t)NULL)

/*
 * Prototypes.
 */
cktp_tunnel_t cktp_open_tunnel(const char *url);
void cktp_close_tunnel(cktp_tunnel_t tunnel);
uint16_t cktp_tunnel_get_mtu(cktp_tunnel_t tunnel, uint16_t mtu);
bool cktp_tunnel_timeout(cktp_tunnel_t tunnel, uint64_t currtime);
void cktp_tunnel_packet(cktp_tunnel_t tunnel, const uint8_t *packet);
void cktp_fragmentation_required(cktp_tunnel_t tunnel, uint16_t mtu,
    const uint8_t *packet);

#endif      /* __CKTP_CLIENT_H */
