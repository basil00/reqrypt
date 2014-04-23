/*
 * tunnel.h
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

#ifndef __TUNNEL_H
#define __TUNNEL_H

#include <stdbool.h>
#include <stdint.h>

#include "cfg.h"
#include "http_server.h"

#define TUNNELS_FILENAME            PROGRAM_NAME ".cache"

typedef struct tunnel_s *tunnel_t;

/*
 * Prototypes.
 */
void tunnel_init(void);
void tunnel_file_read(void);
void tunnel_file_write(void);
bool tunnel_ready(void);
void tunnel_open(void);
bool tunnel_packets(uint8_t *packet, uint8_t **packets, uint64_t hash,
    unsigned repeat, uint16_t config_mtu);
bool tunnel_active_html(http_buffer_t buff);
bool tunnel_all_html(http_buffer_t buff);
void tunnel_add(const char *url);
void tunnel_delete(const char *url);

#endif      /* __TUNNEL_H */
