/*
 * config.h
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

#ifndef __CONFIG_H
#define __CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "cfg.h"
#include "http_server.h"
#include "log.h"
#include "packet_protocol.h"

#define CONFIG_FILENAME         PROGRAM_NAME ".config"

typedef uint8_t config_enum_t;

/*
 * Values for TCP flags.
 */
typedef config_enum_t config_flag_t;
#define FLAG_UNSET              0
#define FLAG_SET                1
#define FLAG_DONT_CARE          2
#define FLAG_UNSET_NAME         "unset"
#define FLAG_SET_NAME           "set"
#define FLAG_DONT_CARE_NAME     "*"

/*
 * Values for 'split_mode'.
 */
typedef config_enum_t config_split_t;
#define SPLIT_NONE              0
#define SPLIT_FULL              1
#define SPLIT_PARTIAL           2
#define SPLIT_NONE_NAME         "none"
#define SPLIT_FULL_NAME         "full"
#define SPLIT_PARTIAL_NAME      "partial"

/*
 * Values for the log level.
 */
#define LOGLEVEL_ALL            LOG_MESSAGE_TRACE
#define LOGLEVEL_PACKETS        LOG_MESSAGE_PACKET
#define LOGLEVEL_INFO           LOG_MESSAGE_INFO
#define LOGLEVEL_WARNINGS       LOG_MESSAGE_NONE
#define LOGLEVEL_NONE           LOG_MESSAGE_NONE
#define LOGLEVEL_ALL_NAME       "all"
#define LOGLEVEL_PACKETS_NAME   "packets"
#define LOGLEVEL_INFO_NAME      "info"
#define LOGLEVEL_WARNINGS_NAME  "warnings"
#define LOGLEVEL_NONE_NAME      "none"

/*
 * Values for the ghost packet mode.
 */
typedef config_enum_t config_ghost_t;
#define GHOST_NONE              0
#define GHOST_NAT               1
#define GHOST_ALWAYS            2
#define GHOST_NONE_NAME         "none"
#define GHOST_NAT_NAME          "nat"
#define GHOST_ALWAYS_NAME       "always"

/*
 * Values for the fragmentation mode.
 */
typedef config_enum_t config_frag_t;
#define FRAG_NETWORK            0
#define FRAG_TRANSPORT          1
#define FRAG_NETWORK_NAME       "network"
#define FRAG_TRANSPORT_NAME     "transport"

/*
 * Configuration representation.
 */
struct config_s
{
    bool           enabled;         // Is circumvention enabled?
    bool           hide_tcp;        // Hide TCP packets?
    bool           hide_tcp_data;   // Hide TCP data packets?
    config_flag_t  hide_tcp_syn;    // Hide TCP packets with SYN flag set?
    config_flag_t  hide_tcp_ack;    // Hide TCP packets with ACK flag set?
    config_flag_t  hide_tcp_psh;    // Hide TCP packets with PSH flag set?
    config_flag_t  hide_tcp_fin;    // Hide TCP packets with FIN flag set?
    config_flag_t  hide_tcp_rst;    // Hide TCP packets with RST flag set?
    bool           hide_udp;        // Hide UDP packets?
    bool           tunnel;          // Tunnel packets?
    config_split_t split;           // How to split data.
    config_ghost_t ghost;           // Send ghost packets?
    bool           ghost_check;     // Use a valid checksum for ghost packets?
    bool           ghost_set_ttl;   // Set the TTL of ghost packets?
    uint8_t        ghost_ttl;       // TTL for ghost packets.
    config_frag_t  fragment;        // How to fragment packets.
    uint16_t       tcp_port;        // TCP port.
    proto_t        tcp_proto;       // TCP protocol handler.
    uint16_t       tcp_port_2;      // TCP port (2).
    proto_t        tcp_proto_2;     // TCP protocol handler (2).
    uint16_t       udp_port;        // UDP port.
    proto_t        udp_proto;       // UDP protocol handler.
    uint16_t       mtu;             // MTU for tunnelled packets.
    bool           launch_ui;       // Auto-launch the UI on startup.
};

/*
 * Prototypes.
 */
void config_init(void);
void config_get(struct config_s *config);
void config_callback(struct http_user_vars_s *vars);

#endif      /* __CONFIG_H */
