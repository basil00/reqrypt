/*
 * socket.h
 * (C) 2010, all rights reserved,
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
#ifndef __SOCKET_H
#define __SOCKET_H

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/udp.h>
#include <unistd.h>

typedef int socket_t;

#define SOCKET_T_FMT                "%d"

#define INVALID_SOCKET              (-1)
#define SOCKET_ERROR                (-1)

#define init_sockets()              /* NOP */
#define close_socket(socket)        close(socket)

#define UDP_NO_CHECK_LAYER          SOL_SOCKET
#define UDP_NO_CHECK_OPTION         SO_NO_CHECK

#define unused                      __unused

#endif      /* __SOCKET_H */
