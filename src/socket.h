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
#ifdef WINDOWS
#include "windows/socket.h"
#endif

#ifdef LINUX
#include "linux/socket.h"
#endif

#ifdef FREEBSD
#include "freebsd/socket.h"
#endif

#ifndef __SOCKET_COMMON_H
#define __SOCKET_COMMON_H

/*
 * Common to all OSs:
 */

/*
 * IPv4 flags.
 */
#define IP_DF 0x4000
#define IP_MF 0x2000

/*
 * UDPLITE macros.
 */
#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE     136
#endif

#ifndef UDPLITE_SEND_CSCOV
#define UDPLITE_SEND_CSCOV  10
#endif

#ifndef UDPLITE_RECV_CSCOV
#define UDPLITE_RECV_CSCOV  11
#endif

#endif      /* __SOCKET_COMMON_H */
