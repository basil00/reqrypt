/*
 * cktp_client.c
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

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cfg.h"
#include "checksum.h"
#include "cktp.h"
#include "cktp_common.h"
#include "cktp_encoding.h"
#include "cktp_url.h"
#include "log.h"
#include "misc.h"
#include "packet.h"
#include "random.h"
#include "socket.h"

#include "cktp_client.h"

/*
 * Holds all relevant information regarding an open CKTP tunnel.
 */
struct cktp_tunnel_s
{
    socket_t          socket;                          /* Tunnel's socket.    */
    int               transport;                       /* Transport protocol. */
    struct cktp_enc_s encodings[CKTP_MAX_ENCODINGS+1]; /* Encodings.          */
    uint8_t           open_encodings;                  /* Number of encodings.*/
    size_t            overhead;                        /* Encoding overhead.  */
    bool              error;                           /* In error state?     */
    uint32_t          auth_id;                         /* Authentication.     */
    uint32_t          flags;                           /* Flags.              */
    uint16_t          filter;                          /* Filter.             */
    uint16_t          seq;                             /* Sequence number.    */
    int               addrtype;                        /* IPv4 or IPv6?       */
    uint32_t          server_addr[4];                  /* Server's IP addr    */
    uint16_t          server_port;                     /* Server's port       */
    uint32_t          client_addr[4];                  /* Client's IP addr    */
    char              server_name[CKTP_MAX_URL_LENGTH+1];
                                                       /* Server's name.      */
    char              server_url[CKTP_MAX_URL_LENGTH+1];
                                                       /* Server's URL.       */
    random_state_t    rng;                             /* Random numbers      */
};

typedef bool (*cktp_reply_handler_t)(cktp_tunnel_t tunnel, uint8_t *packet,
    size_t size, void *data1, void *data2);

/*
 * Prototypes.
 */
static bool cktp_connect(cktp_tunnel_t tunnel);
static bool cktp_encodings_connect(cktp_tunnel_t tunnel);
static bool cktp_encode_packet(cktp_tunnel_t tunnel, uint8_t **buffptr,
    size_t *sizeptr);
static bool cktp_decode_packet(cktp_tunnel_t tunnel, uint8_t **buffptr,
    size_t *sizeptr);
static bool cktp_encodings_connect_handler(cktp_tunnel_t tunnel, uint8_t *buff,
    size_t size, void *data1, void *data2);
static bool cktp_reply_get_auth_handler(cktp_tunnel_t tunnel, uint8_t *reply,
    size_t reply_size, void *data1, void *data2);
static bool cktp_reply_get_info_handler(cktp_tunnel_t tunnel, uint8_t *reply,
    size_t reply_size, void *data1, void *data2);
static bool cktp_reply_handler(cktp_tunnel_t tunnel, const uint8_t *reply,
    size_t reply_size, void *data1, void *data2);
static bool cktp_send_request(cktp_tunnel_t tunnel, uint8_t *buff, size_t size,
    cktp_reply_handler_t reply_handler, void *data1, void *data2);
static void cktp_add_transport_header(cktp_tunnel_t tunnel, uint8_t **packet,
    size_t *length);
static bool cktp_strip_transport_header(cktp_tunnel_t tunnel,
    uint8_t **packet, size_t *length);
static bool cktp_send_packet(cktp_tunnel_t tunnel, uint8_t *packet,
    size_t length);
static bool cktp_recv_packet(cktp_tunnel_t tunnel, uint8_t **packet,
    size_t *length);
static void log_packet(const uint8_t *packet);

/*
 * Opens a CKTP tunnel for use by a client based on the given URL.
 */
extern cktp_tunnel_t cktp_open_tunnel(const char *url)
{
    cktp_tunnel_t tunnel = (cktp_tunnel_t)malloc(sizeof(struct cktp_tunnel_s));
    if (tunnel == NULL)
    {
        error("unable to allocate " SIZE_T_FMT " bytes for tunnel",
            sizeof(struct cktp_tunnel_s));
    }
    memset(tunnel, 0x0, sizeof(struct cktp_tunnel_s));
    tunnel->socket = INVALID_SOCKET;
    
    // Parse the URL.
    strncpy(tunnel->server_url, url, CKTP_MAX_URL_LENGTH);
    if (!cktp_parse_url(tunnel->server_url, &tunnel->transport,
        tunnel->server_name, &tunnel->server_port, tunnel->encodings))
    {
        goto open_tunnel_error;
    }

    // Lookup the server, and copy the address to 'tunnel'.
    trace("looking up IP address of host %s for tunnel %s",
        tunnel->server_name, tunnel->server_url);
    struct hostent *server = gethostbyname(tunnel->server_name);
    if (server == NULL)
    {
        warning("unable to find host %s for server %s", tunnel->server_name,
            tunnel->server_url);
        goto open_tunnel_error;
    }
    if (server->h_addrtype != AF_INET && server->h_addrtype != AF_INET6)
    {
        warning("host %s for server %s uses an unsupported address type %d; "
            "expected IPv4 (%d) or IPv6 (%d)", tunnel->server_name,
            tunnel->server_url, tunnel->addrtype, AF_INET, AF_INET6);
        goto open_tunnel_error;
    }
    tunnel->addrtype = server->h_addrtype;
    memmove(tunnel->server_addr, server->h_addr_list[0], server->h_length);

    // Open a socket and bind it to the server's address.
    switch (tunnel->transport)
    {
        case CKTP_PROTO_IP:
        {
            tunnel->socket = socket(tunnel->addrtype, SOCK_RAW,
                ntohs(tunnel->server_port));
            if (tunnel->socket == INVALID_SOCKET)
            {
                warning("unable to open RAW socket with protocol %u for "
                    "tunnel %s", ntohs(tunnel->server_port),
                    tunnel->server_url);
                goto open_tunnel_error;
            }

            int on = 0;
            if (setsockopt(tunnel->socket, IPPROTO_IP, IP_HDRINCL,
                (char *)&on, sizeof(on)) != 0)
            {
                warning("unable to disable IP header inclusion for tunnel %s",
                    tunnel->server_url);
                goto open_tunnel_error;
            }
            break;
        }
        case CKTP_PROTO_UDP:
        {
            tunnel->socket = socket(tunnel->addrtype, SOCK_DGRAM,
                IPPROTO_UDP);
            if (tunnel->socket == INVALID_SOCKET)
            {
                warning("unable to open UDP socket for tunnel %s",
                    tunnel->server_url);
                goto open_tunnel_error;
            }

#ifndef FREEBSD
            int on = 1;
            if (setsockopt(tunnel->socket, UDP_NO_CHECK_LAYER,
                UDP_NO_CHECK_OPTION, (char *)&on, sizeof(on)) != 0)
            {
                warning("unable to disable UDP checksums for tunnel %s",
                    tunnel->server_url);
                goto open_tunnel_error;
            }
#endif		/* FREEBSD */
            break;
        }
        case CKTP_PROTO_PING:
        {
            tunnel->socket = socket(tunnel->addrtype, SOCK_RAW, IPPROTO_ICMP);
            if (tunnel->socket == INVALID_SOCKET)
            {
                warning("unable to open PING socket for tunnel %s",
                    tunnel->server_url);
                goto open_tunnel_error;
            }

            int on = 0;
            if (setsockopt(tunnel->socket, IPPROTO_IP, IP_HDRINCL,
                (char *)&on, sizeof(on)) != 0)
            {
                warning("unable to disable IP header inclusion for tunnel %s",
                    tunnel->server_url);
                goto open_tunnel_error;
            }

            tunnel->overhead += sizeof(struct icmphdr);
            break;
        }
#if 0
/* #ifdef IPPROTO_UDPLITE */
        case CKTP_PROTO_UDPLITE:
            tunnel->socket = socket(tunnel->addrtype, SOCK_DGRAM,
                IPPROTO_UDPLITE);
            if (tunnel->socket == INVALID_SOCKET)
            {
                warning("unable to open UDPLITE socket for tunnel %s",
                    tunnel->server_url);
                goto open_tunnel_error;
            }

            int coverage = 8;
            if (setsockopt(tunnel->socket, IPPROTO_UDPLITE,
                    UDPLITE_SEND_CSCOV, &coverage, sizeof(coverate)) != 0 ||
                setsockopt(tunnel->socket, IPPROTO_UDPLITE,
                    UDPLITE_RECV_CSCOV, &coverage, sizeof(coverate)) != 0)
            {
                warning("unable to set UDPLITE checksum coverage to %d",
                    coverage);
                goto open_tunnel_error;
            }
            break;
#endif      /* IPPROTO_UDPLITE */

        default:
            panic("unknown or unsupported transport protocol 0x%.4X",
                tunnel->transport);
    }
    trace("created socket (" SOCKET_T_FMT ") for tunnel %s", tunnel->socket,
        tunnel->server_url);

    if (tunnel->addrtype == AF_INET)
    {
        struct sockaddr_in sockaddr;
        memset(&sockaddr, 0x0, sizeof(sockaddr));
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_port   =
            (tunnel->transport == CKTP_PROTO_UDP ||
             tunnel->transport == CKTP_PROTO_UDPLITE? tunnel->server_port: 0);
        sockaddr.sin_addr.s_addr = tunnel->server_addr[0];
        trace("connecting socket (" SOCKET_T_FMT ") to address %s:%u",
            tunnel->socket, inet_ntoa(*(struct in_addr *)tunnel->server_addr),
            ntohs(tunnel->server_port));
        if (connect(tunnel->socket, (struct sockaddr *)&sockaddr, 
                sizeof(struct sockaddr_in)) != 0)
        {
            if (tunnel->transport == CKTP_PROTO_UDP ||
                tunnel->transport == CKTP_PROTO_UDPLITE)
            {
                warning("unable to bind socket to address %s:%u for tunnel %s",
                    inet_ntoa(*(struct in_addr *)tunnel->server_addr),
                    ntohs(tunnel->server_port), tunnel->server_url);
            }
            else
            {
                warning("unable to bind socket to address %s for tunnel %s",
                    inet_ntoa(*(struct in_addr *)tunnel->server_addr),
                    tunnel->server_url);
            }
            goto open_tunnel_error;
        }
    }
    else    /* AF_INET6 */
    {
        struct sockaddr_in6 sockaddr;
        memset(&sockaddr, 0x0, sizeof(sockaddr));
        sockaddr.sin6_family = AF_INET6;
        sockaddr.sin6_port   = tunnel->server_port;
        memmove(&sockaddr.sin6_addr, tunnel->server_addr,
            sizeof(struct in6_addr));
        if (connect(tunnel->socket, (struct sockaddr *)&sockaddr,
                sizeof(struct in6_addr)) != 0)
        {
            // XXX: Better warning message!
            warning("unable to bind socket tunnel %s", tunnel->server_url);
            goto open_tunnel_error;
        }
    }

    /*
     * Initialise the random number generator.
     */
    tunnel->rng = random_init();

    /*
     * Connect to the server.
     */
    if (cktp_connect(tunnel))
    {
        return tunnel;
    }

    /* Fall through. */
open_tunnel_error:

    cktp_close_tunnel(tunnel);
    return (cktp_tunnel_t)NULL;
}

/*
 * Attempts to establish a connection with the server.  If successful, 
 * initialise the rest of 'tunnel' and returns 'true'.  Otherwise, returns
 * 'false', and it is up to the callee to cleanup 'tunnel'.
 */
static bool cktp_connect(cktp_tunnel_t tunnel)
{
    // First establish the connection on the encoding layer(s).
    if (!cktp_encodings_connect(tunnel))
    {
        return false;
    }

    struct
    {
        struct cktp_msg_hdr_req_s header;
        struct cktp_msg_bdy_req_s get_auth_id;
    } __attribute__ ((packed)) request_1;

    request_1.header.type    = CKTP_TYPE_MESSAGE;
    request_1.header.version = CKTP_VERSION;
    request_1.header.size    = CKTP_SIZE(1);
    request_1.header.id      = random_uint32(tunnel->rng);
    request_1.header.seq     = random_uint16(tunnel->rng);
    request_1.get_auth_id.message = CKTP_MESSAGE_GET_AUTH_ID;
    request_1.header.checksum = cktp_checksum(&request_1.header,
        sizeof(request_1));

    // Send message -- Ask for the authentication ID
    trace("[cktp] (" SOCKET_T_FMT ") requesting client identifier",
        tunnel->socket);
    if (!cktp_send_request(tunnel, (uint8_t *)&request_1, sizeof(request_1),
            cktp_reply_get_auth_handler, &request_1, NULL))
    {
        return false;
    }
    if (tunnel->error)
    {
        return false;
    }

    // Send message -- Ask for all sorts of useful information from the
    // server, such as:
    // - Whether tunneling of IPvX is supported;
    // - Our public IP address (if we are behind a NAT);
    struct
    {
        struct cktp_msg_hdr_req_s header;
        struct cktp_msg_bdy_req_s get_flags;
        struct cktp_msg_bdy_req_s get_ip_addr;
        struct cktp_msg_bdy_req_s get_filter;
    } __attribute__ ((packed)) request_2;

    request_2.header.type       = CKTP_TYPE_MESSAGE;
    request_2.header.version    = CKTP_VERSION;
    request_2.header.size       = CKTP_SIZE(3);
    request_2.header.seq        = random_uint16(tunnel->rng);
    request_2.header.id         = tunnel->auth_id;
    request_2.get_flags.message = CKTP_MESSAGE_GET_FLAGS;
    if (tunnel->addrtype == AF_INET)
    {
        request_2.get_ip_addr.message = CKTP_MESSAGE_GET_IPv4_ADDR;
    }
    else
    {
        request_2.get_ip_addr.message = CKTP_MESSAGE_GET_IPv6_ADDR;
    }
    request_2.get_filter.message = CKTP_MESSAGE_GET_FILTER;
    request_2.header.checksum = cktp_checksum(&request_2.header,
        sizeof(request_2));

    trace("[cktp] (" SOCKET_T_FMT ") requesting server parameters",
        tunnel->socket);
    if (!cktp_send_request(tunnel, (uint8_t *)&request_2, sizeof(request_2),
            cktp_reply_get_info_handler, &request_2, NULL))
    {
        return false;
    }
    if (tunnel->error)
    {
        return false;
    }

    // Check that the server's configuration is compatible with ours:
    if (tunnel->addrtype == AF_INET)
    {
        if (!(tunnel->flags & CKTP_FLAG_SUPPORTS_IPv4))
        {
            warning("unable to use tunnel %s; tunnel does not support IPv4",
                tunnel->server_url);
            return false;
        }
    }
    else
    {
        if (!(tunnel->flags & CKTP_FLAG_SUPPORTS_IPv6))
        {
            warning("unable to use tunnel %s; tunnel does not support IPv6",
                tunnel->server_url);
            return false;
        }
    }
    if (!(tunnel->flags & CKTP_FLAG_SUPPORTS_TUNNEL))
    {
        warning("unable to use tunnel %s; tunnel does not support packet "
            "forwarding", tunnel->server_url);
        return false;
    }

    // Check that the server allows HTTP and DNS traffic.
    if (tunnel->filter != CKTP_FILTER_NONE &&
        tunnel->filter != CKTP_FILTER_HTTPDNS_V0)
    {
        warning("unable to use tunnel %s; tunnel does not support HTTP or "
            "DNS packet forwarding", tunnel->server_url);
        return false;
    }

    return true;
}

/*
 * Tests whether we need to reconnect to the server.
 */
bool cktp_tunnel_timeout(cktp_tunnel_t tunnel, uint64_t currtime)
{
    currtime /= MILLISECONDS;
    for (size_t i = 0; tunnel->encodings[i].info != NULL; i++)
    {
        cktp_enc_info_t enc_info = tunnel->encodings[i].info;
        if (enc_info->timeout != NULL)
        {
            cktp_enc_state_t state = tunnel->encodings[i].state;
            uint64_t timeout = enc_info->timeout(state);
            if (timeout < currtime)
            {
                return true;
            }
        }
    }
    return false;
}

/*
 * Perform all of the encoding handshakes.
 */
static bool cktp_encodings_connect(cktp_tunnel_t tunnel)
{
    for (unsigned i = 0; tunnel->encodings[i].info != NULL; i++)
    {
        cktp_enc_info_t enc_info = tunnel->encodings[i].info;
        cktp_enc_state_t state = tunnel->encodings[i].state;
        
        if (enc_info->handshake_request != NULL)
        {
            uint8_t buff[CKTP_MAX_PACKET_SIZE];
            for (unsigned i = 0; i < CKTP_MAX_ENCODING_HANDSHAKE; i++)
            {
                size_t size = sizeof(buff);
                int result = enc_info->handshake_request(state, buff, &size);
                if (result == 0)
                {
                    break;
                }
                if (result < 0)
                {
                    warning("unable to connect to tunnel %s via encoding %s "
                        "(%s)", tunnel->server_url, enc_info->protocol,
                        enc_info->error_string(state, result));
                    return false;
                }

                if (!cktp_send_request(tunnel, buff, size,
                     cktp_encodings_connect_handler, enc_info, state))
                {
                    return false;
                }
            }
        }

        size_t overhead = enc_info->overhead(state);
        tunnel->overhead += overhead;
        tunnel->encodings[i].overhead = overhead;
        tunnel->open_encodings++;
    }

    return true;
}

/*
 * Handler for encoding handshake packet.
 */
static bool cktp_encodings_connect_handler(cktp_tunnel_t tunnel,
    uint8_t *buff, size_t size, void *data1, void *data2)
{
    cktp_enc_info_t enc_info = (cktp_enc_info_t)data1;
    cktp_enc_state_t state = (cktp_enc_state_t)data2;

    errno = 0;
    int result = enc_info->handshake_reply(state, buff, size);
    if (result < 0)
    {
        warning("invalid handshake reply from tunnel %s for encoding %s (%s)",
            tunnel->server_url, enc_info->protocol,
            enc_info->error_string(state, result));
        return false;
    }
    return true;
}

/*
 * Encode a packet.
 */
static bool cktp_encode_packet(cktp_tunnel_t tunnel, uint8_t **buffptr,
    size_t *sizeptr)
{
    for (int i = tunnel->open_encodings-1; i >= 0; i--)
    {
        cktp_enc_info_t enc_info = tunnel->encodings[i].info;
        cktp_enc_state_t enc_state = tunnel->encodings[i].state;
        size_t overhead = tunnel->encodings[i].overhead;
        size_t size0 = *sizeptr;
        uint8_t *buff0 = *buffptr;
        
        int result = enc_info->encode(enc_state, buffptr, sizeptr);
        if (result != 0 ||
            !cktp_encoding_verify(enc_info, overhead, buff0, *buffptr, size0,
                *sizeptr))
        {
            warning("unable to send packet to tunnel %s; encoding %s failed "
                "to encode packet (%s)", tunnel->server_url,
                enc_info->protocol, enc_info->error_string(enc_state, result));
            return false;
        }
    }
    return true;
}

/*
 * Decode a packet.
 */
static bool cktp_decode_packet(cktp_tunnel_t tunnel, uint8_t **buffptr,
    size_t *sizeptr)
{
    for (unsigned i = 0; i < tunnel->open_encodings; i++)
    {
        cktp_enc_info_t enc_info = tunnel->encodings[i].info;
        cktp_enc_state_t enc_state = tunnel->encodings[i].state;
        size_t overhead = tunnel->encodings[i].overhead;
        size_t size0 = *sizeptr;
        uint8_t *buff0 = *buffptr;

        int result = enc_info->decode(enc_state, buffptr, sizeptr);
        if (result != 0 ||
            !cktp_encoding_verify(enc_info, overhead, buff0, *buffptr, size0,
                *sizeptr))
        {
            warning("unable to receive packet from tunnel %s; encoding %s "
                "failed to decode packet (%s)", tunnel->server_url,
                enc_info->protocol, enc_info->error_string(enc_state, result));
            return false;
        }
    }
    return true;
}

/*
 * Send a message packet and wait for a reply.
 */
static bool cktp_send_request(cktp_tunnel_t tunnel, uint8_t *buff, size_t size,
    cktp_reply_handler_t reply_handler, void *data1, void *data2)
{
    unsigned waitsecs = 1;
    for (unsigned i = 0; i < CKTP_MAX_RETRIES; i++)
    {
        // Send the packet:
        {
            // We re-encode for each retry.  This is necessary because each 
            // encoding may result in a different encoded packet (e.g. when
            // using encryption).
            uint8_t enc_buff[CKTP_ENCODING_BUFF_SIZE(size, tunnel->overhead)];
            uint8_t *enc_buff_ptr = CKTP_ENCODING_BUFF_INIT(enc_buff,
                tunnel->overhead);
            size_t enc_size = size;
            memmove(enc_buff_ptr, buff, enc_size);
            if (!cktp_encode_packet(tunnel, &enc_buff_ptr, &enc_size))
            {
                return false;
            }
            if (!cktp_send_packet(tunnel, enc_buff_ptr, enc_size))
            {
                return false;
            }
        }

        // Wait for the reply:
        int64_t rem_usecs = waitsecs*1000000 +
            random_uint32(tunnel->rng) % 1000000;
        while (true)
        {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(tunnel->socket, &fds);
            struct timeval timeout;
            rem_usecs += random_uint32(tunnel->rng) % 1000000;
            timeout.tv_sec  = rem_usecs / 1000000;
            timeout.tv_usec = rem_usecs % 1000000;
            uint64_t time0 = gettime();
            int n = select(tunnel->socket+1, &fds, NULL, NULL, &timeout);
            if (n == 0)
            {
                // Timeout, break to outer loop and try again.
                waitsecs *= CKTP_REPLY_WAIT;
                break;
            }
            else if (n > 0)
            {
                // Received a packet within the time limit.
                uint8_t rep_buff[CKTP_MAX_PACKET_SIZE];
                size_t rep_size;
                uint8_t *rep_buff_ptr = rep_buff;
                if (!cktp_recv_packet(tunnel, &rep_buff_ptr, &rep_size))
                {
                    return false;
                }
                if (rep_buff_ptr != NULL &&
                    cktp_decode_packet(tunnel, &rep_buff_ptr, &rep_size) &&
                    reply_handler(tunnel, rep_buff_ptr, rep_size, data1,
                        data2))
                {
                    return true;
                }

                uint64_t time1 = gettime();
                uint64_t diff = time1 - time0;
                rem_usecs = (diff > rem_usecs? 0: rem_usecs - diff);
            }
            else
            {
                // An error has ocurred.
                warning("unable to wait for message reply from tunnel %s",
                    tunnel->server_url);
                return false;
            }
        }
    }

    errno = ETIMEDOUT;
    warning("unable to send message to tunnel %s", tunnel->server_url);
    return false;
}

/*
 * Handles a 'get auth' reply from the server.
 */
static bool cktp_reply_get_auth_handler(cktp_tunnel_t tunnel, uint8_t *reply,
    size_t reply_size, void *data1, void *data2)
{
    if (!cktp_reply_handler(tunnel, reply, reply_size, data1, data2))
    {
        return false;
    }

    struct cktp_stream_s stream;
    struct cktp_msg_hdr_rep_s *rep_hdr;
    struct cktp_msg_bdy_rep_s *rep_bdy;

    cktp_stream_init(stream, reply_size, reply);
    cktp_stream_get_ptr(stream, struct cktp_msg_hdr_rep_s, rep_hdr, 
        reply_read_error);
    cktp_stream_get_ptr(stream, struct cktp_msg_bdy_rep_s, rep_bdy,
        reply_read_error);
    if (rep_bdy->error != CKTP_OK)
    {
        warning("unable to get client identifier from tunnel %s; tunnel "
            "returned error: %s", tunnel->server_url,
            cktp_error_to_string(rep_bdy->error));
        tunnel->error = true;
        return true;
    }
    cktp_stream_get_val(stream, uint32_t, tunnel->auth_id, reply_read_error);
    
    return true;

reply_read_error:

    warning("unable to get client identifier from tunnel %s; message is "
        "invalid or truncated", tunnel->server_url);
    return false;
}

/*
 * Handles a 'get info' reply from the server.
 */
static bool cktp_reply_get_info_handler(cktp_tunnel_t tunnel, uint8_t *reply,
    size_t reply_size, void *data1, void *data2)
{
    if (!cktp_reply_handler(tunnel, reply, reply_size, data1, data2))
    {
        return false;
    }

    struct cktp_stream_s stream;
    struct cktp_msg_hdr_rep_s *rep_hdr;
    struct cktp_msg_bdy_rep_s *rep_bdy;

    cktp_stream_init(stream, reply_size, reply);
    cktp_stream_get_ptr(stream, struct cktp_msg_hdr_rep_s, rep_hdr,
        reply_read_error);
    cktp_stream_get_ptr(stream, struct cktp_msg_bdy_rep_s, rep_bdy,
        reply_read_error);
    if (rep_bdy->error != CKTP_OK)
    {
        warning("unable to get flags from tunnel %s; tunnel returned "
            "error: %s", tunnel->server_url, 
            cktp_error_to_string(rep_bdy->error));
        tunnel->error = true;
        return true;
    }
    cktp_stream_get_val(stream, uint32_t, tunnel->flags, reply_read_error);

    cktp_stream_get_ptr(stream, struct cktp_msg_bdy_rep_s, rep_bdy,
        reply_read_error);
    if (rep_bdy->error != CKTP_OK)
    {
        warning("unable to IP address from tunnel %s; tunnel returned "
            "error: %s", tunnel->server_url,
            cktp_error_to_string(rep_bdy->error));
        tunnel->error = true;
        return true;
    }
    if (tunnel->addrtype == AF_INET)
    {
        cktp_stream_get_val(stream, uint32_t, tunnel->client_addr[0],
            reply_read_error);
    }
    else
    {
        cktp_stream_get_val(stream, uint32_t, tunnel->client_addr[0],
            reply_read_error);
        cktp_stream_get_val(stream, uint32_t, tunnel->client_addr[1],
            reply_read_error);
        cktp_stream_get_val(stream, uint32_t, tunnel->client_addr[2],
            reply_read_error);
        cktp_stream_get_val(stream, uint32_t, tunnel->client_addr[3],
            reply_read_error);
    }

    cktp_stream_get_ptr(stream, struct cktp_msg_bdy_rep_s, rep_bdy,
        reply_read_error);
    if (rep_bdy->error != CKTP_OK)
    {
        warning("unable to get filter from tunnel %s; tunnel returned "
            "error: %s", tunnel->server_url,
            cktp_error_to_string(rep_bdy->error));
        tunnel->error = true;
        return true;
    }
    uint16_t filter;
    cktp_stream_get_val(stream, uint16_t, filter, reply_read_error);
    tunnel->filter = filter;

    return true;

reply_read_error:

    warning("unable to get parameters from tunnel %s; message is "
        "invalid or truncated", tunnel->server_url);
    return false;
}

/*
 * Handles replies from the server.  Checks that the packet is valid.
 */
static bool cktp_reply_handler(cktp_tunnel_t tunnel, const uint8_t *reply,
    size_t reply_size, void *data1, void *data2)
{
    // Check the validity of the reply header.
    if (reply_size < sizeof(struct cktp_msg_hdr_rep_s))
    {
        warning("invalid message reply from tunnel %s; packet size "
            SIZE_T_FMT " is smaller than the minimum size of " SIZE_T_FMT,
            tunnel->server_url, reply_size, sizeof(struct cktp_msg_hdr_rep_s));
        return false;
    }
    const struct cktp_msg_hdr_req_s *request1 = 
        (const struct cktp_msg_hdr_req_s *)data1;
    struct cktp_msg_hdr_rep_s *reply1 = (struct cktp_msg_hdr_rep_s *)reply;
    if (reply1->seq != request1->seq)
    {
        // Do not warn about this by default -- it may be caused by the client
        // legitimately attempting to open the same tunnel twice.
        if (log_get_level() >= LOG_MESSAGE_TRACE)
        {
            warning("invalid message reply from tunnel %s; expecting sequence "
                "number %u, found %u", tunnel->server_url, request1->seq,
                reply1->seq);
        }
        return false;
    }
    uint16_t reply_checksum = cktp_checksum(reply1, reply_size);
    if (reply1->checksum != reply_checksum)
    {
        warning("invalid message reply from tunnel %s; expecting checksum "
            "0x%.4hx, found 0x%.4hx", tunnel->server_url, reply_checksum,
            reply1->checksum);
        return false;
    }
    
    // Success!
    return true;
}

/*
 * Tunnels an IP packet.
 */
extern void cktp_tunnel_packet(cktp_tunnel_t tunnel, const uint8_t *packet)
{
    if (tunnel == NULL)
    {
        return;
    }
    
    // Check IP version:
    const struct iphdr *ip_header = (const struct iphdr *)packet;
    uint8_t expected_version = (tunnel->addrtype == AF_INET? 4: 6);
    if (expected_version != ip_header->version)
    {
        warning("unable to tunnel packet; expected IP version %u, found %u",
            expected_version, ip_header->version);
        return;
    }

    // Get packet length:
    size_t packet_size;
    switch (tunnel->addrtype)
    {
        case AF_INET:
            packet_size = ntohs(ip_header->tot_len);
            break;
        case AF_INET6:
        {
            struct ip6_hdr *ip6_header = (struct ip6_hdr *)ip_header;
            packet_size = ntohs(ip6_header->ip6_plen);
            break;
        }
        default:
            panic("unknown or unsupported address type %d", tunnel->addrtype);
    }
    if (packet_size > CKTP_MAX_PACKET_SIZE)
    {
packet_too_big_error:
        warning("unable to tunnel packet; packet size (" SIZE_T_FMT ") is too "
            "big, maximum allowed size is %u", packet_size,
            CKTP_MAX_PACKET_SIZE);
        return;
    }

    // Make a copy of the packet:
    uint8_t buff0[CKTP_ENCODING_BUFF_SIZE(packet_size, tunnel->overhead)];
    uint8_t *buff = CKTP_ENCODING_BUFF_INIT(buff0, tunnel->overhead);
    size_t buff_size = packet_size;
    memmove(buff, packet, packet_size);
    struct iphdr *ip_header2 = (struct iphdr *)buff;

    // Adjust the source IP address if the client's IP address doesn't
    // match our public IP address (e.g. we are behind a NAT).
    switch (tunnel->addrtype)
    {
        case AF_INET:
            if (ip_header2->saddr != tunnel->client_addr[0])
            {
                ip_header2->saddr = tunnel->client_addr[0];
                ip_header2->check = 0;
                ip_header2->check = ip_checksum(ip_header2);
                uint8_t *next_header = (uint8_t *)ip_header2 +
                    ip_header2->ihl*sizeof(uint32_t);
                switch (ip_header2->protocol)
                {
                    case IPPROTO_TCP:
                    {
                        struct tcphdr *tcp_header =
                            (struct tcphdr *)next_header;
                        tcp_header->check = 0;
                        tcp_header->check = tcp_checksum(ip_header2);
                        break;
                    }
                    case IPPROTO_UDP:
                    {
                        struct udphdr *udp_header =
                            (struct udphdr *)next_header;
                        udp_header->check = 0;
                        udp_header->check = udp_checksum(ip_header2);
                        break;
                    }
                    default:
                        panic("unsupported IP protocol %u",
                            ip_header2->protocol);
                }
            }
            break;
        case AF_INET6:
            panic("IPv6 not implemented yet");
    }

    // Encode the packet:
    if (!cktp_encode_packet(tunnel, &buff, &buff_size))
    {
        return;
    }
    if (buff_size > CKTP_MAX_PACKET_SIZE)
    {
        goto packet_too_big_error;
    }

    // Track some stats:
    {
        static size_t total_packets = 0;
        static size_t total_bytes = 0;
        total_packets++;
        total_bytes += packet_size;

        // Log this packet if necessary:
        log_packet(packet);

        if (total_packets % 100 == 0)
        {
            log("number of packets tunneled = " SIZE_T_FMT " (total of "
                SIZE_T_FMT "bytes)", total_packets, total_bytes);
        }
    }

    cktp_send_packet(tunnel, buff, buff_size);
}

/*
 * Log a tunneled packet.
 */
static void log_packet(const uint8_t *packet)
{
    if (!log_enabled(LOG_MESSAGE_PACKET))
    {
        return;
    }

    const struct iphdr *ip_header = (const struct iphdr *)packet;
    switch (ip_header->version)
    {
        case 4:
        {
            const struct iphdr *ip_header = (const struct iphdr *)packet;
            const uint8_t *src_ip = (uint8_t *)&ip_header->saddr;
            const uint8_t *dst_ip = (uint8_t *)&ip_header->daddr;
            const uint8_t *next_header = (uint8_t *)ip_header +
                ip_header->ihl*sizeof(uint32_t);
            switch (ip_header->protocol)
            {
                case IPPROTO_TCP:
                {
                    const struct tcphdr *tcp_header = (const struct tcphdr *)
                        next_header;
                    packet("TCP %d.%d.%d.%d:%u to %d.%d.%d.%d:%u %s%s%s%s%s"
                        " (%u bytes)", src_ip[0], src_ip[1], src_ip[2],
                        src_ip[3], ntohs(tcp_header->source),
                        dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
                        ntohs(tcp_header->dest),
                        (tcp_header->syn? "[syn]": ""),
                        (tcp_header->fin? "[fin]": ""),
                        (tcp_header->rst? "[rst]": ""),
                        (tcp_header->psh? "[psh]": ""),
                        (tcp_header->ack? "[ack]": ""),
                        ntohs(ip_header->tot_len));
                    break;
                }
                case IPPROTO_UDP:
                {
                    const struct udphdr *udp_header = (const struct udphdr *)
                        next_header;
                    packet("UDP %d.%d.%d.%d:%u to %d.%d.%d.%d:%u (%u bytes)",
                        src_ip[0], src_ip[1], src_ip[2], src_ip[3],
                        ntohs(udp_header->source),
                        dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
                        ntohs(udp_header->dest),
                        ntohs(ip_header->tot_len));
                    break;
                }
            }
        }
        case 6:
            break;
    }
}

/*
 * Computes the effective MTU of the tunnel.
 */
uint16_t cktp_tunnel_get_mtu(cktp_tunnel_t tunnel, uint16_t mtu0)
{
    int mtu = (int)mtu0;

    switch (tunnel->addrtype)
    {
        case AF_INET:
            mtu -= 0x0F * sizeof(uint32_t);
            break;
        case AF_INET6:
            mtu -= sizeof(struct ip6_hdr);
            break;
        default:
            panic("unknown or unsupported address type %d", tunnel->addrtype);
    }

    switch (tunnel->transport)
    {
        case CKTP_PROTO_IP:
            break;
        case CKTP_PROTO_UDP: case CKTP_PROTO_UDPLITE:
            mtu -= sizeof(struct udphdr);
            break;
        case CKTP_PROTO_PING:
            mtu -= sizeof(struct icmphdr);
            break;
        default:
            panic("unknown or unsupported transport protocol 0x%.2X",
                tunnel->transport);
    }

    mtu -= tunnel->overhead;

    if (mtu < IP_MSS)
    {
        warning("unable to calculate valid MTU of tunnel %s; tunnel "
            "encoding overhead is too high", tunnel->server_url);
        return 0;
    }

    return (uint16_t)mtu;
}

/*
 * Indicates that the given packet is too big, and that fragmentation is
 * required.
 */
void cktp_fragmentation_required(cktp_tunnel_t tunnel, uint16_t mtu,
    const uint8_t *packet)
{
    const struct ethhdr *eth_header = (const struct ethhdr *)packet;
    const struct iphdr *ip_header = (const struct iphdr *)(eth_header + 1);

    switch (ip_header->version)
    {
        case 4:
        {
            uint8_t icmp_body_len = ip_header->ihl*sizeof(uint32_t) + 8;
            uint8_t icmp_len = sizeof(struct icmphdr) + icmp_body_len;
            size_t buff_len = sizeof(struct cktp_rflt_hdr_s) + icmp_len;
            uint8_t buff0[CKTP_ENCODING_BUFF_SIZE(buff_len, tunnel->overhead)];
            uint8_t *buff = CKTP_ENCODING_BUFF_INIT(buff0, tunnel->overhead);
            struct cktp_rflt_hdr_s *reflect = (struct cktp_rflt_hdr_s *)buff;
            reflect->type       = CKTP_TYPE_REFLECT;
            reflect->ip_version = 4;
            reflect->protocol   = IPPROTO_ICMP;
            struct icmphdr *icmp_header = (struct icmphdr *)(reflect + 1);
            memset(icmp_header, 0, sizeof(struct icmphdr));
            icmp_header->type           = ICMP_DEST_UNREACH;
            icmp_header->code           = ICMP_FRAG_NEEDED;
            icmp_header->un.frag.mtu    = htons(mtu);
            uint8_t *icmp_body = (uint8_t *)(icmp_header + 1);
            memmove(icmp_body, ip_header, icmp_body_len);
            struct iphdr *icmp_ip_header = (struct iphdr *)icmp_body;
            if (icmp_ip_header->saddr != tunnel->client_addr[0])
            {
                icmp_ip_header->saddr = tunnel->client_addr[0];
                icmp_ip_header->check = 0;
                icmp_ip_header->check = ip_checksum(icmp_ip_header);
            }
            icmp_header->checksum = 0;
            icmp_header->checksum = icmp_checksum(icmp_header, icmp_len);
            if (!cktp_encode_packet(tunnel, &buff, &buff_len))
            {
                return;
            }
            cktp_send_packet(tunnel, buff, buff_len);
            break;
        }
        case 6:
            panic("not yet implemented: ipv6 packet too big");
        default:
            panic("uknown or unsupported IP version %d", ip_header->version);
    }
}

/*
 * Add transport header.
 */
static void cktp_add_transport_header(cktp_tunnel_t tunnel, uint8_t **packet,
    size_t *length)
{
    switch (tunnel->transport)
    {
        case CKTP_PROTO_PING:
        {
            size_t icmp_len = sizeof(struct icmphdr) + *length;
            *length += sizeof(struct icmphdr);
            *packet -= sizeof(struct icmphdr);
            struct icmphdr *icmp_header = (struct icmphdr *)*packet;
            icmp_header->type = ICMP_ECHO;
            icmp_header->code = 0;
            icmp_header->un.echo.id = tunnel->server_port;
            tunnel->seq++;
            icmp_header->un.echo.sequence = htons(tunnel->seq);
            icmp_header->checksum = 0;
            icmp_header->checksum = icmp_checksum(icmp_header, icmp_len);
            return;
        }
        default:
            return;
    }
}

/*
 * Send a packet.
 */
static bool cktp_send_packet(cktp_tunnel_t tunnel, uint8_t *packet,
    size_t length)
{
    cktp_add_transport_header(tunnel, &packet, &length);
    if (send(tunnel->socket, (char *)packet, length, 0) != length)
    {
        warning("unable to send packet (of size " SIZE_T_FMT ") to tunnel %s",
            length, tunnel->server_url);
        return false;
    }
    return true;
}

/*
 * Strip a transport header.
 */
static bool cktp_strip_transport_header(cktp_tunnel_t tunnel,
    uint8_t **packet, size_t *length)
{
    size_t strip_size = 0;
    switch (tunnel->transport)
    {
        case CKTP_PROTO_IP:
        {
            if (tunnel->addrtype == AF_INET)
            {
                if (*length < sizeof(struct iphdr))
                {
                    return false;
                }
                strip_size = ((struct iphdr *)*packet)->ihl*sizeof(uint32_t);
            }
            else
            {
                // AF_INET6:
                strip_size = sizeof(struct ip6_hdr);
            }
            break;
        }
        case CKTP_PROTO_PING:
        {
            if (tunnel->addrtype == AF_INET)
            {
                if (*length < sizeof(struct iphdr) + sizeof(struct icmphdr))
                {
                    return false;
                }
                struct iphdr *ip_header = (struct iphdr *)*packet;
                size_t ip_header_size = ip_header->ihl*sizeof(uint32_t);
                if (ip_header->ihl < sizeof(struct iphdr) / sizeof(uint32_t) ||
                    *length < ip_header_size + sizeof(struct icmphdr))
                {
                    return false;
                }
                struct icmphdr *icmp_header =
                    (struct icmphdr *)(*packet + ip_header_size);
                if (icmp_header->type != ICMP_ECHOREPLY ||
                    icmp_header->code != 0 ||
                    icmp_header->un.echo.sequence !=
                        htons((uint16_t)tunnel->seq) ||
                    icmp_header->un.echo.id != tunnel->server_port)
                {
                    return false;
                }
                strip_size = ip_header_size + sizeof(struct icmphdr);
            }
            else
            {
                panic("IPv6 not implemented yet");
            }
            break;
        }
        default:
            break;
    }

    if (*length > strip_size)
    {
        *length -= strip_size;
        *packet += strip_size;
        return true;
    }
    return false;
}

/*
 * Receive a packet.
 */
static bool cktp_recv_packet(cktp_tunnel_t tunnel, uint8_t **packet,
    size_t *length)
{
    int n = recv(tunnel->socket, (char *)*packet, CKTP_MAX_PACKET_SIZE, 0);
    if (n < 0)
    {
        warning("unable to receive message from tunnel %s",
            tunnel->server_url);
        return false;
    }
    if (n == 0)
    {
        *packet = NULL;
        return true;
    }

    *length = (size_t)n;
    if (!cktp_strip_transport_header(tunnel, packet, length))
    {
        *packet = NULL;
    }
    return true;
}

/*
 * Close a tunnel.
 */
extern void cktp_close_tunnel(cktp_tunnel_t tunnel)
{
    if (tunnel == NULL)
    {
        return;
    }
    if (tunnel->socket != INVALID_SOCKET && close_socket(tunnel->socket) != 0)
    {
        warning("unable to close socket to tunnel %s", tunnel->server_url);
    }
    if (tunnel->rng != NULL)
    {
        random_free(tunnel->rng);
    }
    for (size_t i = 0; i < tunnel->open_encodings; i++)
    {
        cktp_enc_info_t info = tunnel->encodings[i].info;
        cktp_enc_state_t state = tunnel->encodings[i].state;
        if (state != NULL)
        {
            info->free(state);
        }
    }
    free(tunnel);
}

