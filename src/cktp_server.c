/*
 * cktp_server.c
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

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>

#include "checksum.h"
#include "cktp.h"
#include "cktp_common.h"
#include "cktp_encoding.h"
#include "cktp_server.h"
#include "cktp_url.h"
#include "cookie.h"
#include "thread.h"

#define CKTP_LISTEN_THREADS_MAX     4

/*
 * Prototypes.
 */
static cktp_tunnel_t cktp_clone_tunnel(cktp_tunnel_t tunnel);
static bool cktp_encode_packet(cktp_tunnel_t tunnel, uint8_t **buffptr,
    size_t *sizeptr, unsigned idx);
static int cktp_decode_packet(cktp_tunnel_t tunnel, uint32_t source_addr,
    uint8_t **buffptr, size_t *sizeptr, uint8_t **reply, size_t *replysizeptr);
static void *cktp_listen_loop(void *ptr);
static int64_t cktp_strip_transport_header(cktp_tunnel_t tunnel,
    uint8_t **payload, size_t *payload_size);
static void cktp_add_transport_header(cktp_tunnel_t tunnel, uint8_t **payload,
    size_t *payload_size, int64_t info);
static bool cktp_is_valid_packet(struct iphdr *payload, size_t payload_size,
    uint32_t source_addr);
static bool cktp_request(cktp_tunnel_t tunnel,
    const struct cktp_msg_hdr_req_s *request, size_t request_size,
    uint32_t source_addr, uint8_t *reply, size_t *reply_size);
static void cktp_reflect(struct cktp_rflt_hdr_s *reflect, size_t reflect_size,
    struct sockaddr_in *from_addr, int socket_icmp);
extern void error(const char *message, ...);

/*
 * Holds all relevant information regarding an open CKTP tunnel.
 */
struct cktp_tunnel_s
{
    int socket;                                         // Socket.
    int transport;                                      // Transport.
    uint16_t port;                                      // Port.
    struct cktp_enc_s encodings[CKTP_MAX_ENCODINGS+1];  // Encodings.
    uint8_t open_encodings;                             // #Encodings.
    size_t overhead;                                    // Enc. Overhead.
    struct cookie_gen_s cookie_gen;                     // Cookie generator.
    char url[CKTP_MAX_URL_LENGTH+1];                    // URL.
};

/*
 * Passing parameters to threads.
 */
struct cktp_listen_s
{
    cktp_tunnel_t tunnel;
    int socket_out;
    int socket_icmp;
};

/*
 * Opens a CKTP tunnel end-point.
 */
extern cktp_tunnel_t cktp_open_tunnel(const char *url)
{
    if (strlen(url) >= CKTP_MAX_URL_LENGTH)
    {
        error("unable to parse url %s; url is too long, maximum size is %u",
            url, CKTP_MAX_URL_LENGTH);
        return NULL;
    }

    cktp_tunnel_t tunnel = (cktp_tunnel_t)malloc(sizeof(struct cktp_tunnel_s));
    if (tunnel == NULL)
    {
        error("unable to allocate %zu bytes for tunnel",
            sizeof(struct cktp_tunnel_s));
        return NULL;
    }
    memset(tunnel, 0x0, sizeof(struct cktp_tunnel_s));
    tunnel->socket = -1;

    // Parse the URL:
    strcpy(tunnel->url, url);
    char server_name[CKTP_MAX_URL_LENGTH+1];
    if (!cktp_parse_url(url, &tunnel->transport, server_name, &tunnel->port,
        tunnel->encodings))
    {
        goto open_tunnel_error;
    }
    for (tunnel->open_encodings = 0; 
         tunnel->open_encodings < CKTP_MAX_ENCODINGS &&
         tunnel->encodings[tunnel->open_encodings].info != NULL;
         tunnel->open_encodings++)
    {
        cktp_enc_info_t enc_info =
            tunnel->encodings[tunnel->open_encodings].info;
        cktp_enc_state_t enc_state =
            tunnel->encodings[tunnel->open_encodings].state;
        size_t overhead = enc_info->overhead(enc_state);
        tunnel->encodings[tunnel->open_encodings].overhead = overhead;
        tunnel->overhead += overhead;
    }

    // Open a socket for the server:
    switch (tunnel->transport)
    {
        case CKTP_PROTO_IP:
        {
            tunnel->socket = socket(AF_INET, SOCK_RAW, ntohs(tunnel->port));
            if (tunnel->socket < 0)
            {
                error("unable to open RAW socket with protocol %u for "
                    "server %s", ntohs(tunnel->port), url);
                goto open_tunnel_error;
            }
            int on = 0;
            if (setsockopt(tunnel->socket, IPPROTO_IP, IP_HDRINCL, &on,
                sizeof(on)) != 0)
            {       
                error("unable to disable IP header inclusion for server %s",
                    url);
                goto open_tunnel_error;
            }
            break;
        }
        case CKTP_PROTO_UDP:
        {
            tunnel->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (tunnel->socket < 0)
            {
                error("unable to open UDP socket for server %s", url);
                goto open_tunnel_error;
            }
            int on = 1;
            if (setsockopt(tunnel->socket, SOL_SOCKET, SO_NO_CHECK, &on,
                sizeof(on)) != 0)
            {
                error("unable to disable UDP checksums for server %s", url);
                goto open_tunnel_error;
            }
            break;
        }
        case CKTP_PROTO_PING:
        {
            tunnel->socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (tunnel->socket < 0)
            {
                error("unable to open PING socket for server %s", url);
                goto open_tunnel_error;
            }
            int on = 0;
            if (setsockopt(tunnel->socket, IPPROTO_IP, IP_HDRINCL, &on,
                sizeof(on)) != 0)
            {
                error("unable to disable IP header inclusion for server %s",
                    url);
                goto open_tunnel_error;
            }

            tunnel->overhead += sizeof(struct icmphdr);
            break;
        }
        default:
            error("unable to open socket; unsupported transport protocol "
                "%d for server %s", tunnel->transport, url);
            goto open_tunnel_error;
    }

    // Bind socket:
    struct sockaddr_in from_addr;
    memset(&from_addr, 0x0, sizeof(from_addr));
    from_addr.sin_family      = AF_INET;
    from_addr.sin_port        = tunnel->port;
    from_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(tunnel->socket, (struct sockaddr *)&from_addr, sizeof(from_addr))
        != 0)
    {
        error("unable to bind socket for server %s", url);
        goto open_tunnel_error;
    }

    // Initialise cookie generation:
    cookie_gen_init(&tunnel->cookie_gen);

    return tunnel;

open_tunnel_error:

    cktp_close_tunnel(tunnel);
    return (cktp_tunnel_t)NULL;
}

/*
 * Clones a tunnel.
 */
static cktp_tunnel_t cktp_clone_tunnel(cktp_tunnel_t tunnel)
{
    cktp_tunnel_t newtunnel =
        (cktp_tunnel_t)malloc(sizeof(struct cktp_tunnel_s));
    if (tunnel == NULL)
    {
        error("unable to allocate %zu bytes for tunnel",
            sizeof(struct cktp_tunnel_s));
        exit(EXIT_FAILURE);
    }
    memcpy(newtunnel, tunnel, sizeof(struct cktp_tunnel_s));
    tunnel = newtunnel;

    for (size_t i = 0; i < newtunnel->open_encodings; i++)
    {
        cktp_enc_info_t enc_info = newtunnel->encodings[i].info;
        if (enc_info->clone != NULL)
        {
            cktp_enc_state_t enc_state = newtunnel->encodings[i].state;
            int err = enc_info->clone(enc_state,
                &newtunnel->encodings[i].state);
            if (err != 0)
            {
                error("unable to clone state for encoding %s (%s)",
                    enc_info->protocol,
                    enc_info->error_string(enc_state, err));
                exit(EXIT_FAILURE);
            }
        }
    }

    return newtunnel;
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
    if (tunnel->socket > 0 && close(tunnel->socket) != 0)
    {
        error("unable to close socket");
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

/*
 * Encode a packet.
 */
static bool cktp_encode_packet(cktp_tunnel_t tunnel, uint8_t **buffptr,
    size_t *sizeptr, unsigned idx)
{
    idx = (idx > tunnel->open_encodings? tunnel->open_encodings: idx);
    for (int i = idx-1; i >= 0; i--)
    {
        cktp_enc_info_t enc_info = tunnel->encodings[i].info;
        cktp_enc_state_t enc_state = tunnel->encodings[i].state;
        size_t overhead = tunnel->encodings[i].overhead;
        size_t size0 = *sizeptr;
        uint8_t *buff0 = *buffptr;

        int result = enc_info->encode(enc_state, buffptr, sizeptr);
        
        if (result != 0)
        {
            return false;
        }
        if (!cktp_encoding_verify(enc_info, overhead, buff0, *buffptr, size0,
                *sizeptr))
        {
            return false;
        }
    }
    return true;
}

/*
 * Decode a packet.
 */
static int cktp_decode_packet(cktp_tunnel_t tunnel, uint32_t source_addr,
    uint8_t **buffptr, size_t *sizeptr, uint8_t **replyptr,
    size_t *replysizeptr)
{
    uint8_t *reply = *replyptr;
    for (unsigned i = 0; i < tunnel->open_encodings; i++)
    {
        cktp_enc_info_t enc_info = tunnel->encodings[i].info;
        cktp_enc_state_t enc_state = tunnel->encodings[i].state;
        size_t overhead = tunnel->encodings[i].overhead;
        *replyptr = reply;
        *replysizeptr = CKTP_MAX_PACKET_SIZE;
        size_t size0 = *sizeptr, replysize0 = *replysizeptr;
        uint8_t *buff0 = *buffptr, *reply0 = *replyptr;
        
        int result = enc_info->decode(enc_state, &source_addr, 1, buffptr,
            sizeptr, replyptr, replysizeptr);
        
        if (result != 0)
        {
            return -1;
        }
        if (!cktp_encoding_verify(enc_info, overhead, buff0, *buffptr, size0,
                *sizeptr))
        {
            // No decoded packet -- check for a reply packet:
            if (!cktp_encoding_verify(enc_info, overhead, reply0, *replyptr,
                    replysize0, *replysizeptr))
            {
                return -1;
            }

            // Got a reply packet:
            return i+1;
        }
        // Got a decoded packet, continue:
    }
    return 0;
}

/*
 * Listen for messages.
 */
extern void cktp_listen(cktp_tunnel_t tunnel, int socket_out, int socket_icmp,
    unsigned threads)
{
    // Activate all encodings:
    for (size_t i = 0; i < tunnel->open_encodings; i++)
    {
        cktp_enc_info_t enc_info = tunnel->encodings[i].info;
        cktp_enc_state_t enc_state = tunnel->encodings[i].state;
        if (enc_info->activate != NULL)
        {
            int err = enc_info->activate(enc_state);
            if (err != 0)
            {
                error("unable to activate encoding %s for tunnel %s (%s)",
                    enc_info->protocol, tunnel->url,
                    enc_info->error_string(enc_state, err));
                exit(EXIT_FAILURE);
            }
        }
    }

    // Spawn threads:
    for (unsigned i = 0; i < CKTP_LISTEN_THREADS_MAX-1 && i < threads-1; i++)
    {
        thread_t thread;
        struct cktp_listen_s *params = (struct cktp_listen_s *)
            malloc(sizeof(struct cktp_listen_s));
        if (params == NULL)
        {
            goto params_alloc_error;
        }
        params->tunnel = cktp_clone_tunnel(tunnel);
        params->socket_out = socket_out;
        params->socket_icmp = socket_icmp;
        if (thread_create(&thread, cktp_listen_loop, params) != 0)
        {
            error("unable to create listen thread for tunnel %s",
                tunnel->url);
            exit(EXIT_FAILURE);
        }
    }

    struct cktp_listen_s *params = (struct cktp_listen_s *)
        malloc(sizeof(struct cktp_listen_s));
    if (params == NULL)
    {
        goto params_alloc_error;
    }
    params->tunnel = cktp_clone_tunnel(tunnel);
    params->socket_out = socket_out;
    params->socket_icmp = socket_icmp;
    cktp_listen_loop(params);
    exit(EXIT_SUCCESS);

params_alloc_error:
    
    error("unable to allocate %zu bytes for listen thread parameters for "
        "tunnel %s", sizeof(struct cktp_listen_s), tunnel->url);
    exit(EXIT_FAILURE);
}

/*
 * Main server loop.
 */
static void *cktp_listen_loop(void *ptr)
{
    struct cktp_listen_s *params = (struct cktp_listen_s *)ptr;
    cktp_tunnel_t tunnel = params->tunnel;
    int socket_out  = params->socket_out;
    int socket_icmp = params->socket_icmp;
    free(params);

    struct sockaddr_in from_addr;
    struct sockaddr_in to_addr;
    memset(&to_addr, 0x0, sizeof(to_addr));
    to_addr.sin_family = AF_INET;

    // Use malloc instead of allocating from the stack -- probably safer.
    size_t trans_hdr_size;
    switch (tunnel->transport)
    {
        case CKTP_PROTO_IP:
            trans_hdr_size = 0xF*sizeof(uint32_t);
            break;
        case CKTP_PROTO_PING:
            trans_hdr_size = 0xF*sizeof(uint32_t) + sizeof(struct icmphdr);
            break;
        default:
            trans_hdr_size = 0;
            break;
    }
    size_t packet_size = CKTP_MAX_PACKET_SIZE + trans_hdr_size;
    uint8_t *packet = (uint8_t *)malloc(packet_size);
    uint8_t *reply_buff = (uint8_t *)malloc(
        CKTP_ENCODING_BUFF_SIZE(CKTP_MAX_PACKET_SIZE, tunnel->overhead));
    if (packet == NULL || reply_buff == NULL)
    {
        error("unable to allocate memory for packet buffers");
        exit(EXIT_FAILURE);
    }
    uint8_t *reply = CKTP_ENCODING_BUFF_INIT(reply_buff, tunnel->overhead);

    // Main server loop:
    while (true)
    {
        // Receive a packet:
        socklen_t from_addr_len = sizeof(struct sockaddr_in);
        int result = recvfrom(tunnel->socket, packet, packet_size, 0,
            (struct sockaddr *)&from_addr, &from_addr_len);
        if (result <= 0)
        {
            continue;
        }

        uint8_t *payload = packet;
        size_t payload_size = (size_t)result;

        // Strip the transport header:
        int64_t info = cktp_strip_transport_header(tunnel, &payload,
            &payload_size);
        if (info < 0)
        {
            continue;
        }

        // Decode the packet (if required):
        if (tunnel->open_encodings > 0)
        {
            size_t reply_size;
            uint8_t *reply_ptr = reply;

            int result = cktp_decode_packet(tunnel, from_addr.sin_addr.s_addr,
                &payload, &payload_size, &reply_ptr, &reply_size);
            if (result < 0)
            {
                // Decoding error:
                continue;
            }

            if (result > 0)
            {
                // Got a reply packet:
                unsigned idx = result-1;
                if (cktp_encode_packet(tunnel, &reply, &reply_size, idx))
                {
                    cktp_add_transport_header(tunnel, &reply, &reply_size,
                        info);
                    sendto(tunnel->socket, reply, reply_size, 0,
                        (struct sockaddr *)&from_addr, sizeof(from_addr));
                }
                continue;
            }

            // Otherwise, packet decoded successfully:
        }

        // Handle the packet:
        struct cktp_msg_hdr_req_s *request =
            (struct cktp_msg_hdr_req_s *)payload;
        switch (request->type)
        {
            case CKTP_TYPE_REFLECT:
            {
                struct cktp_rflt_hdr_s *reflect =
                    (struct cktp_rflt_hdr_s *)request;
                cktp_reflect(reflect, payload_size, &from_addr, socket_icmp);
                break;
            }
            case CKTP_TYPE_IPv4:
            {
                struct iphdr *ip_header = (struct iphdr *)request;

                if (!cktp_is_valid_packet(ip_header, payload_size,
                    from_addr.sin_addr.s_addr))
                {
                    continue;
                }

                to_addr.sin_addr.s_addr = ip_header->daddr;
                sendto(socket_out, payload, payload_size, 0,
                    (struct sockaddr *)&to_addr, sizeof(to_addr));
                break;
            }
            case CKTP_TYPE_IPv6:
                // NYI: IPv6
                continue;
            case CKTP_TYPE_MESSAGE:
            {
                size_t reply_size;
                if (!cktp_request(tunnel, request, payload_size,
                    from_addr.sin_addr.s_addr, reply, &reply_size))
                {
                    continue;
                }
                uint8_t *reply_ptr = reply;
                if (tunnel->open_encodings > 0)
                {
                    if (!cktp_encode_packet(tunnel, &reply_ptr, &reply_size,
                        INT32_MAX))
                    {
                        continue;
                    }
                }
                cktp_add_transport_header(tunnel, &reply_ptr, &reply_size,
                    info);
                sendto(tunnel->socket, reply_ptr, reply_size, 0,
                    (struct sockaddr *)&from_addr, sizeof(from_addr));
                break;
            }
            default:
                continue;
        }
    }
}

/*
 * Strip transport header if required.
 */
static int64_t cktp_strip_transport_header(cktp_tunnel_t tunnel,
    uint8_t **payload, size_t *payload_size)
{
    switch (tunnel->transport)
    {
        case CKTP_PROTO_IP:
        {
            if (*payload_size < sizeof(struct iphdr))
            {
                return -1;
            }
            struct iphdr *ip_header = (struct iphdr *)*payload;
            if (ip_header->ihl < 5)
            {
                return -1;
            }
            size_t ip_header_size = ip_header->ihl*sizeof(uint32_t);
            if (*payload_size < ip_header_size)
            {
                return -1;
            }
            *payload += ip_header_size;
            *payload_size -= ip_header_size;
            return 0;
        }
        case CKTP_PROTO_PING:
        {
            if (*payload_size < sizeof(struct iphdr) + sizeof(struct icmphdr))
            {
                return -1;
            }
            struct iphdr *ip_header = (struct iphdr *)*payload;
            if (ip_header->ihl < 5)
            {
                return -1;
            }
            size_t ip_header_size = ip_header->ihl*sizeof(uint32_t);
            if (*payload_size < ip_header_size + sizeof(struct icmphdr))
            {
                return -1;
            }
            struct icmphdr *icmp_header =
                (struct icmphdr *)(*payload + ip_header_size);
            if (icmp_header->type != ICMP_ECHO ||
                icmp_header->code != 0 ||
                icmp_header->un.echo.id != tunnel->port)
            {
                return -1;
            }
            size_t hdr_size = ip_header_size + sizeof(struct icmphdr);
            *payload += hdr_size;
            *payload_size -= hdr_size;
            int64_t info = (int64_t)icmp_header->un.echo.sequence;
            info <<= 16;
            info |= (int64_t)icmp_header->un.echo.id;
            return info;
        }
        default:
            return 0;
    }
}

/*
 * Add transport header.
 */
static void cktp_add_transport_header(cktp_tunnel_t tunnel, uint8_t **payload,
    size_t *payload_size, int64_t info)
{
    switch (tunnel->transport)
    {
        case CKTP_PROTO_PING:
        {
            size_t icmp_len = sizeof(struct icmphdr) + *payload_size;
            *payload -= sizeof(struct icmphdr);
            *payload_size += sizeof(struct icmphdr);
            struct icmphdr *icmp_header = (struct icmphdr *)*payload;
            icmp_header->type = ICMP_ECHOREPLY;
            icmp_header->code = 0;
            icmp_header->un.echo.id = (uint16_t)info;
            info >>= 16;
            icmp_header->un.echo.sequence = (uint16_t)info;
            icmp_header->checksum = 0;
            icmp_header->checksum = icmp_checksum(icmp_header, icmp_len);
            return;
        }
        default:
            return;
    }
}

/*
 * Check if the given IPv4 packet can be forwarded or not. 
 */
static bool cktp_is_valid_packet(struct iphdr *payload, size_t payload_size,
    uint32_t source_addr)
{
    // Preliminary checks:
    if ((uint16_t)payload_size != ntohs(payload->tot_len) ||
        payload->saddr != source_addr ||
        payload->ihl < 5) // RFC 791
    {
        return false;
    }

    // Protocol checks:
    uint8_t *next_header = (uint8_t *)payload + payload->ihl*sizeof(uint32_t);
    switch (payload->protocol)
    {
        case IPPROTO_TCP:
            if (payload_size < payload->ihl*sizeof(uint32_t) +
                sizeof(struct tcphdr))
            {
                return false;
            }
            struct tcphdr *tcp_header = (struct tcphdr *)next_header;
            if (tcp_header->dest != htons(80))
            {
                return false;
            }
            break;
        case IPPROTO_UDP:
            if (payload_size < payload->ihl*sizeof(uint32_t) +
                sizeof(struct udphdr))
            {
                return false;
            }
            struct udphdr *udp_header = (struct udphdr *)next_header;
            if (udp_header->dest != htons(53))
            {
                return false;
            }
            break;
        default:
            return false;
    }

    return cktp_is_ipv4_addr_public(payload->daddr);
}

/*
 * Check if an IPv4 address is public or not.
 */
bool cktp_is_ipv4_addr_public(uint32_t addr)
{
    // Check if the destination address is valid:
    switch ((uint8_t)addr)
    {
        case 0:     // Current Network: RFC 1700
            return false;
        case 10:    // Private Network: RFC 1918
            return false;
        case 127:   // Loopback: RFC 3330
            return false;
        case 172:
        {
            uint8_t b = (uint8_t)(addr >> 8);
            if (b >= 16 && b <= 31) // Private Network: RFC 1918
            {
                 return false;
            }
            break;
        }
        case 192:
        {
            uint8_t b = (uint8_t)(addr >> 8);
            if (b == 168) // Private Network: RFC 1918
            {
                return false;
            }
            break;
        }
        case 255:
        {
            if (addr == INADDR_BROADCAST) // Broadcast: RFC 919
            {
                return false;
            }
            break;
        }
    }

    return true;
}

/*
 * Handle message requests.
 */
static bool cktp_request(cktp_tunnel_t tunnel,
    const struct cktp_msg_hdr_req_s *request, size_t request_size,
    uint32_t source_addr, uint8_t *reply, size_t *reply_size)
{
    // Basic checks:
    if (request->version != CKTP_VERSION ||
        request->size > CKTP_SIZE(CKTP_MAX_REQUESTS) ||
        request->checksum != cktp_checksum(request, request_size))
    {
        return NULL;
    }

    // Parse request:
    uint32_t id = generate_cookie32(&tunnel->cookie_gen, &source_addr, 1);
    struct cktp_stream_s req;
    cktp_stream_init(req, request_size, request);
    cktp_stream_get_ptr(req, struct cktp_msg_hdr_req_s, request, stream_error);
    struct cktp_stream_s rep;
    cktp_stream_init(rep, CKTP_MAX_PACKET_SIZE, reply);
    struct cktp_msg_hdr_rep_s *rep_hdr;
    cktp_stream_get_ptr(rep, struct cktp_msg_hdr_rep_s, rep_hdr, stream_error);
    rep_hdr->seq = request->seq;
    uint32_t *uint32_ptr;
    uint16_t *uint16_ptr;
    for (size_t i = 0; i <= request->size; i++)
    {
        struct cktp_msg_bdy_req_s *req_bdy;
        cktp_stream_get_ptr(req, struct cktp_msg_bdy_req_s, req_bdy,
            stream_error);
        struct cktp_msg_bdy_rep_s *rep_bdy;
        cktp_stream_get_ptr(rep, struct cktp_msg_bdy_rep_s, rep_bdy,
            stream_error);
        if (request->id == id)
        {
            switch (req_bdy->message)
            {
                case CKTP_MESSAGE_NOP:
                    rep_bdy->error = CKTP_OK;
                    break;
                case CKTP_MESSAGE_GET_AUTH_ID:
                    rep_bdy->error = CKTP_OK;
                    cktp_stream_get_ptr(rep, uint32_t, uint32_ptr,
                        stream_error);
                    *uint32_ptr = id;
                    break;
                case CKTP_MESSAGE_GET_FLAGS:
                    rep_bdy->error = CKTP_OK;
                    cktp_stream_get_ptr(rep, uint32_t, uint32_ptr,
                        stream_error);
                    *uint32_ptr = CKTP_FLAG_SUPPORTS_IPv4 |
                                  CKTP_FLAG_SUPPORTS_TUNNEL;
                    break;
                case CKTP_MESSAGE_GET_IPv4_ADDR:
                    rep_bdy->error = CKTP_OK;
                    cktp_stream_get_ptr(rep, uint32_t, uint32_ptr,
                        stream_error);
                    *uint32_ptr = source_addr;
                    break;
                case CKTP_MESSAGE_GET_IPv6_ADDR:
                    rep_bdy->error = CKTP_ERROR_NOT_SUPPORTED;
                    break;
                case CKTP_MESSAGE_GET_FILTER:
                    rep_bdy->error = CKTP_OK;
                    cktp_stream_get_ptr(rep, uint16_t, uint16_ptr,
                        stream_error);
                    *uint16_ptr = CKTP_FILTER_HTTPDNS_V0;
                    break;
                default:
                    rep_bdy->error = CKTP_ERROR_NOT_SUPPORTED;
                    break;
            }
        }
        else
        {
            if (req_bdy->message == CKTP_MESSAGE_GET_AUTH_ID)
            {
                rep_bdy->error = CKTP_OK;
                cktp_stream_get_ptr(rep, uint32_t, uint32_ptr,
                    stream_error);
                *uint32_ptr = id;
            }
            else
            {
                rep_bdy->error = CKTP_ERROR_NOT_AUTHENTICATED;
            }
        }
    }

    *reply_size = cktp_stream_pos(rep);
    rep_hdr->checksum = cktp_checksum(rep_hdr, *reply_size);
    return true;

stream_error:
    return false;
}

/*
 * Reflect packets back to the source.
 */
static void cktp_reflect(struct cktp_rflt_hdr_s *reflect, size_t reflect_size,
    struct sockaddr_in *from_addr, int socket_icmp)
{
    if (reflect_size < sizeof(struct cktp_rflt_hdr_s) +
            sizeof(struct icmphdr) + sizeof(struct iphdr) + 8 ||
        reflect->ip_version != 4 ||
        reflect->protocol != IPPROTO_ICMP)
    {
        return;
    }

    reflect_size -= sizeof(struct cktp_rflt_hdr_s);
    struct icmphdr *icmp_header = (struct icmphdr *)(reflect + 1);
    if (icmp_header->type != ICMP_DEST_UNREACH ||
        icmp_header->code != ICMP_FRAG_NEEDED)
    {
        return;
    }

    struct iphdr *ip_header = (struct iphdr *)(icmp_header + 1);
    if (reflect_size != sizeof(struct icmphdr) +
            ip_header->ihl*sizeof(uint32_t) + 8)
    {
        return;
    }

    sendto(socket_icmp, (uint8_t *)icmp_header, reflect_size, 0,
        (struct sockaddr *)from_addr, sizeof(struct sockaddr_in));
}

