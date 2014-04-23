/*
 * cktp.h
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

#ifndef __CKTP_H
#define __CKTP_H

#include <stdbool.h>
#include <stdint.h>

/*
 * - This protocol deliberately DOES NOT use network byte order EXCEPT for
 *   IP addresses and port numbers.
 */

/*****************************************************************************/
/* APPLICATION LAYER                                                         */
/*****************************************************************************/

/*
 * Various useful constraints.
 */
#define CKTP_MAX_STRING_LENGTH   0xFF /* Maximum string length           */
#define CKTP_MAX_URL_LENGTH      1024 /* Maximum URL length              */
#define CKTP_MAX_RETRIES         5    /* Maximum request retries         */
#define CKTP_REPLY_WAIT          2    /* Reply wait time factor          */
#define CKTP_MAX_PACKET_SIZE     8192 /* Maximum allowed packet size     */
#define CKTP_MAX_REQUESTS        32   /* Maximum requests per message    */
#define CKTP_NO_AUTH_ID          0    /* No authentication ID            */

/*
 * VERSION defines the version number of this protocol.
 */
#define CKTP_VERSION             0

/*
 * TYPE defines what the payload actually is.
 */
#define CKTP_TYPE_REFLECT        3 /* Payload is packet to client            */
#define CKTP_TYPE_IPv4           4 /* Payload is an IPv4 packet              */
#define CKTP_TYPE_MESSAGE        5 /* Payload is a CKTP protocol message     */
#define CKTP_TYPE_IPv6           6 /* Payload is an IPv6 packet              */

/*
 * MESSAGE enumerates the different message types.
 */
#define CKTP_MESSAGE_NOP            0x00 /* Do nothing                      */
#define CKTP_MESSAGE_GET_AUTH_ID    0x01 /* Get the authentication ID       */
#define CKTP_MESSAGE_GET_FLAGS      0x02 /* Get the server's flags          */
#define CKTP_MESSAGE_GET_IPv4_ADDR  0x03 /* Get public IPv4 address         */
#define CKTP_MESSAGE_GET_IPv6_ADDR  0x04 /* Get public IPv6 address         */
#define CKTP_MESSAGE_GET_FILTER     0x05 /* Get the server's filter         */

/*
 * FLAGS for CKTP_MESSAGE_GET_FLAGS
 */
#define CKTP_FLAG_SUPPORTS_IPv4     0x00000001  /* IPv4 is supported. */
#define CKTP_FLAG_SUPPORTS_IPv6     0x00000002  /* IPv6 is supported. */
#define CKTP_FLAG_SUPPORTS_TUNNEL   0x00000004  /* Tunneling is supported. */

/*
 * FILTERS for CKTP_MESSAGE_GET_FILTER
 */
#define CKTP_FILTER_NONE            0x0000      /* No filter is applied. */
#define CKTP_FILTER_HTTPDNS_V0      0x0100      /* HTTP & DNS are allowed. */

/*
 * ERROR codes.
 */
#define CKTP_OK                      0x00 /* No error.                    */
#define CKTP_ERROR_NOT_AUTHENTICATED 0x01 /* Invalid authentication ID.   */
#define CKTP_ERROR_NOT_SUPPORTED     0x02 /* Operation not supported.     */
#define CKTP_ERROR_INVALID_ARGUMENT  0x03 /* Invalid argument.            */

/*
 * Boolean values.
 */
#define CKTP_BOOLEAN_TRUE     0xFF /* Alternatively, any non-zero value. */
#define CKTP_BOOLEAN_FALSE    0x00

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Type  |  IPv  |   Protocol    | 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct cktp_rflt_hdr_s
{
    uint8_t  ip_version:4;
    uint8_t  type:4;
    uint8_t  protocol;
} __attribute__((__packed__));

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Type  |  Ver  |           Checksum            |     Size      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    AuthenticationIdentifier                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        SequenceNumber         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct cktp_msg_hdr_req_s
{
    uint8_t  version:4;     /* Version, must be CKTP_VERSION          */
    uint8_t  type:4;        /* Type, must be CKTP_TYPE_MESSAGE        */
    uint16_t checksum;      /* Checksum, CRC16 0x1021                 */
    uint8_t  size;          /* Number of messages - 1                 */
    uint32_t id;            /* Authentication ID                      */
    uint16_t seq;           /* Sequence number                        */
} __attribute__((__packed__));
#define CKTP_SIZE(size)     ((size)-1)

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |        SequenceNumber         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct cktp_msg_hdr_rep_s
{
    uint16_t checksum;  /* Checksum, CRC16 0x1021.              */
    uint16_t seq;       /* Sequence number.                     */
} __attribute__((__packed__));

struct cktp_msg_bdy_req_s
{
    uint8_t message;
};

struct cktp_msg_bdy_rep_s
{
    uint8_t error;
};

struct cktp_string_s
{
    uint8_t length;
    uint8_t chars[0];
} __attribute__((__packed__));

/*****************************************************************************/
/* UTILITIES                                                                 */
/*****************************************************************************/

struct cktp_buffer_s
{
    uint16_t length;
    uint16_t start;
    uint8_t  buffer[CKTP_MAX_PACKET_SIZE];
};

struct cktp_stream_s
{
    uint16_t pos;
    uint16_t size;
    uint8_t *pkt;
};

#define cktp_stream_init(stream, length, packet)                              \
    do {                                                                      \
        (stream).pos  = 0;                                                    \
        (stream).size = (length);                                             \
        (stream).pkt  = (uint8_t *)(packet);                                  \
    } while (false)
#define cktp_stream_get_ptr(stream, type, out, error)                         \
    do {                                                                      \
        out = (type *)((stream).pkt + (stream).pos);                          \
        (stream).pos += sizeof(type);                                         \
        if ((stream).pos > (stream).size)                                     \
            goto error;                                                       \
    } while (false)
#define cktp_stream_get_val(stream, type, out, error)                         \
    do {                                                                      \
        out = *(type *)((stream).pkt + (stream).pos);                         \
        (stream).pos += sizeof(type);                                         \
        if ((stream).pos > (stream).size)                                     \
            goto error;                                                       \
    } while (false)
#define cktp_stream_get_string(stream, out, error)                            \
    do {                                                                      \
        out = ((struct cktp_string_s *)((stream).pkt))->chars;                \
        (stream).pos += sizeof(struct cktp_string_s) +                        \
            (struct cktp_string_s *)((stream).pkt)->length + 1;               \
        if ((stream).pos > (stream).size)                                     \
            goto error;                                                       \
    } while (false)
#define cktp_stream_pos(stream)                                               \
    ((stream).pos)

#endif      /* __CKTP_H */
