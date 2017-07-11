/*
 * packet_protocol.c
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "packet.h"
#include "packet_protocol.h"
#include "random.h"

/*
 * DNS structures.
 */
struct dnshdr
{
    uint16_t id;
    uint16_t option;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((__packed__));

/*
 * TLS structures.
 */
struct tlshdr
{
    uint8_t content_type; 
    uint16_t version;
    uint16_t length;
} __attribute__((__packed__));

struct client_hello_s
{
    uint8_t type;
    uint8_t length[3];
    uint16_t version;
    uint8_t random[32];
} __attribute__((__packed__));

struct extension_s
{
    uint16_t type;
    uint16_t length;
} __attribute__((__packed__));

struct sni_s
{
    uint16_t length;
    uint16_t type;
    uint8_t name_len;
} __attribute__((__packed__));

/*
 * Prototypes.
 */
static bool http_url_match(uint8_t *packet, size_t *start, size_t *end);
static void http_url_generate(uint8_t *packet, uint64_t hash);
static bool dns_match(uint8_t *packet, size_t *start, size_t *end);
static void dns_generate(uint8_t *packet, uint64_t hash);
static bool tls_sni_match(uint8_t *packet, size_t *start, size_t *end);
static void tls_sni_generate(uint8_t *packet, uint64_t hash);

/*
 * Global pre-defined protocols:
 */
static const struct proto_s protocols[] =
{
    {"http_url", http_url_match, http_url_generate},
    {"dns", dns_match, dns_generate},
    {"tls_sni", tls_sni_match, /*tsl_sni_generate*/NULL},
    {NULL, NULL, NULL}
};

/*
 * Return the proto_t associated with the given protocol name.
 */
proto_t protocol_get(const char *name)
{
    for (uint8_t i = 0; protocols[i].name != NULL; i++)
    {
        if (strcmp(name, protocols[i].name) == 0)
        {
            return i;
        }
    }
    warning("unable to find protocol with name \"%s\"; substituting the "
        "default protocol \"%s\"", name, protocols[PROTOCOL_DEFAULT].name);
    return PROTOCOL_DEFAULT;
}

/*
 * Return the struct proto_s associated with the given proto_t.
 */
const struct proto_s *protocol_get_def(proto_t proto)
{
    if (proto < sizeof(protocols) / sizeof(struct proto_s))
    {
        return &protocols[proto];
    }
    panic("invalid protocol %u", proto);
}

/*
 * Match a URL from a HTTP packet.
 * NOTE: uses a simple heuristic: simply searches for the last "Host" header.
 */
bool http_url_match(uint8_t *packet, size_t *start, size_t *end)
{
    uint8_t *data;
    size_t data_len;
    packet_init(packet, false, NULL, NULL, NULL, NULL, NULL, &data, NULL,
        &data_len);
    if (data == NULL)
    {
        return false;
    }

    static const char *host_header = "\r\nhost: ";
    size_t i = 0, host_start = 0;
    bool found = false;
    while (i < data_len)
    {
        int state = 0;
        for (; i < data_len && host_header[state]; i++)
        {
            if (tolower(data[i]) == host_header[state])
            {
                state++;
            }
            else if(data[i] == '\r')
            {
                state = 1;
            }
            else
            {
                state = 0;
            }
        }

        if (!host_header[state] && data[i] != '\r')
        {
            found = true;
            host_start = i;
        }
    }

    // Fail if we did not find a host header:
    if (!found)
    {
        return false;
    }

    // Find the end of the domain name:
    *start = host_start;
    for (i = host_start; i < data_len && data[i] != '\r'; i++)
        ;
    if (data[i] == '\r')
    {
        *end = i-1;
    }
    else
    {
        *end = i;
    }
    return true;
}

/*
 * Generate a random HTTP requests.
 */
#define MAX_URI_LENGTH          128
#define MIN_HOST_LENGTH         3
#define MAX_HOST_LENGTH         40
#define MIN_HEADER_LENGTH       4
#define MAX_HEADER_LENGTH       20
#define MIN_HEADER_VAL_LENGTH   8
#define MAX_HEADER_VAL_LENGTH   64
#define MAX_HEADERS             4
static void http_url_generate(uint8_t *packet, uint64_t hash)
{
    uint8_t *data;
    size_t data_len;
    packet_init(packet, false, NULL, NULL, NULL, NULL, NULL, &data, NULL,
        &data_len);
    if (data == NULL)
    {
        return;
    }

    rand_state_t rng = rand_init(hash);
    size_t i = 0;
    while (i < data_len)
    {
        static const char get_str[] = "GET /";
        for (; i < data_len && i < sizeof(get_str)-1; i++)
        {
            data[i] = get_str[i];
        }
        if (i >= data_len)
        {
            rand_free(rng);
            return;
        }
        static const char uri_str[] = "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_///";
        size_t max_uri = i + rand_uint32(rng) % MAX_URI_LENGTH;
        for (; i < data_len && i < max_uri; i++)
        {
            data[i] = uri_str[rand_uint32(rng) % (sizeof(uri_str)-1)];
        }
        static const char end_uri_str[] = " HTTP/1.1\r\nHost: ";
        size_t i0 = i;
        for (; i < data_len && i < i0 + sizeof(end_uri_str)-1; i++)
        {
            data[i] = end_uri_str[i - i0];
        }
        static const char host_str[] = "abcdefghijklmnopqrstuvwxyz1234567890-.";
        size_t max_host = i + MIN_HOST_LENGTH +
            rand_uint32(rng) % (MAX_HOST_LENGTH - MIN_HOST_LENGTH);
        for (; i < data_len && i < max_host; i++)
        {
            data[i] = host_str[rand_uint32(rng) % (sizeof(host_str)-1)];
        }
        static const char end_host_str[] = ".com\r\n";
        i0 = i;
        for (; i < data_len && i < i0 + sizeof(end_host_str)-1; i++)
        {
            data[i] = end_host_str[i - i0];
        }
        int max_hdrs = rand_uint32(rng) % MAX_HEADERS;
        for (unsigned j = 0; i < data_len && j < max_hdrs; j++)
        {
            static const char header_str[] = "abcdefhijklmnopqrstuvwxyz-";
            size_t max_hdr = i + MIN_HEADER_LENGTH +
                rand_uint32(rng) % (MAX_HEADER_LENGTH - MIN_HEADER_LENGTH);
            bool upper = true;
            for (; i < data_len && i < max_hdr; i++)
            {
                char c = header_str[rand_uint32(rng) % (sizeof(header_str)-1)];
                c = (upper && c == '-'? 'X': c);
                data[i] = (upper? toupper(c): c);
                upper = (c == '-');
            }
            static const char header_sep_str[] = ": ";
            i0 = i;
            for (; i < data_len && i < i0 + sizeof(header_sep_str)-1; i++)
            {
                data[i] = header_sep_str[i - i0];
            }
            static const char header_val_str[] =
                "abcdefhijklmnopqrstuvwxyzABCDEFHIJKLMNOPQRSTUVWXYZ1234567890"
                "!@#$%^&*()-_=+/?.>,<~;:'\" ";
            size_t max_hdr_val = i + MIN_HEADER_VAL_LENGTH +
                rand_uint32(rng) %
                (MAX_HEADER_VAL_LENGTH - MIN_HEADER_VAL_LENGTH);
            for (; i < data_len && i < max_hdr_val; i++)
            {
                data[i] = header_val_str[rand_uint32(rng) %
                    (sizeof(header_val_str)-1)];
            }
            static const char end_header_str[] = "\r\n";
            i0 = i;
            for (; i < data_len && i < i0 + sizeof(end_header_str)-1; i++)
            {
                data[i] = end_header_str[i - i0];
            }
        }
        static const char end_req_str[] = "\r\n";
        i0 = i;
        for (; i < data_len && i < i0 + sizeof(end_req_str)-1; i++)
        {
            data[i] = end_req_str[i - i0];
        }
    }

    rand_free(rng);
}

/*
 * Match a DNS query.
 */
bool dns_match(uint8_t *packet, size_t *start, size_t *end)
{
    uint8_t *data;
    size_t data_len;
    packet_init(packet, false, NULL, NULL, NULL, NULL, NULL, &data, NULL,
        &data_len);
    if (data == NULL)
    {
        return false;
    }

    if (data_len < sizeof(struct dnshdr) + 2*sizeof(uint16_t) + sizeof(uint8_t))
    {
        return false;
    }

    return true;
}

/*
 * Generate a random DNS request.
 */
#define MIN_LABEL_LENGTH    1
#define MAX_LABEL_LENGTH    32
void dns_generate(uint8_t *packet, uint64_t hash)
{
    uint8_t *data;
    size_t data_len;
    packet_init(packet, false, NULL, NULL, NULL, NULL, NULL, &data, NULL,
        &data_len);
    if (data == NULL)
    {
        return;
    }

    if (data_len < sizeof(struct dnshdr))
    {
        return;
    }

    struct dnshdr *dns_header = (struct dnshdr *)data;
    rand_state_t rng = rand_init(hash);
    dns_header->id      = rand_uint32(rng);
    dns_header->option  = htons(0x0100);    // Standard Query.
    dns_header->qdcount = htons(1); 
    dns_header->ancount = htons(0);
    dns_header->nscount = htons(0);
    dns_header->arcount = htons(0);

    uint8_t *labels = data + sizeof(struct dnshdr);
    size_t labels_size = data_len - sizeof(struct dnshdr) -
        2*sizeof(uint16_t) - sizeof(uint8_t);
    size_t i = 0;
    while (i < labels_size)
    {
        size_t label_len = MIN_LABEL_LENGTH +
            rand_uint32(rng) % (MAX_LABEL_LENGTH - MIN_LABEL_LENGTH);
        if (label_len + 1 > labels_size - i)
        {
            label_len = (labels_size - i) - 1;
        }
        labels[i++] = label_len;
        static const char label_str[] = "abcdefghijklmnopqrstuvwxyz-";
        for (int j = 0; j < label_len; j++)
        {
            labels[i++] = label_str[rand_uint32(rng) % (sizeof(label_str)-1)];
        }
    }
    labels[i++] = 0x0;
    labels[i++] = 0x0;
    labels[i++] = 0x1;
    labels[i++] = 0x0;
    labels[i++] = 0x1;
    rand_free(rng);
}

/*
 * Match a TLS
 */
bool tls_sni_match(uint8_t *packet, size_t *start, size_t *end)
{
    uint8_t *data;
    ssize_t data_len;
    packet_init(packet, false, NULL, NULL, NULL, NULL, NULL, &data, NULL,
        &data_len);
    if (data == NULL)
    {
        return false;
    }
    if (data_len <= sizeof(struct tlshdr))
    {
        return false;
    }
    struct tlshdr *tls_header = (struct tlshdr *)data;
    if (tls_header->content_type != 0x16)
    {
        return false;
    }
    data_len -= sizeof(struct tlshdr);
    if (data_len <= sizeof(struct client_hello_s))
    {
        return false;
    }
    struct client_hello_s *client_hello =
        (struct client_hello_s *)(tls_header + 1);
    if (client_hello->type != 0x01)
    {
        return false;
    }
    data_len -= sizeof(struct client_hello_s);
    if (data_len <= sizeof(uint8_t))
    {
        return false;
    }
    uint8_t *len8 = (uint8_t *)(client_hello + 1);
    data_len -= sizeof(uint8_t) + *len8;
    if (data_len <= sizeof(uint16_t))
    {
        return false;
    }
    uint16_t *len16 = (uint16_t *)(len8 + 1 + *len8);
    data_len -= sizeof(uint16_t) + ntohs(*len16);
    if (data_len <= sizeof(uint8_t))
    {
        return false;
    }
    len8 = (uint8_t *)(len16 + 1) + ntohs(*len16);
    data_len -= sizeof(uint8_t) + *len8;
    if (data_len <= sizeof(uint16_t))
    {
        return false;
    }
    len16 = (len8 + 1 + *len8);
    data_len -= sizeof(uint16_t);
    struct extension_s *extension = (struct extension *)(len16 + 1);
    while (data_len > sizeof(struct extension_s))
    {
        if (extension->type == htons(0x0000))
        {
            data_len -= sizeof(struct extension_s);
            if (data_len <= sizeof(struct sni_s))
            {
                return false;
            }
            struct sni_s *sni = (struct sni_s *)(extension + 1);
            uint8_t name_len = sni->name_len;
            if (name_len == 0)
            {
                return false;
            }
            name_len--;
            data_len -= sizeof(struct sni_s);
            name_len = ((ssize_t)name_len > data_len? data_len: name_len);
            uint8_t *name = (uint8_t *)(sni + 1);
            *start = (name - data);
            *end   = *start + name_len;
            return true;
        }
        uint16_t len = ntohs(extension->length);
        data_len -= sizeof(struct extension_s) + len;
        extension = (struct extension_s *)((uint8_t *)(extension + 1) + len);
    }
    return false;
}


