/*
 * cktp_url.c
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cktp.h"
#include "cktp_url.h"
#include "log.h"
#include "socket.h"

#include "encodings/crypt.h"
#include "encodings/pad.h"

#define MAX_TRANSPORT_NAME  16
#define MAX_PORT            20

/*
 * Supported transports.
 */
struct transport_s
{
    char name[MAX_TRANSPORT_NAME+1];
    unsigned max_port;
    int proto;
};

struct transport_s trans_data[] =
{
    {"ip",      UINT8_MAX,  CKTP_PROTO_IP},
    {"ping",    UINT16_MAX, CKTP_PROTO_PING},
    {"tcp",     UINT16_MAX, CKTP_PROTO_TCP},
    {"udp",     UINT16_MAX, CKTP_PROTO_UDP},
    {"udplite", UINT16_MAX, CKTP_PROTO_UDPLITE}
};

static int transport_s_compare(const void *a, const void *b)
{
    const struct transport_s *a1 = (const struct transport_s *)a;
    const struct transport_s *b1 = (const struct transport_s *)b;
    return strcmp(a1->name, b1->name);
}

/*
 * Supported encodings.
 */
struct encoding_s
{
    char name[CKTP_MAX_ENCODING_NAME+1];
    cktp_enc_info_t info;
};

struct encoding_s enc_data[] =
{
    {"crypt", &crypt_encoding},
    {"pad",   &pad_encoding}
};

static int encoding_s_compare(const void *a, const void *b)
{
    const struct encoding_s *a1 = (const struct encoding_s *)a;
    const struct encoding_s *b1 = (const struct encoding_s *)b;
    return strcmp(a1->name, b1->name);
}

/*
 * Parse a tunnel url.  The general URL syntax is:
 * TRANSPORT://SERVER:PORT[?ENCODING[=OPTIONS]+...]
 */
bool cktp_parse_url(const char *url, int *transport, char *server,
    uint16_t *port, struct cktp_enc_s *encodings)
{
    size_t i = 0;

    // TRANSPORT:
    struct transport_s trans_key;
    for (; i < MAX_TRANSPORT_NAME && url[i] && isalnum(url[i]); i++)
    {
        trans_key.name[i] = url[i];
    }
    trans_key.name[i] = '\0';
    if (url[i] != ':' || url[i+1] != '/' || url[i+2] != '/')
    {
        warning("unable to parse url \"%s\"; expected token '://' is missing",
            url);
        return false;
    }
    i += 3;
    struct transport_s *trans_info = bsearch(&trans_key, trans_data,
        sizeof(trans_data) / sizeof(struct transport_s),
        sizeof(struct transport_s), transport_s_compare);
    if (trans_info == NULL)
    {
        warning("unable to parse url \"%s\"; invalid or unsupported "
            "transport protocol \"%s\"", url, trans_key.name);
        return false;
    }
    if (transport != NULL)
    {
        *transport = trans_info->proto;
    }

    // SERVER:
    size_t j = 0;
    for (; j < CKTP_MAX_URL_LENGTH && url[i] &&
           (isalnum(url[i]) || url[i] == '.' || url[i] == '-'); i++, j++)
    {
        if (server != NULL)
        {
            server[j] = url[i];
        }
    }
    if (server != NULL)
    {
        server[j] = '\0';
    }

    // PORT:
    if (trans_info->max_port != 0)
    {
        if (url[i] != ':')
        {
            warning("unable to parse url \"%s\"; expected token ':' is "
                "missing", url);
            return false;
        }
        i++;

        for (j = 0; j < MAX_PORT && isdigit(url[i]); j++, i++)
            ;
        if (j == 0)
        {
            warning("unable to parse url \"%s\"; expected port number is "
                "missing", url);
            return false;
        }
        unsigned port0 = strtoull(url + i - j, NULL, 10);
        if (port0 > trans_info->max_port)
        {
            warning("unable to parse url \"%s\"; port number must be within "
                "the range 0..%u, found %u", url, trans_info->max_port,
                port0);
            return false;
        }
        if (port != NULL)
        {
            *port = htons((uint16_t)port0);
        }
    }

    if (url[i] == '\0')
    {
        if (encodings != NULL)
        {
            encodings[0].info = NULL;
            encodings[0].state = NULL;
        }
        return true;
    }

    // ENCODINGS:
    if (url[i] != '?')
    {
        warning("unable to parse url \"%s\"; expected token '?' or "
            "end-of-url is missing", url);
        return false;
    }
    i++;

    for (j = 0; j < CKTP_MAX_ENCODINGS; j++)
    {
        struct encoding_s enc_key;
        size_t k;
        for (k = 0; k < CKTP_MAX_ENCODING_NAME && isalnum(url[i]); k++, i++)
        {
            enc_key.name[k] = url[i];
        }
        if (k == 0)
        {
            warning("unable to parse url \"%s\"; expected encoding name is "
                "missing", url);
            return false;
        }
        enc_key.name[k] = '\0';

        struct encoding_s *enc_info = bsearch(&enc_key, enc_data,
            sizeof(enc_data) / sizeof(struct encoding_s),
            sizeof(struct encoding_s), encoding_s_compare);
        if (enc_info == NULL)
        {
            warning("unable to parse url \"%s\"; invalid or unsupported "
                "encoding \"%s\"", url, enc_key.name);
            return false;
        }

        // Parse comma seperated set of encoding options
        char enc_options[CKTP_MAX_ENCODING_OPTIONS+1];
        k = 0;
        size_t enc_options_size = 0;
        if (url[i] == '=')
        {
            i++;
            for (; k < CKTP_MAX_ENCODING_OPTIONS && url[i] && url[i] != '+';
                   k++, i++)
            {
                if (url[i] == ',')
                {
                    enc_options[k] = '\0';
                    enc_options_size++;
                }
                else
                {
                    enc_options[k] = url[i];
                }
            }
            enc_options_size++;
        }
        enc_options[k] = '\0';
        
        // Intialise the encoding:
        if (encodings != NULL)
        {
            cktp_enc_state_t state;
            int err = enc_info->info->init(&encoding_lib, enc_info->name,
                enc_options, enc_options_size, &state);
            if (err != 0)
            {
                warning("unable to parse url \"%s\"; failed to initialise "
                    "encoding \"%s\" (%s)", url, enc_key.name,
                    enc_info->info->error_string(NULL, err));
                return false;
            }
       
            encodings[j].info  = enc_info->info;
            encodings[j].state = state;
        }

        if (url[i] == '\0')
        {
            break;
        }
        if (url[i] != '+')
        {
            warning("unable to parse url \"%s\"; expected token '+' or "
                "end-of-url is missing", url);
            return false;
        }
        i++;
    }

    if (url[i] != '\0')
    {
        warning("unable to parse URL \"%s\"; too many encodings (maximum is "
            "%u)", url, CKTP_MAX_ENCODINGS);
        return false;
    }

    return true;
}

