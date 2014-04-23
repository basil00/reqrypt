/*
 * pad.c
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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pad.h"

/*
 * PAD ENCODING:
 * Adds padding to the beginning of the message.  The length of the padding is
 * variable, and the content of the padding is undefined (implementation
 * dependent).  This implementation pads with random data.
 */

#define PAD_DEFAULT_MIN     0
#define PAD_DEFAULT_MAX     16

/*
 * Pad paramter index.
 */
#define PAD_MIN     0
#define PAD_MAX     1
#define PAD_SIZE    2
#define PAD_VALUE   3
struct cktp_enc_param_s pad_params[] =
{
    {"max",   PAD_MAX,   CKTP_ENCODING_TYPE_UINT},
    {"min",   PAD_MIN,   CKTP_ENCODING_TYPE_UINT},
    {"size",  PAD_SIZE,  CKTP_ENCODING_TYPE_UINT},
    {"value", PAD_VALUE, CKTP_ENCODING_TYPE_STRING},
};

/*
 * Pad encoding errors.
 */
#define PAD_ERROR_BAD_NAME                      (-100)
#define PAD_ERROR_BAD_URL_PARAMETER             (-101)
#define PAD_ERROR_REPEATED_URL_PARAMETER        (-102)
#define PAD_ERROR_INCOMPATIBLE_URL_PARAMETERS   (-103)
#define PAD_ERROR_OUT_OF_MEMORY                 (-104)
#define PAD_ERROR_BAD_LENGTH                    (-105)
#define PAD_ERROR_BAD_PAD                       (-106)

/*
 * Pad encoding internal state.
 */
struct pad_state_s
{
    cktp_enc_lib_t lib;
    cktp_enc_rng_t rng;
    bool fixed;             // true = 'use size', false = 'use min/max'
    uint8_t min;            // Minimum pad length
    uint8_t max;            // Maximum pad length
    uint8_t size;           // Pad size
    char *value;            // Pad value
};
typedef struct pad_state_s *pad_state_t;
typedef pad_state_t state_t;

/*
 * Prototypes.
 */
static int pad_init(const cktp_enc_lib_t lib, const char *protocol,
    const char *options, size_t options_size, state_t *stateptr);
static void pad_free(state_t state);
static size_t pad_overhead(state_t state);
static const char *pad_error_string(state_t state, int err);
static int pad_encode(state_t state, uint8_t **dataptr, size_t *sizeptr);
static int pad_decode(state_t state, uint8_t **dataptr, size_t *sizeptr);
#ifdef SERVER
static int pad_server_decode(state_t state, uint32_t *source_addr,
    size_t source_size, uint8_t **dataptr, size_t *sizeptr, uint8_t **replyptr,
    size_t *replysizeptr);
#endif      /* SERVER */

/*
 * Pad encoding protocol:
 */
struct cktp_enc_info_s pad_encoding =
{
    "pad",
    (encoding_init_t)pad_init,
    (encoding_free_t)pad_free,
    (encoding_overhead_t)pad_overhead,
    (encoding_error_string_t)pad_error_string,
#ifdef CLIENT
    NULL,
    NULL,
    NULL,
    (encoding_encode_t)pad_encode,
    (encoding_decode_t)pad_decode
#endif      /* CLIENT */

#ifdef SERVER
    NULL,
    NULL,
    (encoding_encode_t)pad_encode,
    (encoding_server_decode_t)pad_server_decode
#endif      /* SERVER */
};

/*
 * Initialise the padding state.
 */
static int pad_init(const cktp_enc_lib_t lib, const char *protocol,
    const char *options, size_t options_size, state_t *stateptr)
{
    *stateptr = NULL;
    if (strcmp(protocol, "pad") != 0)
    {
        return PAD_ERROR_BAD_NAME;
    }

    uint8_t min = PAD_DEFAULT_MIN;
    uint8_t max = PAD_DEFAULT_MAX;
    uint8_t size = 0;
    char *value = NULL;
    bool seen_min = false, seen_max = false, seen_size = false,
         seen_value = false;
    for (size_t i = 0; i < options_size; i++)
    {
        struct cktp_enc_val_s val;
        int result = lib->parse_param(pad_params,
            sizeof(pad_params) / sizeof(struct cktp_enc_param_s),
            options, &val);
        if (result < 0)
        {
            free(value);
            return PAD_ERROR_BAD_URL_PARAMETER;
        }

        if (val.val.uint_val > UINT8_MAX)
        {
            free(value);
            return PAD_ERROR_BAD_URL_PARAMETER;
        }

        switch (val.param->id)
        {
            case PAD_MIN:
                if (seen_min)
                {
                    free(value);
                    return PAD_ERROR_REPEATED_URL_PARAMETER;
                }
                seen_min = true;
                min = val.val.uint_val;
                break;
            case PAD_MAX:
                if (seen_max)
                {
                    free(value);
                    return PAD_ERROR_REPEATED_URL_PARAMETER;
                }
                seen_max = true;
                max = val.val.uint_val;
                break;
            case PAD_SIZE:
                if (seen_size)
                {
                    free(value);
                    return PAD_ERROR_REPEATED_URL_PARAMETER;
                }
                seen_size = true;
                size = val.val.uint_val;
                break;
            case PAD_VALUE:
                if (seen_value)
                {
                    free(value);
                    return PAD_ERROR_REPEATED_URL_PARAMETER;
                }
                seen_value = true;
                value = strdup(val.val.str_val);
                size_t len = strlen(value);
                if (len == 0 || len > UINT8_MAX)
                {
                    free(value);
                    return PAD_ERROR_BAD_URL_PARAMETER;
                }
                break;
            default:
                free(value);
                return PAD_ERROR_BAD_URL_PARAMETER;
        }

        options += strlen(options) + 1;
    }

    if (seen_value && !seen_size && !seen_min && !seen_max)
    {
        seen_size = true;
        size = (uint8_t)strlen(value);
    }

    if (seen_size && (seen_min || seen_max))
    {
        free(value);
        return PAD_ERROR_INCOMPATIBLE_URL_PARAMETERS;
    }

    if (min > max)
    {
        free(value);
        return PAD_ERROR_INCOMPATIBLE_URL_PARAMETERS;
    }

    state_t state = (state_t)malloc(sizeof(struct pad_state_s));
    if (state == NULL)
    {
        free(value);
        return PAD_ERROR_OUT_OF_MEMORY;
    }
    state->lib   = lib;
    state->min   = min;
    state->max   = max;
    state->size  = size;
    state->value = value;
    state->fixed = seen_size;
    state->rng   = lib->random_init();
    *stateptr = state;
    return 0;
}

/*
 * Free state.
 */
static void pad_free(state_t state)
{
    state->lib->random_free(state->rng);
    free(state->value);
    free(state);
}

/*
 * Query pad overhead.
 */
static size_t pad_overhead(state_t state)
{
    return (state->fixed? (size_t)state->size: (size_t)state->max + 1);
}

/*
 * Error strings.
 */
static const char *pad_error_string(state_t state, int err)
{
    switch (err)
    {
        case PAD_ERROR_BAD_NAME:
            return "bad encoding name";
        case PAD_ERROR_BAD_URL_PARAMETER:
            return "bad URL parameter";
        case PAD_ERROR_REPEATED_URL_PARAMETER:
            return "repeated URL parameter";
        case PAD_ERROR_INCOMPATIBLE_URL_PARAMETERS:
            return "incompatible URL parameters";
        case PAD_ERROR_OUT_OF_MEMORY:
            return "out of memory";
        case PAD_ERROR_BAD_LENGTH:
            return "bad length";
        case PAD_ERROR_BAD_PAD:
            return "bad pad";
        default:
            return "generic error";
    }
}

/*
 * Fill padding.
 */
static void pad_fill(state_t state, uint8_t *pad, size_t pad_size)
{
    if (state->value == NULL)
    {
        state->lib->random(state->rng, pad, pad_size);
    }
    else
    {
        for (size_t i = 0, j = 0; i < pad_size; i++)
        {
            pad[i] = state->value[j];
            j = (state->value[i+1] == '\0'? 0: j+1);
        }
    }
}

/*
 * Check padding.
 */
static bool pad_check(state_t state, uint8_t *pad, size_t pad_size)
{
    if (state->value == NULL)
    {
        return true;
    }
    for (size_t i = 0, j = 0; i < pad_size; i++)
    {
        if (pad[i] != state->value[j])
        {
            return false;
        }
        j = (state->value[i+1] == '\0'? 0: j+1);
    }
    return true;
}

/*
 * Add padding to the message.
 */
static int pad_encode(state_t state, uint8_t **dataptr, size_t *sizeptr)
{
    uint8_t *data = *dataptr, *pad;
    size_t size = *sizeptr;

    uint8_t pad_size;
    if (state->fixed)
    {
        // Fixed length padding:
        pad_size = state->size;
        data -= pad_size;
        size += pad_size;
        pad = data;
    }
    else
    {
        // Random length padding:
        uint8_t pad_size_byte;
        state->lib->random(state->rng, &pad_size_byte, sizeof(pad_size_byte));
        pad_size = state->min + pad_size_byte % (state->max - state->min + 1);
        data -= pad_size + 1;
        size += pad_size + 1;
        data[0] = pad_size_byte;
        pad = data + 1;
    }
    pad_fill(state, pad, pad_size);

    *dataptr = data;
    *sizeptr = size;
    return 0;
}

/*
 * Strip padding from message.
 */
static int pad_decode(state_t state, uint8_t **dataptr, size_t *sizeptr)
{
    uint8_t *data = *dataptr;
    size_t size = *sizeptr;

    uint8_t pad_size;
    if (state->fixed)
    {
        pad_size = state->size;
        if (pad_size < size && !pad_check(state, data, pad_size))
        {
            return PAD_ERROR_BAD_PAD;
        }
    }
    else
    {
        uint8_t pad_size_byte = data[0];
        pad_size = state->min + pad_size_byte % (state->max - state->min + 1);
        pad_size++;
    }
    
    if (pad_size >= size)
    {
        return PAD_ERROR_BAD_LENGTH;
    }
    data += pad_size;
    size -= pad_size;
    *dataptr = data;
    *sizeptr = size;
    return 0;
}

#ifdef SERVER

/*
 * (Server) Strip padding from message.
 */
static int pad_server_decode(state_t state, uint32_t *source_addr,
    size_t source_size, uint8_t **dataptr, size_t *sizeptr, uint8_t **replyptr,
    size_t *replysizeptr)
{
    return pad_decode(state, dataptr, sizeptr);
}

#endif      /* SERVER */

