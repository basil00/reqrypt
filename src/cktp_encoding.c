/*
 * cktp_encoding.c
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "cfg.h"
#include "cktp_encoding.h"
#include "log.h"
#include "misc.h"
#include "random.h"

/*
 * Prototypes.
 */
static int enc_parse_param(const cktp_enc_param_t params, size_t params_size,
    const char *param_str, cktp_enc_val_t val);
static size_t enc_base64_encode(const uint8_t *in, size_t insize, char *out);
static size_t enc_base64_decode(const char *in, size_t insize, uint8_t *out);
static cktp_enc_rng_t enc_random_init(void);
static void enc_random_free(cktp_enc_rng_t rng);
static void enc_random(cktp_enc_rng_t rng, void *ptr, size_t size);
static uint64_t enc_gettime(void);
static void enc_sleeptime(uint64_t ms);

/*
 * Global encoding helper library.
 */
struct cktp_enc_lib_s encoding_lib =
{
    enc_parse_param,
    enc_base64_encode,
    enc_base64_decode,
    enc_random_init,
    enc_random_free,
    enc_random,
    enc_gettime,
    enc_sleeptime
};

/*
 * Parameter compare function.
 */
static int cktp_enc_param_s_compare(const void *a, const void *b)
{
    const struct cktp_enc_param_s *a1 = (const struct cktp_enc_param_s *)a;
    const struct cktp_enc_param_s *b1 = (const struct cktp_enc_param_s *)b;

    size_t a1_size = strlen(a1->name);
    size_t b1_size = strlen(b1->name);
    size_t min_size = (a1_size < b1_size? a1_size: b1_size);
    return strncmp(a1->name, b1->name, min_size);
}

/*
 * Parse an encoding option/parameter.
 */
static int enc_parse_param(const cktp_enc_param_t params, size_t params_size,
    const char *param_str, cktp_enc_val_t val)
{
    if (*param_str == '\0')
    {
        errno = EINVAL;
        return -1;
    }

    struct cktp_enc_param_s key;
    key.name = param_str;
    cktp_enc_param_t p = bsearch(&key, params, params_size,
        sizeof(struct cktp_enc_param_s), cktp_enc_param_s_compare);

    if (p == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    val->param = p;
    const char *val_str = param_str + strlen(p->name);
    if (*val_str == '.')
    {
        val_str++;
    }
    switch (p->type)
    {
        case CKTP_ENCODING_TYPE_NIL:
            break;
        case CKTP_ENCODING_TYPE_INT:
        {
            char *end_ptr;
            val->val.int_val = strtoll(val_str, &end_ptr, 10);
            if (*val_str == '\0' || *end_ptr != '\0')
            {
                errno = EINVAL;
                return -1;
            }
            break;
        }
        case CKTP_ENCODING_TYPE_UINT:
        {
            char *end_ptr;
            val->val.uint_val = strtoull(val_str, &end_ptr, 10);
            if (*val_str == '\0' || *end_ptr != '\0')
            {
                errno = EINVAL;
                return -1;
            }
            break;
        }
        case CKTP_ENCODING_TYPE_STRING:
        {
            size_t i;
            for (i = 0; val_str[i] != '\0' && i < CKTP_MAX_STRING_LENGTH; i++)
            {
                val->val.str_val[i] = val_str[i];
            }
            if (val_str[i] != '\0')
            {
                errno = EINVAL;
                return -1;
            }
            val->val.str_val[i] = '\0';
            break;
        }
        default:
            errno = EINVAL;
            return -1;
    }

    return 0;
}

/*
 * Random numbers.
 */
static cktp_enc_rng_t enc_random_init(void)
{
    return random_init();
}
static void enc_random_free(cktp_enc_rng_t rng)
{
    random_free(rng);
}
static void enc_random(cktp_enc_rng_t rng, void *ptr, size_t size)
{
    random_memory(rng, ptr, size);
}

/*
 * Encode data as base64.
 */
size_t enc_base64_encode(const uint8_t *in, size_t insize, char *out)
{
    return base64_encode(in, insize, out);
}

/*
 * Decode base64 data.
 */
size_t enc_base64_decode(const char *in, size_t insize, uint8_t *out)
{
    return base64_decode(in, insize, out);
}

/*
 * Called after encoding/decoding packets.
 */
bool cktp_encoding_verify(cktp_enc_info_t info, size_t overhead,
    const uint8_t *oldptr, const uint8_t *newptr, size_t oldsize,
    size_t newsize)
{
    if (newptr == NULL)
    {
        return false;
    }
    if (newsize == 0)
    {
        return false;
    }

    // Check for buggy encoding implementations:
    if (newsize > oldsize)
    {
        size_t sizediff = newsize - oldsize;
        if (sizediff > 2*overhead)
        {
            error("unable to encode/decode packet; encoding %s implementation "
                "bug; consumed " SIZE_T_FMT " bytes, maximum allowed is "
                SIZE_T_FMT " bytes", info->protocol, sizediff, 2*overhead);
            exit(EXIT_FAILURE);
        }
    }
    size_t ptrdiff = (size_t)llabs((intptr_t)newptr - (intptr_t)oldptr);
    if (ptrdiff > overhead)
    {
        error("unable to encode/decode packet; encoding %s implementation "
            "bug; buffer moved " SIZE_T_FMT " bytes, maximum allowed is "
            SIZE_T_FMT " bytes",
            info->protocol, ptrdiff, overhead);
        exit(EXIT_FAILURE);
    }

    return true;
}

/*
 * Get the current time.
 */
static uint64_t enc_gettime(void)
{
    return gettime() / MILLISECONDS;
}

/*
 * Sleep for the given number of milliseconds.
 */
static void enc_sleeptime(uint64_t ms)
{
    sleeptime(ms * MILLISECONDS);
}

