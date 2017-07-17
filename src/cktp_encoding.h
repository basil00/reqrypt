/*
 * cktp_encoding.h
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

#ifndef __CKTP_ENCODING_H
#define __CKTP_ENCODING_H

#include <stdbool.h>
#include <stdint.h>

#include "cktp.h"
#include "random.h"

/*
 * Encoding related constants.
 */
#define CKTP_MAX_ENCODINGS              8
#define CKTP_MAX_ENCODING_NAME          16
#define CKTP_MAX_ENCODING_OPTIONS       64
#define CKTP_MAX_ENCODING_HANDSHAKE     32
#define CKTP_MAX_ENCODING_RETRIES       3

/*
 * Encoding parameters.
 */
#define CKTP_ENCODING_TYPE_NIL          0
#define CKTP_ENCODING_TYPE_INT          1
#define CKTP_ENCODING_TYPE_UINT         2
#define CKTP_ENCODING_TYPE_STRING       3
typedef uint8_t cktp_enc_type_t;
struct cktp_enc_param_s
{
    const char *name;
    uint16_t id;
    cktp_enc_type_t type;
};
typedef struct cktp_enc_param_s *cktp_enc_param_t;

struct cktp_enc_val_s
{
    cktp_enc_param_t param;
    union
    {
        int64_t int_val;
        uint64_t uint_val;
        char str_val[CKTP_MAX_STRING_LENGTH+1];
    } val;
};
typedef struct cktp_enc_val_s *cktp_enc_val_t;

/*
 * Encoding helper library.
 */
typedef int (*encoding_parse_param_t)(const cktp_enc_param_t params,
    size_t params_size, const char *param_str, cktp_enc_val_t val);
typedef size_t (*encoding_base64_encode_t)(const uint8_t *in, size_t insize,
    char *out);
typedef size_t (*encoding_base64_decode_t)(const char *in, size_t insize,
    uint8_t *out);
typedef random_state_t cktp_enc_rng_t;
typedef cktp_enc_rng_t (*encoding_random_init_t)(void);
typedef void (*encoding_random_free_t)(cktp_enc_rng_t rng);
typedef void (*encoding_random_t)(cktp_enc_rng_t rng, void *ptr, size_t size);
typedef uint64_t (*encoding_gettime_t)(void);
typedef void (*encoding_sleeptime_t)(uint64_t ms);

struct cktp_enc_lib_s
{
    encoding_parse_param_t parse_param;
    encoding_base64_encode_t base64_encode;
    encoding_base64_decode_t base64_decode;
    encoding_random_init_t random_init;
    encoding_random_free_t random_free;
    encoding_random_t random;
    encoding_gettime_t gettime;
    encoding_sleeptime_t sleeptime;
};
typedef struct cktp_enc_lib_s *cktp_enc_lib_t;

extern struct cktp_enc_lib_s encoding_lib;

/*
 * Encoding protocol's state.
 */
typedef void *cktp_enc_state_t;

/*
 * Encoding driver functions.
 */
typedef int (*encoding_init_t)(const cktp_enc_lib_t lib, const char *protocol,
    const char *options, size_t options_size, cktp_enc_state_t *stateptr);
typedef int (*encoding_activate_t)(cktp_enc_state_t state);
typedef int (*encoding_clone_t)(cktp_enc_state_t state,
    cktp_enc_state_t *stateptr);
typedef void (*encoding_free_t)(cktp_enc_state_t state);
typedef size_t (*encoding_overhead_t)(cktp_enc_state_t state);
typedef uint64_t (*encoding_timeout_t)(cktp_enc_state_t state);
typedef int (*encoding_handshake_request_t)(cktp_enc_state_t state,
    uint8_t *data, size_t *size);
typedef int (*encoding_handshake_reply_t)(cktp_enc_state_t state,
    uint8_t *data, size_t size);
typedef int (*encoding_encode_t)(cktp_enc_state_t state, uint8_t **dataptr,
    size_t *sizeptr);
typedef int (*encoding_decode_t)(cktp_enc_state_t state, uint8_t **dataptr,
    size_t *sizeptr);
typedef int (*encoding_server_decode_t)(cktp_enc_state_t state,
    uint32_t *source_addr, size_t source_size, uint8_t **dataptr,
    size_t *sizeptr, uint8_t **replyptr, size_t *replysizeptr);
typedef const char *(*encoding_error_string_t)(cktp_enc_state_t state,
    int err);

/*
 * Encoding info.
 */
struct cktp_enc_info_s
{
    const char *protocol;
    encoding_init_t init;
    encoding_free_t free;
    encoding_overhead_t overhead;
    encoding_error_string_t error_string;

#ifdef CLIENT
    encoding_timeout_t timeout;
    encoding_handshake_request_t handshake_request;
    encoding_handshake_reply_t handshake_reply;
    encoding_encode_t encode;
    encoding_decode_t decode;
#endif      /* CLIENT */

#ifdef SERVER
    encoding_activate_t activate;
    encoding_clone_t clone;
    encoding_encode_t encode;
    encoding_server_decode_t decode;
#endif      /* SERVER */
};
typedef struct cktp_enc_info_s *cktp_enc_info_t;

/*
 * Encoding itself.
 */
struct cktp_enc_s
{
    cktp_enc_info_t info;           // Encoding's implementation
    cktp_enc_state_t state;         // Encoding's state
    size_t overhead;                // Maximum overhead of this encoding
};

/*
 * Initialise an encoding buffer.
 */
#define CKTP_ENCODING_BUFF_SIZE(size0, overhead)    ((size0)+2*(overhead))
#define CKTP_ENCODING_BUFF_INIT(buff0, overhead)    ((buff0)+(overhead))
bool cktp_encoding_verify(cktp_enc_info_t info, size_t overhead,
    const uint8_t *oldptr, const uint8_t *newptr, size_t oldsize,
    size_t newsize);

#endif      /* __ENCODING_H */
