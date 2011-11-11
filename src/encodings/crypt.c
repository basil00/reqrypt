/*
 * crypt.c
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

/*
 * PROTOCOL SUMMARY: 
 *
 * HANDSHAKE:
 * (0) Server publishes the URL(RSACertificateHash), where
 *     - RSACertificateHash is a cryptographic hash function of an RSA
 *       certificate.
 * (1) Client sends a GET_COOKIE request.
 * (2) Server responds with a COOKIE(Cookie) reply.
 * (3) [OPTIONAL] Client sends a GET_CERTIFICATE(Cookie) request, where:
 *     - Cookie is the same as message (2).
 *     - This is OPTIONAL if the client has a cached copy of the
 *       RSACertificate corresponding to RSACertificateHash from message (0).
 * (4) [OPTIONAL] Server responds with a CERTIFICATE(RSACertificate) message.
 *     The client verifies that hash(RSACertificate) == RSACertificateHash
 * (5) Client sends a GET_KEY(Cookie, ClientDHPublicKey) request, where:
 *     - Cookie is the same as message (2).
 *     - ClientDHPublicKey is the client's DH public key
 * (6) Server responds with a
 *          KEY(ServerDHPublicKey, encrypt_DHSharedKey(
 *              sign_RSAPrivateKey(SessionKey, SessionKeyId)))
 *      reply, where:
 *      - ServerDHPublicKey is the server's DH public key.
 *      - DHSharedKey is the DH shared secret key.
 *      - RSAPrivateKey is the RSA private key corresponding to
 *        RSACertificate.
 *      - SessionKey is the private key to use for the rest of the tunneling
 *        session.
 *      - SessionKeyId is the key identifier associated to SessionKey.
 *        Note: SessionKey is secret, SessionKeyId may be public.
 *
 * Note: portions of messages (1) - (6) are additionally encrypted using
 *       RSACertificateHash as the key.  This makes it necessary for an
 *       eavesdropper to know the URL in order to read some protocol fields.
 *       This is a cheap way of adding more work for any attacker.
 *
 * TUNNELING:
 *
 * All encryption is done using a block cipher is CTR mode.
 *
 * (*) Client prepends a CLIENT_HEADER(IV, SessionKeyId, MAC) header and
 *     encrypts the packet using SessionKey, where
 *     - IV is a randomly generated Initialisation Vector.
 *     - SessionKeyId is the same as message (4) from the handshake.
 *     - MAC is the Message Authentication Code.
 * (*) Server prepends a SERVER_HEADER(IV, MAC) header and encrypts the packet
 *     using SessionKey, as per above.
 *
 * Note: The Client additionally encrypts the SessionKeyId with the same IV
 *       and RSACertificateHash as the key.
 *
 * NOTES:
 * (1) The server is stateless.  The server derives the SessionKey from the
 *     SessionKeyId using a cryptographically secure secret hash function.
 *
 * POSSIBLE (NON-STANDARD) ATTACKS:
 * - A man-in-the-middle could modify message (0) to insert their own
 *   certificate hash and message (3) to insert their own matching
 *   certificate.  Then a standard man-in-the-middle attack can be executed.
 *   To counter this message (0) may be sent using some other secure protocol
 *   (e.g. SSL), or simply published widely.
 * - A man-in-the-middle could observe a protocol handshake, then send forged
 *   GET_KEY requests to the server.  If the server returns the same
 *   (SessionKey, SessionKeyId) as the one returned to the client, the session
 *   is compromised.  To counter this the SessionKeyId is at least 39 bits
 *   (effective), meaning an average of 2^38 forged GET_KEY requests are
 *   required.  As each GET_KEY is 100+ bytes, this is attack requires
 *   multiple terabytes of GET_KEY messages to be sent.  Hopefully this is
 *   impractical for some time.  The SessionKeyId may be up to 63 bits long.
 * - The protocol has no built-in protection against replay attacks.  This is
 *   because (1) the server is stateless, and (2) the tunneled protocols such
 *   as CKTP, TCP, and UDP have their own sequence numbers.
 *
 * IMPLEMENTATION BUGS:
 * - This code has not been scrutinised/tested nearly enough to be considered
 *   secure.  Rely on it at your own risk.
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cktp_encoding.h"
#include "cookie.h"
#include "encodings/aes.h"
#include "encodings/aes_hardware.h"
#include "encodings/crypt.h"

#ifdef CLIENT
#include "natural.h"
#endif

#ifdef SERVER
#include <gmp.h>

#include "quota.h"
#include "thread.h"
#endif

/*
 * Parameters:
 */
#define CRYPT_PUBLIC_KEY_SIZE           128
#define CRYPT_KEY_SIZE                  16
#define CRYPT_BLOCK_SIZE                CRYPT_KEY_SIZE
#define CRYPT_HASH_SIZE                 CRYPT_KEY_SIZE
#define CRYPT_HASH_BASE64_SIZE          ((CRYPT_HASH_SIZE * 8 - 1) / 6 + 1)
#define CRYPT_PUBLIC_KEY_BASE64_SIZE    \
    ((CRYPT_PUBLIC_KEY_SIZE * 8 - 1) / 6 + 1)
#define CRYPT_DH_GENERATOR              2
#define CRYPT_RSA_EXPONENT              0x00010001
#define CRYPT_MIN_AKEY_SIZE             2
#define CRYPT_MIN_ID_SIZE               5
#define CRYPT_MIN_IV_SIZE               4
#define CRYPT_MIN_MAC_SIZE              2
#define CRYPT_MAX_AKEY_SIZE             CRYPT_MIN_AKEY_SIZE
#define CRYPT_MAX_ID_SIZE               sizeof(uint64_t)
#define CRYPT_MAX_IV_SIZE               sizeof(uint64_t)
#define CRYPT_MAX_MAC_SIZE              sizeof(uint64_t)
#define CRYPT_DEFAULT_AKEY_SIZE         2
#define CRYPT_DEFAULT_ID_SIZE           6
#define CRYPT_DEFAULT_IV_SIZE           5
#define CRYPT_DEFAULT_MAC_SIZE          3
#define CRYPT_HEADER_SEQ                0x243F6A88          // PI
#define CRYPT_GEN_IDX_MASK              0x0000000000000001ull
#define CRYPT_TIMEOUT                   (60*60*1000)        // 60 minutes
#define CRYPT_TIMEOUT_BUFF              (60*1000)           // 60 seconds
#define CRYPT_MIN_TIMEOUT               (5*60*1000)         // 5 minutes
#define CRYPT_MAX_TIMEOUT               (24*60*60*1000)     // 1 day
#define CRYPT_KEYS_FILENAME             PACKAGE_NAME ".crypt.keys"
#define CRYPT_QUOTA_RK_TIMEMIN          4000                // 4 seconds
#define CRYPT_QUOTA_RK_TIMEMAX          8000                // 8 seconds
#define CRYPT_QUOTA_RK_RATE             8                   // 8 per second
#define CRYPT_QUOTA_RK_NUM_BUCKETS      256

/*
 * Error codes.
 */

#define CRYPT_ERROR_BAD_NAME                (-100)
#define CRYPT_ERROR_BAD_STATE               (-101)
#define CRYPT_ERROR_BAD_LENGTH              (-102)
#define CRYPT_ERROR_BAD_CERTIFICATE         (-103)
#define CRYPT_ERROR_BAD_PARAMETER           (-104)
#define CRYPT_ERROR_BAD_VERSION             (-105)
#define CRYPT_ERROR_BAD_MAGIC_NUMBER        (-106)
#define CRYPT_ERROR_BAD_TIMEOUT             (-107)
#define CRYPT_ERROR_BAD_COOKIE              (-108)
#define CRYPT_ERROR_BAD_SEQ                 (-109)
#define CRYPT_ERROR_BAD_MAC                 (-110)
#define CRYPT_ERROR_BAD_URL_PARAMETER       (-111)
#define CRYPT_ERROR_MISSING_URL_PARAMETER   (-112)
#define CRYPT_ERROR_REPEATED_URL_PARAMETER  (-113)
#define CRYPT_ERROR_OUT_OF_MEMORY           (-114)
#define CRYPT_ERROR_DOS                     (-115)

/*
 * 1024-bit prime for DH key exchange (see RFC2412 Appendix E.2)
 */
static const uint8_t p0[CRYPT_PUBLIC_KEY_SIZE] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x81, 0x53, 0xE6, 0xEC,
    0x51, 0x66, 0x28, 0x49, 0xE6, 0x1F, 0x4B, 0x7C, 0x11, 0x24, 0x9F, 0xAE,
    0xA5, 0x9F, 0x89, 0x5A, 0xFB, 0x6B, 0x38, 0xEE, 0xED, 0xB7, 0x06, 0xF4,
    0xB6, 0x5C, 0xFF, 0x0B, 0x6B, 0xED, 0x37, 0xA6, 0xE9, 0x42, 0x4C, 0xF4,
    0xC6, 0x7E, 0x5E, 0x62, 0x76, 0xB5, 0x85, 0xE4, 0x45, 0xC2, 0x51, 0x6D,
    0x6D, 0x35, 0xE1, 0x4F, 0x37, 0x14, 0x5F, 0xF2, 0x6D, 0x0A, 0x2B, 0x30,
    0x1B, 0x43, 0x3A, 0xCD, 0xB3, 0x19, 0x95, 0xEF, 0xDD, 0x04, 0x34, 0x8E,
    0x79, 0x08, 0x4A, 0x51, 0x22, 0x9B, 0x13, 0x3B, 0xA6, 0xBE, 0x0B, 0x02,
    0x74, 0xCC, 0x67, 0x8A, 0x08, 0x4E, 0x02, 0x29, 0xD1, 0x1C, 0xDC, 0x80,
    0x8B, 0x62, 0xC6, 0xC4, 0x34, 0xC2, 0x68, 0x21, 0xA2, 0xDA, 0x0F, 0xC9,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/*****************************************************************************/

/*
 * Protocol messages:
 */

#define CRYPT_ID_REQ_COOKIE                         0
#define CRYPT_ID_REQ_CERTIFICATE                    1
#define CRYPT_ID_REQ_KEY                            2
#define CRYPT_ID_MAX_RESERVED                       8

/*
 * NOTE: for all of these structures 'seq' must be (a) uint32_t and (b)
 *       be the first field.
 */

struct crypt_req_cookie_s
{
    uint32_t seq;                                   // Sequence Number
    uint64_t unused;                                // Unused
} __attribute__((__packed__));

struct crypt_rep_cookie_s
{
    uint32_t seq;                                   // Sequence Number
    uint32_t cookie;                                // Cookie
} __attribute__((__packed__));

struct crypt_req_certificate_s
{
    uint32_t seq;                                   // Sequence Number
    uint32_t cookie;                                // Cookie
} __attribute__((__packed__));

struct crypt_rep_certificate_s
{
    uint32_t seq;                                   // Sequence Number
    uint8_t certificate[CRYPT_PUBLIC_KEY_SIZE];     // Certificate
} __attribute__((__packed__));

struct crypt_req_key_s
{
    uint32_t seq;                                   // Sequence Number
    uint32_t cookie;                                // Cookie
    uint8_t public_key[CRYPT_PUBLIC_KEY_SIZE];      // Public key
} __attribute__((__packed__));

#define CRYPT_VERSION               0
#define CRYPT_MAGIC                 0xA1C3952A

struct crypt_rep_key_s
{
    uint32_t seq;                                   // Sequence number
    uint8_t public_key[CRYPT_PUBLIC_KEY_SIZE];      // Public key
    uint32_t seq2;                                  // Sequence number (IV)
    uint64_t iv;                                    // Initialisation Vector
    uint64_t mac;                                   // MAC
    struct
    {
        uint8_t version;                            // Protocol version
        uint32_t magic;                             // Magic number
        uint8_t signature[CRYPT_PUBLIC_KEY_SIZE];   // Signed data
    } __attribute__((__packed__)) encrypted;
} __attribute__((__packed__));

#define CRYPT_SIGNED_MAGIC_1        0xA614BF722967C0D7ULL
#define CRYPT_SIGNED_MAGIC_2        0x843CD0BE88A8F703ULL

struct crypt_signed_data_s
{
    uint64_t iv;                                    // Initialisation Vector
    uint64_t mac;                                   // MAC
    struct
    {
        uint64_t magic1;                            // Magic number (1)
        uint64_t magic2;                            // Magic number (2)
        uint8_t version;                            // Protocol version
        uint32_t seq;                               // Sequence number
        uint64_t id;                                // Session ID
        uint8_t key[CRYPT_KEY_SIZE];                // Session key
        uint32_t timeout;                           // Timeout (ms)
        uint8_t reserved[16];                       // Reserved
    } __attribute__((__packed__)) encrypted;
} __attribute__((__packed__));

/*****************************************************************************/

/*
 * Prototypes.
 */
static void xxtea_expandkey(const uint8_t *key, size_t keysize, uint8_t *ekey);
static void xxtea_encrypt(const uint32_t *v, const uint32_t *k, uint32_t *r);

#define CRYPT_STATE_HANDSHAKE_REQ_COOKIE        1 
#define CRYPT_STATE_HANDSHAKE_REQ_CERTIFICATE   2
#define CRYPT_STATE_HANDSHAKE_REQ_KEY           3

typedef void (*expandkeyfunc_t)(const void *key, size_t keysize, void *ekey);
typedef void (*encryptfunc_t)(const void *block, const void *key,
    void *result);
typedef bool (*testfunc_t)(void);

/*
 * Cipher representation.
 */
struct cipher_s
{
    const char      *name;              // Cipher name
    size_t          ekeysize;           // Expanded key size
    expandkeyfunc_t expandkey;          // Optional expand key
    encryptfunc_t   encrypt;            // Encrypt
    testfunc_t      test;               // Hardware cipher supported?
};

/*
 * List of available ciphers.
 */
struct cipher_s ciphers[] =
{
    {   // AES128
        "aes",
        CRYPT_KEY_SIZE*(AES_ROUNDS+1),
        (expandkeyfunc_t)aes_expandkey,
        (encryptfunc_t)aes_encrypt,
        NULL
    },
    {   // XXTEA (128 block size)
        "xxtea",
        CRYPT_KEY_SIZE,
        (expandkeyfunc_t)xxtea_expandkey,
        (encryptfunc_t)xxtea_encrypt,
        NULL
    }
};

/*
 * List of hardware-accelerated ciphers.
 */
struct cipher_s hardware_ciphers[] =
{
    {   // AES128
        "aes",
        CRYPT_KEY_SIZE*(AES_ROUNDS+1),
        (expandkeyfunc_t)aes_hardware_expandkey,
        (encryptfunc_t)aes_hardware_encrypt,
        (testfunc_t)aes_hardware_test
    }      
};

/*
 * Comparison function for struct cipher_s
 */
static int cipher_s_compare(const void *a, const void *b)
{
    const struct cipher_s *a1 = (const struct cipher_s *)a;
    const struct cipher_s *b1 = (const struct cipher_s *)b;
    return strcmp(a1->name, b1->name);
}

#ifdef SERVER
struct crypt_global_state_s
{
    uint8_t refcount;                           // Reference count
    uint64_t seq_key;                           // Sequence key
    uint32_t seq;                               // Sequence number
    uint8_t gen_idx;                            // Current generator index
    uint64_t gen_timeout;                       // Timeout for gen_idx
    struct cookie_gen_s cookie_gen[2];          // Cookie generator
    struct cookie_gen_s key_gen[2];             // Key generator
    quota_t quota;                              // Request Key quota
    mpz_t mp_certificate;                       // Certificate
    mpz_t mp_sign_key;                          // Sign key
};
#endif      /* SERVER */

struct crypt_state_s
{
    cktp_enc_lib_t lib;                         // Encoding lib
    cktp_enc_rng_t rng;                         // Random numbers
    const struct cipher_s *cipher;              // Selected cipher
    uint64_t id;                                // Session ID
    size_t id_size;                             // ID size
    size_t iv_size;                             // IV size
    size_t mac_size;                            // MAC size
    bool pad;                                   // Pad handshake packets?
    uint8_t cert_hash[CRYPT_HASH_SIZE];         // Certificate hash
    uint8_t certificate[CRYPT_PUBLIC_KEY_SIZE]; // Certificate
    uint8_t *ekey;                              // Expanded key
#ifdef CLIENT
    bool have_cert;                             // Have certificate?
    bool save_cert;                             // Should save certificate?
    uint8_t key[CRYPT_PUBLIC_KEY_SIZE];         // Key
    uint8_t state;                              // Handshake state
    uint64_t seq_key;                           // Sequence key
    uint32_t seq;                               // Sequence number
    uint64_t timeout;                           // Timeout before reconnect
#endif      /* CLIENT */

#ifdef SERVER
    uint8_t key[CRYPT_KEY_SIZE];                // Key
    uint8_t sign_key[CRYPT_PUBLIC_KEY_SIZE];    // Signing key
    struct crypt_global_state_s *gbl_state;     // Global state
#endif      /* SERVER */
};

#ifdef SERVER
/*
 * Pre-computed GMP numbers for the server.
 */
static bool mp_init = false;
static mpz_t p;                                 // DH prime (p0)
static mpz_t p1;                                // DH prime less 1 (p - 1)
static mpz_t g;                                 // DH generator
#endif      /* SERVER */

typedef struct crypt_state_s *crypt_state_t;
typedef crypt_state_t state_t;

/*
 * Crypt user parameters:
 */
#define CRYPT_CERT              0
#define CRYPT_CIPHER            1
#define CRYPT_HANDSHAKEPAD      2
#define CRYPT_SEC               3
struct cktp_enc_param_s crypt_params[] =
{
    {"cert",            CRYPT_CERT,         CKTP_ENCODING_TYPE_STRING},
    {"cipher",          CRYPT_CIPHER,       CKTP_ENCODING_TYPE_STRING},
    {"handshakepad",    CRYPT_HANDSHAKEPAD, CKTP_ENCODING_TYPE_NIL},
    {"sec",             CRYPT_SEC,          CKTP_ENCODING_TYPE_UINT}
};

/*
 * Prototypes.
 */
static uint64_t encrypt(const struct cipher_s *cipher, const uint8_t *iv,
    size_t ivsize, uint32_t seq, const uint8_t *ekey, uint8_t *data,
    size_t datasize);
static uint64_t decrypt(const struct cipher_s *cipher, const uint8_t *iv,
    size_t ivsize, uint32_t seq, const uint8_t *ekey, uint8_t *data,
    size_t datasize);
static void crypt(const struct cipher_s *cipher, const uint8_t *iv,
    size_t ivsize, const uint8_t *key, uint8_t *data, size_t datasize);
static void hash(const struct cipher_s *cipher, uint8_t *data, size_t datasize,
    uint8_t *hashval);
static int crypt_init(const cktp_enc_lib_t lib, const char *protocol,
    const char *options, size_t options_size, state_t *stateptr);
static struct cipher_s *crypt_cipher_search(const char *name);
static void crypt_free(state_t state);
static size_t crypt_overhead(state_t state);
static const char *crypt_error_string(state_t state, int err);
static size_t crypt_handshake_pad_length(state_t state, uint8_t *data,
    size_t size);
static bool crypt_handshake_is_valid_length(state_t state, size_t basesize,
    size_t extsize);
static uint32_t crypt_seq(uint32_t seq, uint64_t seq_key);
#ifdef CLIENT
static bool crypt_find_certificate(state_t state);
static void crypt_save_certificate(state_t state);
static uint64_t crypt_timeout(state_t state);
static int crypt_handshake_request(state_t state, uint8_t *data, size_t *size);
static int crypt_handshake_reply(state_t state, uint8_t *data, size_t size);
static int crypt_decode(state_t state, uint8_t **dataptr, size_t *sizeptr);
#endif      /* CLIENT */
static int crypt_encode(state_t state, uint8_t **dataptr, size_t *sizeptr);
#ifdef SERVER
static inline uint32_t crypt_next_seq(state_t state);
static int crypt_activate(state_t state);
static int crypt_clone(state_t state, state_t *stateptr);
static int crypt_server_decode(state_t state, uint32_t *source_addr,
    size_t source_size, uint8_t **dataptr, size_t *sizeptr,
    uint8_t **replyptr, size_t *replysizeptr);
static bool crypt_server_init(state_t state, bool read_cert);
static void *crypt_timeout_manager(void *state_ptr);
static bool crypt_read_certificate(state_t state);
static uint32_t crypt_cookie(state_t state, uint32_t *source_addr,
    size_t source_size);
static void crypt_key(state_t state, uint32_t *source_addr, size_t source_size,
    uint32_t id, uint8_t *key);
#endif      /* SERVER */

/*
 * Crypt encoding protocol:
 */
struct cktp_enc_info_s crypt_encoding =
{
    "crypt",
    (encoding_init_t)crypt_init,
    (encoding_free_t)crypt_free,
    (encoding_overhead_t)crypt_overhead,
    (encoding_error_string_t)crypt_error_string,

#ifdef CLIENT
    (encoding_timeout_t)crypt_timeout,
    (encoding_handshake_request_t)crypt_handshake_request,
    (encoding_handshake_reply_t)crypt_handshake_reply,
    (encoding_encode_t)crypt_encode,
    (encoding_decode_t)crypt_decode
#endif      /* CLIENT */

#ifdef SERVER
    (encoding_activate_t)crypt_activate,
    (encoding_clone_t)crypt_clone,
    (encoding_encode_t)crypt_encode,
    (encoding_server_decode_t)crypt_server_decode
#endif      /* SERVER */
};

/*
 * Initialise the state.
 */
static int crypt_init(const cktp_enc_lib_t lib, const char *protocol,
    const char *options, size_t options_size, state_t *stateptr)
{
    *stateptr = NULL;
    if (strcmp(protocol, "crypt") != 0)
    {
        return CRYPT_ERROR_BAD_NAME;
    }

    bool seen_cipher = false, seen_cert = false, seen_pad = false,
         seen_sec = false;
    struct cipher_s *cipher = NULL;
    uint8_t cert_hash[CRYPT_HASH_SIZE+1];
    size_t id_size = CRYPT_DEFAULT_ID_SIZE,
           iv_size = CRYPT_DEFAULT_IV_SIZE,
           mac_size = CRYPT_DEFAULT_MAC_SIZE;
    for (size_t i = 0; i < options_size; i++)
    {
        struct cktp_enc_val_s val;
        int result = lib->parse_param(crypt_params,
            sizeof(crypt_params) / sizeof(struct cktp_enc_param_s),
            options, &val);
        if (result < 0)
        {
            return CRYPT_ERROR_BAD_URL_PARAMETER;
        }

        switch (val.param->id)
        {
            case CRYPT_CERT:
            {
                if (seen_cert)
                {
                    return CRYPT_ERROR_REPEATED_URL_PARAMETER;
                }
                if (strlen(val.val.str_val) != CRYPT_HASH_BASE64_SIZE)
                {
                    return CRYPT_ERROR_BAD_URL_PARAMETER;
                }
                if (lib->base64_decode(val.val.str_val, CRYPT_HASH_BASE64_SIZE,
                        cert_hash) != CRYPT_HASH_SIZE+1)
                {
                    return CRYPT_ERROR_BAD_URL_PARAMETER;
                }
                seen_cert = true;
                break;
            }
            case CRYPT_CIPHER:
            {
                if (seen_cipher)
                {
                    return CRYPT_ERROR_REPEATED_URL_PARAMETER;
                }
                cipher = crypt_cipher_search(val.val.str_val);
                if (cipher == NULL)
                {
                    return CRYPT_ERROR_BAD_URL_PARAMETER;
                }
                seen_cipher = true;
                break;
            }
            case CRYPT_HANDSHAKEPAD:
            {
                if (seen_pad)
                {
                    return CRYPT_ERROR_REPEATED_URL_PARAMETER;
                }
                seen_pad = true;
                break;
            }
            case CRYPT_SEC:
            {
                if (seen_sec)
                {
                    return CRYPT_ERROR_REPEATED_URL_PARAMETER;
                }
                unsigned sec = val.val.uint_val;
                size_t akey_size = (sec / 1000) % 10;
                id_size = (sec / 100) % 10;
                iv_size = (sec / 10) % 10;
                mac_size = sec % 10;
                if (akey_size < CRYPT_MIN_AKEY_SIZE ||
                    akey_size > CRYPT_MAX_AKEY_SIZE ||
                    id_size < CRYPT_MIN_ID_SIZE ||
                    id_size > CRYPT_MAX_ID_SIZE ||
                    iv_size < CRYPT_MIN_IV_SIZE ||
                    iv_size > CRYPT_MAX_IV_SIZE ||
                    mac_size < CRYPT_MIN_MAC_SIZE ||
                    mac_size > CRYPT_MAX_MAC_SIZE)
                {
                    return CRYPT_ERROR_BAD_URL_PARAMETER;
                }
                seen_sec = true;
                break;
            }
            default:
                return CRYPT_ERROR_BAD_URL_PARAMETER;
        }

        options += strlen(options) + 1;
    }

    state_t state = (state_t)malloc(sizeof(struct crypt_state_s));
    if (state == NULL)
    {
        return CRYPT_ERROR_OUT_OF_MEMORY;
    }
    state->lib      = lib;
    state->cipher   = cipher;
    state->id_size  = id_size;
    state->iv_size  = iv_size;
    state->mac_size = mac_size;
    state->pad      = seen_pad;
    memcpy(state->cert_hash, cert_hash, CRYPT_HASH_SIZE);
    state->rng = lib->random_init();
    state->ekey = (uint8_t *)malloc(cipher->ekeysize);
    if (state->ekey == NULL)
    {
        free(state);
        return CRYPT_ERROR_OUT_OF_MEMORY;
    }

#ifdef CLIENT
    if (!seen_cert)
    {
        free(state->ekey);
        free(state);
        return CRYPT_ERROR_MISSING_URL_PARAMETER;
    }
    state->have_cert = crypt_find_certificate(state);
    state->save_cert = false;
    state->state = CRYPT_STATE_HANDSHAKE_REQ_COOKIE;
#endif

#ifdef SERVER
    if (!crypt_server_init(state, seen_cert))
    {
        free(state->ekey);
        free(state);
        return CRYPT_ERROR_MISSING_URL_PARAMETER;
    }
#endif
    
    *stateptr = state;
    return 0;
}

/*
 * Search for a given cipher.
 */
static struct cipher_s *crypt_cipher_search(const char *name)
{
    struct cipher_s key;
    key.name = name;
    struct cipher_s *cipher = bsearch(&key, hardware_ciphers,
        sizeof(hardware_ciphers) / sizeof(struct cipher_s),
        sizeof(struct cipher_s), cipher_s_compare);
    if (cipher != NULL &&
        (cipher->test == NULL || cipher->test()))
    {
        return cipher;
    }
    cipher = bsearch(&key, ciphers, sizeof(ciphers) / sizeof(struct cipher_s),
        sizeof(struct cipher_s), cipher_s_compare);
    return cipher;
}

/*
 * Free state.
 */
static void crypt_free(state_t state)
{
    state->lib->random_free(state->rng);
    free(state->ekey);
#ifdef SERVER
    state->gbl_state->refcount--;
    if (state->gbl_state->refcount == 0)
    {
        quota_free(state->gbl_state->quota);
        mpz_clear(state->gbl_state->mp_certificate);
        mpz_clear(state->gbl_state->mp_sign_key);
        free(state->gbl_state);
    }
#endif
    free(state);
}

/*
 * Query crypt overhead.
 */
static size_t crypt_overhead(state_t state)
{
    return state->iv_size + state->id_size + sizeof(uint32_t) +
        state->mac_size;
}

/*
 * Convert error codes to strings.
 */
static const char *crypt_error_string(state_t state, int err)
{
    switch (err)
    {
        case CRYPT_ERROR_BAD_NAME:
            return "bad encoding name";
        case CRYPT_ERROR_BAD_STATE:
            return "bad internal state";
        case CRYPT_ERROR_BAD_LENGTH:
            return "bad message length";
        case CRYPT_ERROR_BAD_CERTIFICATE:
            return "bad certificate";
        case CRYPT_ERROR_BAD_PARAMETER:
            return "bad cryptographic parameter";
        case CRYPT_ERROR_BAD_VERSION:
            return "bad protocol version";
        case CRYPT_ERROR_BAD_MAGIC_NUMBER:
            return "bad magic number";
        case CRYPT_ERROR_BAD_TIMEOUT:
            return "bad timeout value";
        case CRYPT_ERROR_BAD_COOKIE:
            return "bad cookie";
        case CRYPT_ERROR_BAD_SEQ:
            return "bad sequence number";
        case CRYPT_ERROR_BAD_MAC:
            return "bad message authentication code";
        case CRYPT_ERROR_BAD_URL_PARAMETER:
            return "bad URL parameter";
        case CRYPT_ERROR_MISSING_URL_PARAMETER:
            return "missing URL parameter";
        case CRYPT_ERROR_REPEATED_URL_PARAMETER:
            return "repeated URL parameter";
        case CRYPT_ERROR_OUT_OF_MEMORY:
            return "out of memory";
        case CRYPT_ERROR_DOS:
            return "dos packet";
        default:
            return "generic error";
    }
}

/*
 * Add a random extension to a handshake packet.
 */
static size_t crypt_handshake_pad_length(state_t state, uint8_t *data,
    size_t size)
{
    if (state->pad)
    {
        size_t extend;
        state->lib->random(state->rng, &extend, sizeof(extend));
        extend = extend % (size / 2);
        state->lib->random(state->rng, data+size, extend);
        return size + extend;
    }
    else
    {
        return size;
    }
}

/*
 * Returns 'true' iff extension is valid.
 */
static bool crypt_handshake_is_valid_length(state_t state, size_t basesize,
    size_t extsize)
{
    if (state->pad)
    {
        return (extsize >= basesize);
    }
    else
    {
        return (extsize == basesize);
    }
}

/*
 * Get a sequence number.
 */
static uint32_t crypt_seq(uint32_t seq, uint64_t seq_key)
{
    // Micro encryption based on TEA:
    register uint16_t v0 = (uint16_t)seq, v1 = (uint16_t)(seq >> 16), sum = 0;
    register uint16_t k0 = (uint16_t)seq_key, k1 = (uint16_t)(seq_key >> 16),
        k2 = (uint16_t)(seq_key >> 32), k3 = (uint16_t)(seq_key >> 48);
    for (register unsigned i = 0; i < 8; i++)
    {
        sum += 0x9E37;
        v0 += ((v1 << 2) + k0) ^ (v1 + sum) ^ ((v1 >> 3) + k1);
        v1 += ((v0 << 2) + k2) ^ (v0 + sum) ^ ((v0 >> 3) + k3);  
    }
    return ((uint32_t)v0 | (((uint32_t)v1) << 16));
}

#ifdef CLIENT

/*
 * Find a certificate from the local cache.
 */
static bool crypt_find_certificate(state_t state)
{
    FILE *file = fopen(CRYPT_CERT_CACHE_FILENAME, "r");
    if (file == NULL)
    {
        return false;
    }

    while (true)
    {
        char c = getc(file);
        switch (c)
        {
            case EOF:
                fclose(file);
                return false;
            case '\n':
                continue;
            case '#':
                while ((c = getc(file)) != '\n' && c != EOF)
                    ;
                continue;
            default:
                ungetc(c, file);
                break;
        }

        bool cipher_match = true;
        size_t i;
        for (i = 0; (c = getc(file)) != '\t'; i++)
        {
            if (!isalpha(c))
            {
                fclose(file);
                goto parse_error;
            }
            if (cipher_match)
            {
                cipher_match = (c == state->cipher->name[i]);
            }
        }
        if (cipher_match && state->cipher->name[i] != '\0')
        {
            cipher_match = false;
        }

        char cert_hash_str[CRYPT_HASH_BASE64_SIZE + 1];
        char cert_str[CRYPT_PUBLIC_KEY_BASE64_SIZE + 1];
        if (getc(file) != '\t' ||
            fgets(cert_hash_str, sizeof(cert_hash_str), file) == NULL ||
            getc(file) != ' ' ||
            fgets(cert_str, sizeof(cert_str), file) == NULL ||
            getc(file) != '\n')
        {
            fclose(file);
            goto parse_error;
        }

        if (!cipher_match)
        {
            continue;
        }

        uint8_t cert_hash[CRYPT_HASH_SIZE+1];
        if (state->lib->base64_decode(cert_hash_str, sizeof(cert_hash_str)-1,
                cert_hash) != sizeof(cert_hash))
        {
            fclose(file);
            goto parse_error;
        }

        if (memcmp(cert_hash, state->cert_hash, sizeof(state->cert_hash)) == 0)
        {
            fclose(file);
            uint8_t cert[CRYPT_PUBLIC_KEY_SIZE+1];
            if (state->lib->base64_decode(cert_str, sizeof(cert_str)-1,
                    cert) != sizeof(cert))
            {
                goto parse_error;
            }
            memcpy(state->certificate, cert, sizeof(state->certificate));
            
            // Verify the certificate hash:
            hash(state->cipher, state->certificate, sizeof(state->certificate),
                cert_hash);
            if (memcmp(cert_hash, state->cert_hash, sizeof(state->cert_hash))
                    != 0)
            {
                goto parse_error;
            }

            return true;
        }
    }

parse_error:
    // If there is a parse error we assume the file is corrupted.  Delete it.
    remove(CRYPT_CERT_CACHE_FILENAME);
    return false;
}

/*
 * Save a local copy of the given certificate.
 */
static void crypt_save_certificate(state_t state)
{
    char cert_hash_str[CRYPT_HASH_BASE64_SIZE + 1];
    size_t end = state->lib->base64_encode(state->cert_hash,
        sizeof(state->cert_hash), cert_hash_str);
    cert_hash_str[end] = '\0';

    char cert_str[CRYPT_PUBLIC_KEY_BASE64_SIZE + 1];
    end = state->lib->base64_encode(state->certificate,
        sizeof(state->certificate), cert_str);
    cert_str[end] = '\0';

    FILE *file = fopen(CRYPT_CERT_CACHE_FILENAME, "a");
    if (file == NULL)
    {
        return;
    }

    fprintf(file, "%s\t\t%s %s\n", state->cipher->name, cert_hash_str,
        cert_str);
    fclose(file);
}

/*
 * Get the timeout.
 */
static uint64_t crypt_timeout(state_t state)
{
    return state->timeout;
}

/*
 * Handshake request.
 */
static int crypt_handshake_request(state_t state, uint8_t *data, size_t *size)
{
    switch (state->state)
    {
        case 0:
            return 0;       // TODO: fix
        case CRYPT_STATE_HANDSHAKE_REQ_COOKIE:
        {
            struct crypt_req_cookie_wrap_s
            {
                uint8_t iv[state->iv_size];
                uint8_t id[state->id_size];
                struct crypt_req_cookie_s request;
            } __attribute__((packed));
            typedef struct crypt_req_cookie_wrap_s *crypt_req_cookie_wrap_t;
            crypt_req_cookie_wrap_t req = (crypt_req_cookie_wrap_t)data;

            state->lib->random(state->rng, req->iv, sizeof(req->iv));
            uint64_t id = CRYPT_ID_REQ_COOKIE;
            memcpy(req->id, &id, sizeof(req->id));
            state->lib->random(state->rng, &state->seq, sizeof(state->seq));
            req->request.seq = state->seq;
            state->lib->random(state->rng, &req->request.unused,
                sizeof(req->request.unused));
            crypt(state->cipher, req->iv, sizeof(req->iv), state->cert_hash,
                req->id, sizeof(req->id) + sizeof(req->request.seq));
            *size = crypt_handshake_pad_length(state, data, sizeof(*req));
            return CRYPT_STATE_HANDSHAKE_REQ_COOKIE;
        }
        case CRYPT_STATE_HANDSHAKE_REQ_CERTIFICATE:
        {
            struct crypt_req_certificate_wrap_s
            {
                uint8_t iv[state->iv_size];
                uint8_t id[state->id_size];
                struct crypt_req_certificate_s request;
            } __attribute__((packed));
            typedef struct crypt_req_certificate_wrap_s *
                crypt_req_certificate_wrap_t;
            crypt_req_certificate_wrap_t req =
                (crypt_req_certificate_wrap_t)data;

            state->lib->random(state->rng, req->iv, sizeof(req->iv));
            uint64_t id = CRYPT_ID_REQ_CERTIFICATE;
            memcpy(req->id, &id, sizeof(req->id));
            state->lib->random(state->rng, &state->seq, sizeof(state->seq));
            req->request.seq = state->seq;
            req->request.cookie = state->id;
            crypt(state->cipher, req->iv, sizeof(req->iv), state->cert_hash,
                req->id, sizeof(req->id) + sizeof(req->request));
            *size = crypt_handshake_pad_length(state, data, sizeof(*req));
            return CRYPT_STATE_HANDSHAKE_REQ_CERTIFICATE;
        }
        case CRYPT_STATE_HANDSHAKE_REQ_KEY:
        {
            struct crypt_req_key_wrap_s
            {
                uint8_t iv[state->iv_size];
                uint8_t id[state->id_size];
                struct crypt_req_key_s request;
            } __attribute__((packed));
            typedef struct crypt_req_key_wrap_s *crypt_req_key_wrap_t;
            crypt_req_key_wrap_t req = (crypt_req_key_wrap_t)data;

            state->lib->random(state->rng, req->iv, sizeof(req->iv));
            uint64_t id = CRYPT_ID_REQ_KEY;
            memcpy(req->id, &id, sizeof(req->id));
            state->lib->random(state->rng, &state->seq, sizeof(state->seq));
            req->request.seq = state->seq;
            req->request.cookie = state->id;

            N e[N_SIZE], p[N_SIZE], b[N_SIZE];
            uint8_t g = CRYPT_DH_GENERATOR;
            N_set(&g, sizeof(g), b);
            
            // Generate DH private key.  Make sure it is < p0
            do
            {
                state->lib->random(state->rng, state->key, sizeof(state->key));
            }
            while (memcmp(state->key + CRYPT_PUBLIC_KEY_SIZE -
                    sizeof(uint64_t), p0 + CRYPT_PUBLIC_KEY_SIZE -
                    sizeof(uint64_t), sizeof(uint64_t)) >= 0);

            N_set(state->key, sizeof(state->key), e);
            N_set(p0, sizeof(p0), p);
            N r[N_SIZE];
            N_modexp(b, e, p, r);
            N_get(req->request.public_key, sizeof(req->request.public_key), r);
            crypt(state->cipher, req->iv, sizeof(req->iv), state->cert_hash,
                req->id, sizeof(req->id) + sizeof(req->request));
            *size = crypt_handshake_pad_length(state, data, sizeof(*req));
            return CRYPT_STATE_HANDSHAKE_REQ_KEY;
        }
    }
    return CRYPT_ERROR_BAD_STATE;
}

/*
 * Handshake reply.
 */
static int crypt_handshake_reply(state_t state, uint8_t *data, size_t size)
{
    switch (state->state)
    {
        case CRYPT_STATE_HANDSHAKE_REQ_COOKIE:
        {
            struct crypt_rep_cookie_wrap_s
            {
                uint8_t iv[state->iv_size];
                struct crypt_rep_cookie_s reply;
            } __attribute__((packed));
            typedef struct crypt_rep_cookie_wrap_s *crypt_rep_cookie_wrap_t;
            crypt_rep_cookie_wrap_t rep = (crypt_rep_cookie_wrap_t)data;

            if (!crypt_handshake_is_valid_length(state, sizeof(*rep), size))
            {
                return CRYPT_ERROR_BAD_LENGTH;
            }
            crypt(state->cipher, rep->iv, sizeof(rep->iv), state->cert_hash,
                (uint8_t *)&rep->reply, sizeof(rep->reply));
            if (rep->reply.seq != state->seq)
            {
                return CRYPT_ERROR_BAD_SEQ;
            }
            state->id = rep->reply.cookie;
            if (state->have_cert)
            {
                state->state = CRYPT_STATE_HANDSHAKE_REQ_KEY;
            }
            else
            {
                state->state = CRYPT_STATE_HANDSHAKE_REQ_CERTIFICATE;
            }
            return state->state;
        }
        case CRYPT_STATE_HANDSHAKE_REQ_CERTIFICATE:
        {
            struct crypt_rep_certificate_wrap_s
            {
                uint8_t iv[state->iv_size];
                struct crypt_rep_certificate_s reply;
            } __attribute__((packed));
            typedef struct crypt_rep_certificate_wrap_s *
                crypt_rep_certificate_wrap_t;
            crypt_rep_certificate_wrap_t rep =
                (crypt_rep_certificate_wrap_t)data;

            if (!crypt_handshake_is_valid_length(state, sizeof(*rep), size))
            {
                return CRYPT_ERROR_BAD_LENGTH;
            }
            crypt(state->cipher, rep->iv, sizeof(rep->iv), state->cert_hash,
                (uint8_t *)&rep->reply, sizeof(rep->reply));
            if (rep->reply.seq != state->seq)
            {
                return CRYPT_ERROR_BAD_SEQ;
            }

            // Check the authenticity of the certificate:
            uint8_t cert_hash[CRYPT_HASH_SIZE];
            hash(state->cipher, rep->reply.certificate,
                sizeof(rep->reply.certificate), cert_hash);
            if (memcmp(cert_hash, state->cert_hash, sizeof(cert_hash)) != 0)
            {
                return CRYPT_ERROR_BAD_CERTIFICATE;
            }

            state->have_cert = true;
            state->save_cert = true;
            memcpy(state->certificate, rep->reply.certificate,
                sizeof(state->certificate));
            state->state = CRYPT_STATE_HANDSHAKE_REQ_KEY;
            return CRYPT_STATE_HANDSHAKE_REQ_KEY;
        }
        case CRYPT_STATE_HANDSHAKE_REQ_KEY:
        {
            struct crypt_rep_key_wrap_s
            {
                uint8_t iv[state->iv_size];
                struct crypt_rep_key_s reply;
            } __attribute__((packed));
            typedef struct crypt_rep_key_wrap_s *crypt_rep_key_wrap_t;
            crypt_rep_key_wrap_t rep = (crypt_rep_key_wrap_t)data;

            if (!crypt_handshake_is_valid_length(state, sizeof(*rep), size))
            {
                return CRYPT_ERROR_BAD_LENGTH;
            }
            N e[N_SIZE], p[N_SIZE], b[N_SIZE];
            crypt(state->cipher, rep->iv, sizeof(rep->iv), state->cert_hash,
                (uint8_t *)&rep->reply, sizeof(rep->reply.seq) +
                sizeof(rep->reply.public_key) + sizeof(rep->reply.seq2));
            if (rep->reply.seq != state->seq)
            {
                return CRYPT_ERROR_BAD_SEQ;
            }

            // Calculate DH shared secret key:
            N_set(p0, sizeof(p0), p);
            N_set(rep->reply.public_key, sizeof(rep->reply.public_key), b);
            if (!N_lt2(b, p))
            {
                return CRYPT_ERROR_BAD_PARAMETER;
            }
            N_set(state->key, sizeof(state->key), e);
            N r[N_SIZE];
            N_modexp(b, e, p, r);
            if (!N_neq1(r))
            {
                return CRYPT_ERROR_BAD_PARAMETER;
            }
            uint8_t t[CRYPT_PUBLIC_KEY_SIZE];
            N_get(t, sizeof(t), r);
            uint8_t key[CRYPT_KEY_SIZE];
            hash(state->cipher, t, sizeof(t), key);

            // Decrypt the rest of the message:
            uint8_t ekey[state->cipher->ekeysize];
            state->cipher->expandkey(key, sizeof(key), ekey);
            uint64_t mac = decrypt(state->cipher, (uint8_t *)&rep->reply.iv,
                sizeof(rep->reply.iv), rep->reply.seq2, ekey,
                (uint8_t *)&rep->reply.encrypted,
                sizeof(rep->reply.encrypted));
            if (mac != rep->reply.mac)
            {
                return CRYPT_ERROR_BAD_MAC;
            }
            if (rep->reply.encrypted.version != CRYPT_VERSION)
            {
                return CRYPT_ERROR_BAD_VERSION;
            }
            if (rep->reply.encrypted.magic != CRYPT_MAGIC)
            {
                return CRYPT_ERROR_BAD_MAGIC_NUMBER;
            }
            
            // Decrypt the signature using the public key:
            N_set(state->certificate, sizeof(state->certificate), p);
            N_set(rep->reply.encrypted.signature,
                sizeof(rep->reply.encrypted.signature), b);
            uint32_t e0 = CRYPT_RSA_EXPONENT;
            N_set((uint8_t *)&e0, sizeof(e0), e);
            N_modexp(b, e, p, r);
            N_get(t, sizeof(t), r);

            struct crypt_signed_data_s *signed_data =
                (struct crypt_signed_data_s *)t;
            mac = decrypt(state->cipher, (uint8_t *)&signed_data->iv,
                sizeof(signed_data->iv), rep->reply.seq2, ekey,
                (uint8_t *)&signed_data->encrypted,
                sizeof(signed_data->encrypted));
            if (signed_data->encrypted.magic1 != CRYPT_SIGNED_MAGIC_1 ||
                signed_data->encrypted.magic2 != CRYPT_SIGNED_MAGIC_2)
            {
                return CRYPT_ERROR_BAD_MAGIC_NUMBER;
            }
            if (mac != signed_data->mac)
            {
                return CRYPT_ERROR_BAD_MAC;
            }
            if (signed_data->encrypted.version != CRYPT_VERSION)
            {
                return CRYPT_ERROR_BAD_VERSION;
            }
            if (signed_data->encrypted.seq != state->seq)
            {
                return CRYPT_ERROR_BAD_SEQ;
            }
            state->id = signed_data->encrypted.id;
            if (signed_data->encrypted.timeout < CRYPT_MIN_TIMEOUT ||
                signed_data->encrypted.timeout > CRYPT_MAX_TIMEOUT)
            {
                return CRYPT_ERROR_BAD_TIMEOUT;
            }
            state->timeout = state->lib->gettime() +
                signed_data->encrypted.timeout;
            memcpy(state->key, signed_data->encrypted.key,
                sizeof(signed_data->encrypted.key));
            state->cipher->expandkey(signed_data->encrypted.key,
                sizeof(signed_data->encrypted.key), state->ekey);
            state->state = 0;

            // Save the certificate if required
            if (state->save_cert)
            {
                crypt_save_certificate(state);
            }

            // Initialize the sequence number.
            state->lib->random(state->rng, &state->seq, sizeof(state->seq));
            state->lib->random(state->rng, &state->seq_key,
                sizeof(state->seq_key));

            return 0;
        }
    }
    return CRYPT_ERROR_BAD_STATE;
}

/*
 * Decode a packet.
 */
static int crypt_decode(state_t state, uint8_t **dataptr, size_t *sizeptr)
{
    uint8_t *data = *dataptr;
    size_t size = *sizeptr;

    struct crypt_server_header_s
    {
        uint8_t iv[state->iv_size];
        uint32_t seq;
        uint8_t mac[state->mac_size];
    } __attribute__((packed));
    typedef struct crypt_server_header_s *crypt_server_header_t;

    if (size <= sizeof(struct crypt_server_header_s))
    {
        *dataptr = NULL;
        *sizeptr = 0;
        return CRYPT_ERROR_BAD_LENGTH;
    }

    crypt_server_header_t header = (crypt_server_header_t)data;
    crypt(state->cipher, header->iv, sizeof(header->iv), state->cert_hash,
        (uint8_t *)&header->seq, sizeof(header->seq));
    uint8_t *payload = data + sizeof(struct crypt_server_header_s);
    size_t payloadsize = size - sizeof(struct crypt_server_header_s);
    uint64_t mac = decrypt(state->cipher, header->iv, sizeof(header->iv),
        header->seq, state->ekey, payload, payloadsize);

    if (memcmp(header->mac, &mac, sizeof(header->mac)) != 0)
    {
        *dataptr = NULL;
        *sizeptr = 0;
        return CRYPT_ERROR_BAD_MAC;
    }

    *dataptr = payload;
    *sizeptr = payloadsize;
    return 0;
}

/*
 * Encode a packet.
 */
static int crypt_encode(state_t state, uint8_t **dataptr, size_t *sizeptr)
{
    uint8_t *data = *dataptr, *data0 = data;
    size_t size = *sizeptr, size0 = size;

    struct crypt_client_header_s
    {
        uint8_t iv[state->iv_size];
        uint8_t id[state->id_size];
        uint32_t seq;
        uint8_t mac[state->mac_size];
    } __attribute__((packed));
    typedef struct crypt_client_header_s *crypt_client_header_t;

    data -= sizeof(struct crypt_client_header_s);
    size += sizeof(struct crypt_client_header_s);
   
    crypt_client_header_t header = (crypt_client_header_t)data;
    memcpy(header->id, &state->id, sizeof(header->id));
    header->seq = crypt_seq(state->seq++, state->seq_key);
    state->lib->random(state->rng, header->iv, sizeof(header->iv));
    uint64_t mac = encrypt(state->cipher, header->iv, sizeof(header->iv),
        header->seq, state->ekey, data0, size0);
    memcpy(header->mac, &mac, sizeof(header->mac));
    crypt(state->cipher, header->iv, sizeof(header->iv), state->cert_hash,
        header->id, sizeof(header->id) + sizeof(header->seq));

    *dataptr = data;
    *sizeptr = size;
    return 0;
}

#endif      /* CLIENT */

#ifdef SERVER

/*
 * Get next sequence number (thread safe).
 */
static inline uint32_t crypt_next_seq(state_t state)
{
    uint32_t seq0 = __sync_fetch_and_add(&state->gbl_state->seq, 1);
    return crypt_seq(seq0, state->gbl_state->seq_key);
}

/*
 * Activate state.
 */
static int crypt_activate(state_t state)
{
    thread_t thread;
    if (thread_create(&thread, crypt_timeout_manager, (void *)state))
    {
        return CRYPT_ERROR_OUT_OF_MEMORY;
    }

    return 0;
}

/*
 * Clone state.
 */
static int crypt_clone(state_t state, state_t *stateptr)
{
    state_t newstate = (state_t)malloc(sizeof(struct crypt_state_s));
    uint8_t *newekey = (uint8_t *)malloc(state->cipher->ekeysize);
    if (newstate == NULL || newekey == NULL)
    {
        return CRYPT_ERROR_OUT_OF_MEMORY;
    }
    memcpy(newstate, state, sizeof(struct crypt_state_s));
    newstate->ekey = newekey;
    state->gbl_state->refcount++;

    // New (independent) RNG:
    newstate->rng = state->lib->random_init();
    *stateptr = newstate;
    return 0;
}

/*
 * Server handle a packet.
 */
static int crypt_server_decode(state_t state, uint32_t *source_addr,
    size_t source_size, uint8_t **dataptr, size_t *sizeptr,
    uint8_t **replyptr, size_t *replysizeptr)
{
    uint8_t *data = *dataptr;
    size_t size = *sizeptr;
    uint8_t *reply = *replyptr;

    // Client header:
    struct crypt_client_header_s
    {
        uint8_t iv[state->iv_size];
        uint8_t id[state->id_size];
        uint32_t seq;
        uint8_t mac[state->mac_size];
    } __attribute__((packed));
    typedef struct crypt_client_header_s *crypt_client_header_t;

    crypt_client_header_t client_header = (crypt_client_header_t)data;
    if (size <= sizeof(client_header->iv) + sizeof(client_header->id) +
            sizeof(client_header->seq))
    {
        return CRYPT_ERROR_BAD_LENGTH;
    }
    // NOTE: This has the side-affect of decrypting seq in any handshake
    //       packet.
    crypt(state->cipher, client_header->iv, sizeof(client_header->iv),
        state->cert_hash, client_header->id, sizeof(client_header->id) +
        sizeof(client_header->seq));
    uint64_t id = 0;
    memcpy(&id, client_header->id, sizeof(client_header->id));

    // Packet is a handshake packet:
    switch (id)
    {
        case CRYPT_ID_REQ_COOKIE:
        {
            // Packet is a cookie request.
            struct crypt_req_cookie_wrap_s
            {
                uint8_t iv[state->iv_size];
                uint8_t id[state->id_size];
                struct crypt_req_cookie_s request;
            } __attribute__((packed));
            typedef struct crypt_req_cookie_wrap_s *crypt_req_cookie_wrap_t;
            crypt_req_cookie_wrap_t req = (crypt_req_cookie_wrap_t)data;

            struct crypt_rep_cookie_wrap_s
            {
                uint8_t iv[state->iv_size];
                struct crypt_rep_cookie_s reply;
            } __attribute__((packed));
            typedef struct crypt_rep_cookie_wrap_s *crypt_rep_cookie_wrap_t;
            crypt_rep_cookie_wrap_t rep = (crypt_rep_cookie_wrap_t)reply;

            if (!crypt_handshake_is_valid_length(state, sizeof(*req), size))
            {
                return CRYPT_ERROR_BAD_LENGTH;
            }
            
            rep->reply.seq = req->request.seq;
            rep->reply.cookie = crypt_cookie(state, source_addr, source_size);
            state->lib->random(state->rng, rep->iv, sizeof(rep->iv));
            crypt(state->cipher, rep->iv, sizeof(rep->iv), state->cert_hash,
                (uint8_t *)&rep->reply, sizeof(rep->reply));
            *replysizeptr =
                crypt_handshake_pad_length(state, reply, sizeof(*rep));
            *dataptr = NULL;
            *sizeptr = 0;
            return 0;
        }
        case CRYPT_ID_REQ_CERTIFICATE:
        {
            // Packet is a certificate request.
            struct crypt_req_certificate_wrap_s
            {
                uint8_t iv[state->iv_size];
                uint8_t id[state->id_size];
                struct crypt_req_certificate_s request;
            } __attribute__((packed));
            typedef struct crypt_req_certificate_wrap_s *
                crypt_req_certificate_wrap_t;
            crypt_req_certificate_wrap_t req =
                (crypt_req_certificate_wrap_t)data;

            struct crypt_rep_certificate_wrap_s
            {
                uint8_t iv[state->iv_size];
                struct crypt_rep_certificate_s reply;
            } __attribute__((packed));
            typedef struct crypt_rep_certificate_wrap_s *
                crypt_rep_certificate_wrap_t;
            crypt_rep_certificate_wrap_t rep =
                (crypt_rep_certificate_wrap_t)reply;

            if (!crypt_handshake_is_valid_length(state, sizeof(*req), size))
            {
                return CRYPT_ERROR_BAD_LENGTH;
            }
            rep->reply.seq = req->request.seq;
            crypt(state->cipher, req->iv, sizeof(req->iv), state->cert_hash,
                req->id, sizeof(req->id) + sizeof(req->request));
            if (req->request.cookie != crypt_cookie(state, source_addr,
                    source_size))
            {
                return CRYPT_ERROR_BAD_COOKIE;
            }
            memcpy(rep->reply.certificate, state->certificate,
                sizeof(rep->reply.certificate));
            state->lib->random(state->rng, rep->iv, sizeof(rep->iv));
            crypt(state->cipher, rep->iv, sizeof(rep->iv), state->cert_hash,
                (uint8_t *)&rep->reply, sizeof(rep->reply));
            *replysizeptr =
                crypt_handshake_pad_length(state, reply, sizeof(*rep));
            *dataptr = NULL;
            *sizeptr = 0;
            return 0;
        }
        case CRYPT_ID_REQ_KEY:
        {
            // Packet is a key request.
            struct crypt_req_key_wrap_s
            {
                uint8_t iv[state->iv_size];
                uint8_t id[state->id_size];
                struct crypt_req_key_s request;
            } __attribute__((packed));
            typedef struct crypt_req_key_wrap_s *crypt_req_key_wrap_t;
            crypt_req_key_wrap_t req = (crypt_req_key_wrap_t)data;

            struct crypt_rep_key_wrap_s
            {
                uint8_t iv[state->iv_size];
                struct crypt_rep_key_s reply;
            } __attribute__((packed));
            typedef struct crypt_rep_key_wrap_s *crypt_rep_key_wrap_t;
            crypt_rep_key_wrap_t rep = (crypt_rep_key_wrap_t)reply;
            
            if (!crypt_handshake_is_valid_length(state, sizeof(*req), size))
            {
                return CRYPT_ERROR_BAD_LENGTH;
            }
            rep->reply.seq = req->request.seq;
            crypt(state->cipher, req->iv, sizeof(req->iv), state->cert_hash,
                req->id, sizeof(req->id) + sizeof(req->request));
            if (req->request.cookie != crypt_cookie(state, source_addr,
                    source_size))
            {
                return CRYPT_ERROR_BAD_COOKIE;
            }

            // First determine if we should service this request:
            // Note: must come after cookie check.
            if (!quota_check(state->gbl_state->quota, state->lib, state->rng,
                    source_addr, source_size))
            {
                // Packet is likely part of a DoS, ignore it:
                return CRYPT_ERROR_DOS;
            }

            // Get the client's DH public key:
            mpz_t client_public_key;
            mpz_init(client_public_key);
            mpz_import(client_public_key, sizeof(req->request.public_key), -1,
                sizeof(uint8_t), 0, 0, req->request.public_key);

            // CHECK: g^x != 1
            if (mpz_cmp_ui(client_public_key, 1) <= 0)
            {
                mpz_clear(client_public_key);
                return CRYPT_ERROR_BAD_PARAMETER;
            }

            // CHECK: g^x < p - 1
            if (mpz_cmp(client_public_key, p1) >= 0)
            {
                mpz_clear(client_public_key);
                return CRYPT_ERROR_BAD_PARAMETER;
            }

            // Make a DH private key:
            uint8_t t[CRYPT_PUBLIC_KEY_SIZE];
            mpz_t server_private_key;
            mpz_init(server_private_key);
            do
            {
                state->lib->random(state->rng, t, sizeof(t));
                mpz_import(server_private_key, sizeof(t), -1, sizeof(uint8_t),
                    0, 0, t);
                // CHECK: x in {2, ..., p - 2}
            }
            while (mpz_cmp(server_private_key, p1) >= 0 ||
                   mpz_cmp_ui(server_private_key, 1) <= 0);

            // Compute the DH shared secret key:
            mpz_t shared_key;
            mpz_init(shared_key);
            mpz_powm(shared_key, client_public_key, server_private_key, p);
            mpz_clear(client_public_key);

            // CHECK: g^xy != 1
            if (mpz_cmp_ui(shared_key, 1) == 0)
            {
                mpz_clear(server_private_key);
                mpz_clear(shared_key);
                return CRYPT_ERROR_BAD_PARAMETER;
            }

            // Compute the DH public ket for the server:
            mpz_t server_public_key;
            mpz_init(server_public_key);
            mpz_powm(server_public_key, g, server_private_key, p);
            mpz_clear(server_private_key);
            mpz_export(rep->reply.public_key, NULL, -1, sizeof(uint8_t), 0, 0,
                server_public_key);
            mpz_clear(server_public_key);

            // Compute the key for encrypting the rest of the reply:
            mpz_export(t, NULL, -1, sizeof(uint8_t), 0, 0, shared_key);
            mpz_clear(shared_key);
            uint8_t request_key[CRYPT_KEY_SIZE];
            hash(state->cipher, t, sizeof(t), request_key);
            
            // Setup the private (encrypted) part of the reply:
            rep->reply.encrypted.version = CRYPT_VERSION;
            rep->reply.encrypted.magic   = CRYPT_MAGIC;
            
            // Create the private & signed part of the reply:
            state->lib->random(state->rng, rep->reply.encrypted.signature +
                sizeof(struct crypt_signed_data_s),
                sizeof(rep->reply.encrypted.signature) -
                sizeof(struct crypt_signed_data_s));
            struct crypt_signed_data_s *signed_data =
                (struct crypt_signed_data_s *)rep->reply.encrypted.signature;
            signed_data->encrypted.magic1 = CRYPT_SIGNED_MAGIC_1;
            signed_data->encrypted.magic2 = CRYPT_SIGNED_MAGIC_2;
            signed_data->encrypted.version = CRYPT_VERSION;
            signed_data->encrypted.seq = rep->reply.seq;
            uint64_t id;
            state->lib->random(state->rng, &id, sizeof(id));
            id &= ~CRYPT_GEN_IDX_MASK;
            id |= (uint64_t)state->gbl_state->gen_idx;
            signed_data->encrypted.id = id;
            uint64_t currtime = state->lib->gettime();
            uint64_t randtime;
            state->lib->random(state->rng, &randtime, sizeof(randtime));
            uint64_t timeout = (state->gbl_state->gen_timeout - currtime) +
                CRYPT_TIMEOUT_BUFF +
                randtime % (CRYPT_TIMEOUT - 2*CRYPT_TIMEOUT_BUFF);
            if (timeout <= CRYPT_MIN_TIMEOUT + CRYPT_TIMEOUT_BUFF)
            {
                timeout = CRYPT_MIN_TIMEOUT + CRYPT_TIMEOUT_BUFF +
                    (~randtime) % (CRYPT_TIMEOUT - CRYPT_MIN_TIMEOUT - 
                        2*CRYPT_TIMEOUT_BUFF);
            }
            signed_data->encrypted.timeout = timeout;
            state->lib->random(state->rng, signed_data->encrypted.reserved,
                sizeof(signed_data->encrypted.reserved));
            crypt_key(state, source_addr, source_size,
                signed_data->encrypted.id, signed_data->encrypted.key);
            state->lib->random(state->rng, &signed_data->iv,
                sizeof(signed_data->iv));
            uint8_t ekey[state->cipher->ekeysize];
            state->cipher->expandkey(request_key, sizeof(request_key), ekey);
            rep->reply.seq2 = crypt_next_seq(state);
            signed_data->mac = encrypt(state->cipher,
                (uint8_t *)&signed_data->iv, sizeof(signed_data->iv),
                rep->reply.seq2, ekey, (uint8_t *)&signed_data->encrypted,
                sizeof(signed_data->encrypted));

            // MSB unset, ensure message <= n
            rep->reply.encrypted.signature[CRYPT_PUBLIC_KEY_SIZE-1] &= 0x7F;

            // Sign the relevant part of the reply:
            mpz_t signature;
            mpz_init(signature);
            mpz_import(signature, sizeof(rep->reply.encrypted.signature), -1,
                sizeof(uint8_t), 0, 0, rep->reply.encrypted.signature);
            mpz_t sign_result;
            mpz_init(sign_result);
            mpz_powm(sign_result, signature, state->gbl_state->mp_sign_key,
                state->gbl_state->mp_certificate);
            mpz_clear(signature);
            mpz_export(rep->reply.encrypted.signature, NULL, -1,
                sizeof(uint8_t), 0, 0, sign_result);
            mpz_clear(sign_result);

            // Encrypt the private data:
            state->lib->random(state->rng, &rep->reply.iv,
                sizeof(rep->reply.iv));
            rep->reply.mac = encrypt(state->cipher, (uint8_t *)&rep->reply.iv,
                sizeof(rep->reply.iv), rep->reply.seq2, ekey,
                (uint8_t *)&rep->reply.encrypted,
                sizeof(rep->reply.encrypted));

            // Scramble header:
            state->lib->random(state->rng, rep->iv, sizeof(rep->iv));
            crypt(state->cipher, rep->iv, sizeof(rep->iv), state->cert_hash,
                (uint8_t *)&rep->reply, sizeof(rep->reply.seq) +
                sizeof(rep->reply.public_key) + sizeof(rep->reply.seq2));
            *replysizeptr =
                crypt_handshake_pad_length(state, reply, sizeof(*rep));
            *dataptr = NULL;
            *sizeptr = 0;

            // All done:
            return 0;
        }
        default:
        {
            // This is a tunnelled packet, not a handshake packet.
            if (size <= sizeof(struct crypt_client_header_s))
            {
                return CRYPT_ERROR_BAD_LENGTH;
            }
            uint8_t *payload = data + sizeof(struct crypt_client_header_s);
            size_t payloadsize = size - sizeof(struct crypt_client_header_s);
            crypt_key(state, source_addr, source_size, id, state->key);
            state->cipher->expandkey(state->key, sizeof(state->key),
                state->ekey);
            uint64_t mac = decrypt(state->cipher, client_header->iv,
                sizeof(client_header->iv), client_header->seq, state->ekey,
                payload, payloadsize);
            if (memcmp(client_header->mac, &mac, sizeof(client_header->mac))
                    != 0)
            {
                return CRYPT_ERROR_BAD_MAC;
            }
            state->id = 0;
            memcpy(&state->id, client_header->id, sizeof(client_header->id));
            *dataptr = payload;
            *sizeptr = payloadsize;
            return 0;
        }
    }
}

/*
 * Encode a packet.
 */
static int crypt_encode(state_t state, uint8_t **dataptr, size_t *sizeptr)
{
    uint8_t *data = *dataptr, *data0 = data;
    size_t size = *sizeptr, size0 = size;

    struct crypt_server_header_s
    {
        uint8_t iv[state->iv_size];
        uint32_t seq;
        uint8_t mac[state->mac_size];
    } __attribute__((packed));
    typedef struct crypt_server_header_s *crypt_server_header_t;

    data -= sizeof(struct crypt_server_header_s);
    size += sizeof(struct crypt_server_header_s);

    crypt_server_header_t header = (crypt_server_header_t)data;
    state->lib->random(state->rng, header->iv, sizeof(header->iv));
    header->seq = crypt_next_seq(state);
    uint64_t mac = encrypt(state->cipher, header->iv, sizeof(header->iv),
        header->seq, state->ekey, data0, size0);
    memcpy(header->mac, &mac, sizeof(header->mac));
    crypt(state->cipher, header->iv, sizeof(header->iv), state->cert_hash,
        (uint8_t *)&header->seq, sizeof(header->seq));

    *dataptr = data;
    *sizeptr = size;
    return 0;
}

/*
 * Server specific initialisation.
 */
static bool crypt_server_init(state_t state, bool read_cert)
{
    struct crypt_global_state_s *gbl_state = (struct crypt_global_state_s *)
        malloc(sizeof(struct crypt_global_state_s));
    if (gbl_state == NULL)
    {
        return false;
    }
    gbl_state->refcount = 1;
    state->gbl_state = gbl_state;

    if (!cookie_gen_init(gbl_state->cookie_gen) ||
        !cookie_gen_init(gbl_state->cookie_gen+1) ||
        !cookie_gen_init(gbl_state->key_gen) ||
        !cookie_gen_init(gbl_state->key_gen+1))
    {
        return false;
    }
    state->lib->random(state->rng, &gbl_state->seq, sizeof(gbl_state->seq));
    state->lib->random(state->rng, &gbl_state->seq_key,
        sizeof(gbl_state->seq_key));
    state->lib->random(state->rng, &gbl_state->gen_idx,
        sizeof(gbl_state->gen_idx));
    gbl_state->gen_idx %= 2;
    
    // Get the certificate:
    if (!crypt_read_certificate(state))
    {
        return false;
    }

    // Compute MP numbers for future use:
    if (!mp_init)
    {
        mpz_init(p);
        mpz_import(p, sizeof(p0), -1, sizeof(uint8_t), 0, 0, p0);
        // May as well check this:
        assert(mpz_probab_prime_p(p, 10) != 0);
        mpz_init(p1);
        mpz_sub_ui(p1, p, 1);
        mpz_init(g);
        mpz_set_ui(g, CRYPT_DH_GENERATOR);
        mp_init = true;
    }
    state->gbl_state->quota = quota_init(state->lib, CRYPT_QUOTA_RK_TIMEMIN,
        CRYPT_QUOTA_RK_TIMEMAX, CRYPT_QUOTA_RK_NUM_BUCKETS,
        CRYPT_QUOTA_RK_RATE);
    mpz_init(state->gbl_state->mp_certificate);
    mpz_import(state->gbl_state->mp_certificate, sizeof(state->certificate),
        -1, sizeof(uint8_t), 0, 0, state->certificate);
    mpz_init(state->gbl_state->mp_sign_key);
    mpz_import(state->gbl_state->mp_sign_key, sizeof(state->sign_key), -1,
        sizeof(uint8_t), 0, 0, state->sign_key);

    return true;
}

/*
 * Thread that handles timeouts.
 */
static void *crypt_timeout_manager(void *state_ptr)
{
    state_t state = (state_t)state_ptr;

    while (true)
    {
        state->gbl_state->gen_timeout = state->lib->gettime() + CRYPT_TIMEOUT;
        state->lib->sleeptime(CRYPT_TIMEOUT);

        // At this point no client should be using the old state, therefore
        // we can safely just clobber it.
        state->lib->random(state->rng, state->gbl_state->cookie_gen +
            !state->gbl_state->gen_idx, sizeof(struct cookie_gen_s));
        state->lib->random(state->rng, state->gbl_state->key_gen +
            !state->gbl_state->gen_idx,
            sizeof(struct cookie_gen_s));
        state->gbl_state->gen_idx = !state->gbl_state->gen_idx;
    }

    return NULL;
}

/*
 * Read a certificate from the key file.
 */
static bool crypt_read_certificate(state_t state)
{
    FILE *file = fopen(CRYPT_KEYS_FILENAME, "r");
    if (file == NULL)
    {
        return false;
    }

    while (true)
    {
        char c;
        c = getc(file);
        switch (c)
        {
            case EOF:
                fclose(file);
                return false;
            case '\n':
                continue;
            case '#':
                while ((c = getc(file)) != '\n' && c != EOF)
                    ;
                continue;
            default:
                ungetc(c, file);
                break;
        }

        bool cipher_match = true;
        size_t i;
        for (i = 0; (c = getc(file)) != '\t'; i++)
        {
            if (!isalpha(c))
            {
                fclose(file);
                return false;
            }
            if (cipher_match)
            {
                cipher_match = (c == state->cipher->name[i]);
            }
        }
        if (cipher_match && state->cipher->name[i] != '\0')
        {
            cipher_match = false;
        }

        char cert_hash_str[CRYPT_HASH_BASE64_SIZE + 1];
        char cert_str[CRYPT_PUBLIC_KEY_BASE64_SIZE + 1];
        char key_str[CRYPT_PUBLIC_KEY_BASE64_SIZE + 1];

        if (getc(file) != '\t' ||
            fgets(cert_hash_str, sizeof(cert_hash_str), file) == NULL ||
            getc(file) != ' ' ||
            fgets(cert_str, sizeof(cert_str), file) == NULL ||
            getc(file) != ' ' ||
            fgets(key_str, sizeof(key_str), file) == NULL ||
            getc(file) != '\n')
        {
            fclose(file);
            return false;
        }

        if (!cipher_match)
        {
            continue;
        }

        uint8_t cert_hash[CRYPT_HASH_SIZE+1];
        if (state->lib->base64_decode(cert_hash_str, sizeof(cert_hash_str)-1,
                cert_hash) != sizeof(cert_hash))
        {
            fclose(file);
            return false;
        }
        if (memcmp(cert_hash, state->cert_hash, sizeof(state->cert_hash)) == 0)
        {
            uint8_t cert[CRYPT_PUBLIC_KEY_SIZE+1];
            uint8_t sign_key[CRYPT_PUBLIC_KEY_SIZE+1];
            if (state->lib->base64_decode(cert_str, sizeof(cert_str)-1,
                    cert) != sizeof(cert) ||
                state->lib->base64_decode(key_str, sizeof(key_str)-1,
                    sign_key) != sizeof(sign_key))
            {
                fclose(file);
                return false;
            }
            fclose(file);
            memcpy(state->certificate, cert, sizeof(state->certificate));
            memcpy(state->sign_key, sign_key, sizeof(state->sign_key));
            return true;
        }
    }
}

/*
 * Generate the initial handshake cookie.
 */
static uint32_t crypt_cookie(state_t state, uint32_t *source_addr,
    size_t source_size)
{
    struct crypt_global_state_s *gbl_state = state->gbl_state;
    uint32_t cookie = generate_cookie32(gbl_state->cookie_gen +
        gbl_state->gen_idx, source_addr, source_size);
    if (cookie <= CRYPT_ID_MAX_RESERVED)
    {
        cookie += CRYPT_ID_MAX_RESERVED;
    }
    return cookie;
}

/*
 * Generate the secret key from the source address and the session ID.
 */
static void crypt_key(state_t state, uint32_t *source_addr, size_t source_size,
    uint32_t id, uint8_t *key)
{
    uint32_t source_addr_copy[source_size];
    memcpy(source_addr_copy, source_addr, source_size*sizeof(uint32_t));
    source_addr_copy[0] ^= id;
    uint64_t *r0 = (uint64_t *)key;
    uint64_t *r1 = (uint64_t *)(key + sizeof(uint64_t));
    uint8_t gen_idx = (uint64_t)id & CRYPT_GEN_IDX_MASK;
    generate_cookie128(state->gbl_state->key_gen + gen_idx, source_addr_copy,
        source_size, r0, r1);
}

#endif      /* SERVER */

#ifdef TOOL

/*
 * 'TOOL' is for building a tool that generates certificates.
 */

#include <openssl/rsa.h>
#include <sys/file.h>
#include <unistd.h>

#include "base64.h"
#include "cfg.h"

/*
 * Crypt tool usage message.
 */
void usage(void)
{
    fprintf(stderr, "usage: %s_tool (", PROGRAM_NAME);
    bool prev = false;
    for (size_t i = 0; i < sizeof(ciphers) / sizeof(struct cipher_s); i++)
    {
        if (prev)
        {
            fputc('|', stderr);
        }
        prev = true;
        fprintf(stderr, "%s", ciphers[i].name);
    }
    fputs(") (gen|test)\n", stderr);
}

/*
 * Entry point for the crypt tool.
 */
int main(int argc, const char **argv)
{
    printf("%s_tool %s Copyright (C) 2010 basil\n", PROGRAM_NAME,
        PROGRAM_VERSION);
    puts("License GPLv3+: GNU GPL version 3 or later "
        "<http://gnu.org/licenses/gpl.html>.");
    puts("This is free software: you are free to change and redistribute it.");
    puts("There is NO WARRANTY, to the extent permitted by law.");
    putchar('\n');

    // Check arguments:
    if (argc != 3)
    {
        usage();
        return EXIT_FAILURE;
    }
    struct cipher_s *cipher = crypt_cipher_search(argv[1]);
    if (cipher == NULL)
    {
        fprintf(stderr, "error: unknown cipher %s\n", argv[1]);
        usage();
        return EXIT_FAILURE;
    }

    if (strcmp(argv[2], "test") == 0)
    {
        // Cipher test:
        uint8_t plaintext[CRYPT_BLOCK_SIZE];
        uint8_t key[CRYPT_KEY_SIZE];
        srand(time(NULL));
        for (size_t i = 0; i < sizeof(plaintext); i++)
        {
            plaintext[i] = (uint8_t)rand();
        }
        for (size_t i = 0; i < sizeof(key); i++)
        {
            key[i] = (uint8_t)rand();
        }
        uint8_t ekey[cipher->ekeysize];
        cipher->expandkey(key, sizeof(key), ekey);
        uint8_t ciphertext[CRYPT_BLOCK_SIZE];
        cipher->encrypt(plaintext, ekey, ciphertext);
        fputs("plaintext : ", stdout);
        for (size_t i = 0; i < sizeof(plaintext); i++)
        {
            printf("%.2X", plaintext[i]);
        }
        putchar('\n');
        fputs("key       : ", stdout);
        for (size_t i = 0; i < sizeof(key); i++)
        {
            printf("%.2X", key[i]);
        }
        putchar('\n');
        fputs("ciphertext: ", stdout);
        for (size_t i = 0; i < sizeof(ciphertext); i++)
        {
            printf("%.2X", ciphertext[i]);
        }
        putchar('\n');
    }
    else if (strcmp(argv[2], "gen") == 0)
    {
        // Key generation:

        // Change to the server directory:
        if (chdir(PROGRAM_DIR) != 0)
        {
            fprintf(stderr, "error: unable to change to directory \"%s\": "
                "%s\n", PROGRAM_DIR, strerror(errno));
            return EXIT_FAILURE;
        }

        // Generate the RSA public/private keys:
        RSA *rsa = RSA_generate_key(1024, CRYPT_RSA_EXPONENT, NULL, NULL);
        if (!RSA_check_key(rsa))
        {
            fprintf(stderr, "error: unable to verify generated RSA "
                "parameters\n");
            return EXIT_FAILURE;
        }
        uint8_t certificate[CRYPT_PUBLIC_KEY_SIZE];
        uint8_t sign_key[CRYPT_PUBLIC_KEY_SIZE];
        if (rsa == NULL ||
            BN_bn2bin(rsa->n, certificate) == 0 ||
            BN_bn2bin(rsa->d, sign_key) == 0)
        {
            fprintf(stderr, "error: unable to create RSA big numbers: %s\n",
                strerror(ENOMEM));
            return EXIT_FAILURE;
        }
        RSA_free(rsa);

        // Correct endianess
        for (size_t i = 0; i < CRYPT_PUBLIC_KEY_SIZE / 2; i++)
        {
            uint8_t tmp;
            tmp = certificate[sizeof(certificate)-i-1];
            certificate[sizeof(certificate)-i-1] = certificate[i];
            certificate[i] = tmp;

            tmp = sign_key[sizeof(sign_key)-i-1];
            sign_key[sizeof(sign_key)-i-1] = sign_key[i];
            sign_key[i] = tmp;
        }
        
        // Generate the certificate's hash value:
        uint8_t cert_hash[CRYPT_HASH_SIZE];
        hash(cipher, certificate, sizeof(certificate), cert_hash);

        // Write the certificate:
        char cert_hash_str[CRYPT_HASH_BASE64_SIZE + 1];
        size_t end = base64_encode(cert_hash, sizeof(cert_hash),
            cert_hash_str);
        cert_hash_str[end] = '\0';

        char cert_str[CRYPT_PUBLIC_KEY_BASE64_SIZE + 1];
        end = base64_encode(certificate, sizeof(certificate), cert_str);
        cert_str[end] = '\0';

        char key_str[CRYPT_PUBLIC_KEY_BASE64_SIZE + 1];
        end = base64_encode(sign_key, sizeof(sign_key), key_str);
        key_str[end] = '\0';

        FILE *file = fopen(CRYPT_KEYS_FILENAME, "a");
        if (file == NULL)
        {
            fprintf(stderr, "error: unable to open file \"%s\" for appending: "
                "%s\n", CRYPT_KEYS_FILENAME, strerror(errno));
            return EXIT_FAILURE;
        }
        flock(fileno(file), LOCK_EX);
        fprintf(file, "%s\t\t%s %s %s\n", cipher->name, cert_hash_str, cert_str,
            key_str);
        fflush(file);
        flock(fileno(file), LOCK_UN);
        fclose(file);

        // Print the results:
        if (!isatty(fileno(stdout)))
        {
            printf("crypt=cipher.%s,cert.%s\n", cipher->name, cert_hash_str);
        }
        else
        {
            printf("\33[33mcrypt=cipher.%s,cert.%s\33[0m\n", cipher->name,
                cert_hash_str);
        }
    }
    else
    {
        fprintf(stderr, "error: unknown command %s\n", argv[2]);
        usage();
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

#endif      /* TOOL */

/*****************************************************************************/

/*
 * Block initialiser.
 */
static size_t block_init(uint8_t *block, const uint8_t *iv, size_t ivsize,
    uint32_t seq)
{
    // Copy IV
    size_t i = 0;
    for (; i < ivsize; i++)
    {
        block[i] = iv[i];
    }

    // Copy sequence number
    uint8_t *seq_ptr = (uint8_t *)&seq;
    for (size_t j = 0; j < sizeof(uint32_t); i++, j++)
    {
        block[i] = seq_ptr[j];
    }

    // Padding
    for (; i < CRYPT_BLOCK_SIZE; i++)
    {
        block[i] = 0x0;
    }

    return CRYPT_BLOCK_SIZE - sizeof(uint16_t);
}

/*
 * Encrypt using the given cipher and return the MAC.
 */
static uint64_t encrypt(const struct cipher_s *cipher, const uint8_t *iv,
    size_t ivsize, uint32_t seq, const uint8_t *ekey, uint8_t *data,
    size_t datasize)
{
    uint8_t block[CRYPT_BLOCK_SIZE];
    size_t counter_offset = block_init(block, iv, ivsize, seq);
    uint8_t result[CRYPT_BLOCK_SIZE];

    uint8_t mac_block[CRYPT_BLOCK_SIZE];
    block_init(mac_block, iv, ivsize, seq);

    // Prepend the length for MAC length strengthening:
    size_t m = 0;
    uint16_t datasize16 = (uint16_t)datasize;
    for (; m < sizeof(uint16_t); m++)
    {
        mac_block[m] ^= (uint8_t)datasize16;
        datasize16 >>= 8;
    }

    // Encrypt the data and compute the MAC:
    for (size_t i = 0, j = 0; i < datasize; i++)
    {
        if (j == 0)
        {
            cipher->encrypt(block, ekey, result);
            (*(uint16_t *)(block + counter_offset))++;
            j = CRYPT_BLOCK_SIZE;
        }
        j--;
        mac_block[m++] ^= data[i];
        data[i] ^= result[j];
        if (m == CRYPT_BLOCK_SIZE)
        {
            cipher->encrypt(mac_block, ekey, mac_block);
            m = 0;
        }
    }
    if (m != 0)
    {
        cipher->encrypt(mac_block, ekey, mac_block);
    }

    // Return the 64-bit MAC:
    uint64_t *mac_block64 = (uint64_t *)mac_block;
    return *mac_block64;
}

/*
 * Decrypt using the given cipher and return the MAC.
 */
static uint64_t decrypt(const struct cipher_s *cipher, const uint8_t *iv,
    size_t ivsize, uint32_t seq, const uint8_t *ekey, uint8_t *data,
    size_t datasize)
{
    uint8_t block[CRYPT_BLOCK_SIZE];
    size_t counter_offset = block_init(block, iv, ivsize, seq);
    uint8_t result[CRYPT_BLOCK_SIZE];

    uint8_t mac_block[CRYPT_BLOCK_SIZE];
    block_init(mac_block, iv, ivsize, seq);

    // Prepend the length for MAC length strengthening:
    size_t m = 0;
    uint16_t datasize16 = (uint16_t)datasize;
    for (; m < sizeof(uint16_t); m++)
    {
        mac_block[m] ^= (uint8_t)datasize16;
        datasize16 >>= 8;
    }

    // Decrypt the data and compute the MAC:
    for (size_t i = 0, j = 0; i < datasize; i++)
    {
        if (j == 0)
        {
            cipher->encrypt(block, ekey, result);
            (*(uint16_t *)(block + counter_offset))++;
            j = CRYPT_BLOCK_SIZE;
        }
        j--;
        data[i] ^= result[j];
        mac_block[m++] ^= data[i];
        if (m == CRYPT_BLOCK_SIZE)
        {
            cipher->encrypt(mac_block, ekey, mac_block);
            m = 0;
        }
    }
    if (m != 0)
    {
        cipher->encrypt(mac_block, ekey, mac_block);
    }

    // Return the 64-bit MAC:
    uint64_t *mac_block64 = (uint64_t *)mac_block;
    return *mac_block64;
}

/*
 * Encrypt/decrypt only, no MAC.
 */
static void crypt(const struct cipher_s *cipher, const uint8_t *iv,
    size_t ivsize, const uint8_t *key, uint8_t *data, size_t datasize)
{
    uint8_t ekey[cipher->ekeysize];
    cipher->expandkey(key, CRYPT_KEY_SIZE, ekey);

    uint8_t block[CRYPT_BLOCK_SIZE];
    size_t counter_offset = block_init(block, iv, ivsize, CRYPT_HEADER_SEQ);
    uint8_t result[CRYPT_BLOCK_SIZE];
    
    // Encrypt the data and compute the MAC:
    for (size_t i = 0, j = 0; i < datasize; i++)
    {
        if (j == 0)
        {
            cipher->encrypt(block, ekey, result);
            (*(uint16_t *)(block + counter_offset))++;
            j = CRYPT_BLOCK_SIZE;
        }
        j--;
        data[i] ^= result[j];
    }
}

/*
 * Hash using the given cipher (Davies-Meyer construction + Merkle-Damgard
 * strengthening).
 */
static void hash(const struct cipher_s *cipher, uint8_t *data, size_t datasize,
    uint8_t *hashval)
{
    uint8_t block[CRYPT_BLOCK_SIZE];
    memcpy(block, p0 + sizeof(uint64_t), CRYPT_HASH_SIZE);

    // Hash message:
    uint8_t ekey[cipher->ekeysize];
    uint8_t block_copy[CRYPT_BLOCK_SIZE];
    for (size_t i = 0; i < datasize; i += CRYPT_HASH_SIZE)
    {
        cipher->expandkey(data,
            (i + CRYPT_HASH_SIZE > datasize? datasize - i: CRYPT_HASH_SIZE),
            ekey);
        memcpy(block_copy, block, sizeof(block));
        cipher->encrypt(block, ekey, block);
        for (size_t j = 0; j < CRYPT_BLOCK_SIZE; j++)
        {
            block[j] ^= block_copy[j];
        }
    }

    // Hash length:
    cipher->expandkey(&datasize, sizeof(datasize), ekey);
    memcpy(hashval, block, sizeof(block));
    cipher->encrypt(block, ekey, block);
    for (size_t i = 0; i < CRYPT_BLOCK_SIZE; i++)
    {
        hashval[i] ^= block[i];
    }
}

/*****************************************************************************/

#define XXTEA_ROUNDS    19
#define XXTEA_DELTA     0x9E3779B9
#define XXTEA_MIX(i, y, z, sum, k, e)                                   \
    (((z) >> 5 ^ (y) << 2) + ((y) >> 3 ^ (z) << 4)) ^ (((sum) ^ (y)) +  \
        ((k)[((i) & 0x03) ^ (e)] ^ (z)))

/*
 * XXTEA expand key.
 */
static void xxtea_expandkey(const uint8_t *key, size_t keysize, uint8_t *ekey)
{
    size_t i = 0;
    for (; i < 16 && i < keysize; i++)
    {
        ekey[i] = key[i];
    }
    for (; i < 16; i++)
    {
        ekey[i] = 0x0;
    }
}

/*
 * XXTEA encryption.
 * NOTE: This version uses a fixed block size of 128 bits.
 */
static void xxtea_encrypt(const uint32_t *v, const uint32_t *k, uint32_t *r)
{
    register uint32_t v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3];
    register uint32_t sum = 0, e;
    for (unsigned i = 0; i < XXTEA_ROUNDS; i++)
    {
        sum += XXTEA_DELTA;
        e = (sum >> 2) & 0x03;
        v0 += XXTEA_MIX(0, v1, v3, sum, k, e);
        v1 += XXTEA_MIX(1, v2, v0, sum, k, e);
        v2 += XXTEA_MIX(2, v3, v1, sum, k, e);
        v3 += XXTEA_MIX(3, v0, v2, sum, k, e);
    }
    r[0] = v0;
    r[1] = v1;
    r[2] = v2;
    r[3] = v3;
}

