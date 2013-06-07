/*
 * aes_hardware.c
 * (C) 2011, all rights reserved,
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
 * AES hardware accelerated encryption.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "aes_hardware.h"

/*
 * Beautification.
 */
typedef long long int int128_t __attribute__ ((vector_size (16)));

#define aes_enc                     __builtin_ia32_aesenc128
#define aes_enc_last                __builtin_ia32_aesenclast128
#define aes_keygen_assist           __builtin_ia32_aeskeygenassist128

#define bshuffle                    __builtin_ia32_pshufd
#define lshift4(a, b)               \
    __builtin_ia32_pslldqi128((a), (b) * 8)

#define cpuid(f, ax, bx, cx, dx)    \
    __asm__ __volatile__ ("cpuid" : "=a" (ax), "=b" (bx), "=c" (cx), \
        "=d" (dx) : "a" (f))

/*
 * Prototypes.
 */
static int128_t aes_expandkey_assist(int128_t a, int128_t b);

/*
 * AES hardware test.
 */
extern bool aes_hardware_test(void)
{
    unsigned a, b, c, d;
    cpuid(1, a, b, c, d);
    return ((c & 0x02000000) != 0);
}

/*
 * AES key expansion assist.
 */
static int128_t aes_expandkey_assist(int128_t a, int128_t b)
{
    b = bshuffle(b, 0xFF);
    int128_t c = lshift4(a, 4);
    a = c ^ a;
    c = lshift4(a, 4);
    a = c ^ a;
    c = lshift4(a, 4);
    return c ^ a ^ b;
}

/*
 * AES key expansion.
 */
extern void aes_hardware_expandkey(const uint8_t *key0, size_t keysize,
    uint8_t *ekey0)
{
    // Warning: key0 need not be aligned, gcc will assume it is.
    size_t i;
    for (i = 0; i < keysize; i++)
    {
        ekey0[i] = key0[i];
    }
    for (; i < 16; i++)
    {
        ekey0[i] = 0x0;
    }

    int128_t *ekey = (int128_t *)ekey0;
    int128_t key = ekey[0];
    ekey[1]  = key = aes_expandkey_assist(key, aes_keygen_assist(key, 0x1));
    ekey[2]  = key = aes_expandkey_assist(key, aes_keygen_assist(key, 0x2));
    ekey[3]  = key = aes_expandkey_assist(key, aes_keygen_assist(key, 0x4));
    ekey[4]  = key = aes_expandkey_assist(key, aes_keygen_assist(key, 0x8));
    ekey[5]  = key = aes_expandkey_assist(key, aes_keygen_assist(key, 0x10));
    ekey[6]  = key = aes_expandkey_assist(key, aes_keygen_assist(key, 0x20));
    ekey[7]  = key = aes_expandkey_assist(key, aes_keygen_assist(key, 0x40));
    ekey[8]  = key = aes_expandkey_assist(key, aes_keygen_assist(key, 0x80));
    ekey[9]  = key = aes_expandkey_assist(key, aes_keygen_assist(key, 0x1B));
    ekey[10] = key = aes_expandkey_assist(key, aes_keygen_assist(key, 0x36));
}

/*
 * AES encryption.
 */
extern void aes_hardware_encrypt(const uint8_t *v0, const uint32_t *rk0,
    uint8_t *o)
{
    const int128_t *rk = (const int128_t *)rk0;
    int128_t v = *(int128_t *)v0;

    v ^= rk[0];
    v = aes_enc(v, rk[1]);
    v = aes_enc(v, rk[2]);
    v = aes_enc(v, rk[3]);
    v = aes_enc(v, rk[4]);
    v = aes_enc(v, rk[5]);
    v = aes_enc(v, rk[6]);
    v = aes_enc(v, rk[7]);
    v = aes_enc(v, rk[8]);
    v = aes_enc(v, rk[9]);
    v = aes_enc_last(v, rk[10]);

    *(int128_t *)o = v;
}

