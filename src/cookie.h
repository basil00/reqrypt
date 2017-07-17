/*
 * cookie.h
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

#ifndef __COOKIE_H
#define __COOKIE_H

/*
 * Note: this module is fully defined in this header file.  This is for:
 * - speed, and
 * - use in encodings
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Cookie generator parameters.
 */
struct cookie_gen_s
{
    uint32_t v[4];
    uint32_t k[4];
    uint32_t r[4];
};

typedef struct cookie_gen_s *cookie_gen_t;

/*
 * Initialise a cookie_gen_t.
 */
static inline bool cookie_gen_init(cookie_gen_t gen)
{
    const char *rand_dev = "/dev/urandom";
    FILE *rand = fopen(rand_dev, "r");
    if (rand == NULL)
    {
        return false;
    }
    if (fread(gen, sizeof(struct cookie_gen_s), 1, rand) != 1)
    {
        fclose(rand);
        return false;
    }
    fclose(rand);
    return true;
}

/*
 * Generate a cookie based on the given data.
 * The algorithm is based on reduced-round XXTEA.
 */
#define COOKIE_ROUNDS               10          // Reduced from 19
#define COOKIE_DELTA                0x9E3779B9
#define COOKIE_MIX(i, y, z, sum, k, e)                                  \
    (((z) >> 5 ^ (y) << 2) + ((y) >> 3 ^ (z) << 4)) ^ (((sum) ^ (y)) +  \
        ((k)[((i) & 0x03) ^ (e)] ^ (z)));

static inline void generate_cookie128(cookie_gen_t gen, uint32_t *data,
    size_t size, uint64_t *r0, uint64_t *r1)
{
    register uint32_t v0 = gen->v[0], v1 = gen->v[1], v2 = gen->v[2],
        v3 = gen->v[3];
    switch (size)
    {
        case 4:
            v3 ^= data[3];
        case 3:
            v2 ^= data[2];
        case 2:
            v3 ^= data[1];
        case 1:
            v1 ^= data[0];
    }
    register uint32_t sum = 0, e;
    for (unsigned i = 0; i < COOKIE_ROUNDS; i++)
    {
        sum += COOKIE_DELTA;
        e = (sum >> 2) & 0x03;
        v0 += COOKIE_MIX(0, v1, v3, sum, gen->k, e);
        v1 += COOKIE_MIX(1, v2, v0, sum, gen->k, e);
        v2 += COOKIE_MIX(2, v3, v1, sum, gen->k, e);
        v3 += COOKIE_MIX(3, v0, v2, sum, gen->k, e);
    }

    v0 ^= gen->r[0];
    v1 ^= gen->r[1];
    v2 ^= gen->r[2];
    v3 ^= gen->r[3];

    *r0 = (((uint64_t)v0) << 32) | v1;
    *r1 = (((uint64_t)v2) << 32) | v3;
}

/*
 * 64-bit version.
 */
static inline uint64_t generate_cookie64(cookie_gen_t gen, uint32_t *data,
    size_t size)
{
    uint64_t r0, r1;
    generate_cookie128(gen, data, size, &r0, &r1);
    return r0 ^ r1;
}

/*
 * 32-bit version.
 */
static inline uint32_t generate_cookie32(cookie_gen_t gen, uint32_t *data,
    size_t size)
{
    uint64_t r0 = generate_cookie64(gen, data, size);
    return ((uint32_t)(r0 >> 32)) ^ (uint32_t)r0;
}

/*
 * 16-bit version.
 */
static inline uint16_t generate_cookie16(cookie_gen_t gen, uint32_t *data,
    size_t size)
{
    uint32_t r0 = generate_cookie64(gen, data, size);
    return ((uint16_t)(r0 >> 16)) ^ (uint16_t)r0;
}

#endif      /* __COOKIE_H */
