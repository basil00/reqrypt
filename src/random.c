/*
 * random.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfg.h"
#include "log.h"
#include "misc.h"
#include "random.h"
#include "thread.h"

struct random_state_s
{
    uint32_t v[4];              // Plain text
    uint32_t k[4];              // Key
    uint32_t r[4];              // Seed
    uint32_t e[4];              // Cipher text
    size_t e_idx;               // Next byte
};

/*
 * Prototypes.
 */
static void generate_random(random_state_t state);

/*
 * Initialise the random number generator.
 */
random_state_t random_init(void)
{
    random_state_t state = (random_state_t)malloc(
        sizeof(struct random_state_s));
    if (state == NULL)
    {
        error("unable to allocate " SIZE_T_FMT " bytes for random state",
            sizeof(struct random_state_s));
        exit(EXIT_FAILURE);     // For server.
    }

    state->e_idx = sizeof(state->e);
    uint8_t buff[sizeof(state->v) + sizeof(state->k) + sizeof(state->r)];
    random_ext_init(buff, sizeof(buff));
    memmove(state->v, buff, sizeof(state->v));
    memmove(state->k, buff + sizeof(state->v), sizeof(state->k));
    memmove(state->r, buff + sizeof(state->v) + sizeof(state->k),
        sizeof(state->r));
    return state;
}

/*
 * Free the random number generator.
 */
void random_free(random_state_t state)
{
    free(state);
}

/*
 * Generic random functions:
 */
uint8_t random_uint8(random_state_t state)
{
    uint8_t r;
    random_memory(state, &r, sizeof(r));
    return r;
}
uint16_t random_uint16(random_state_t state)
{
    uint16_t r;
    random_memory(state, &r, sizeof(r));
    return r;
}
uint32_t random_uint32(random_state_t state)
{
    uint32_t r;
    random_memory(state, &r, sizeof(r));
    return r;
}
uint64_t random_uint64(random_state_t state)
{
    uint64_t r;
    random_memory(state, &r, sizeof(r));
    return r;
}

/*
 * Cryptographically secure random number generator.
 */
void random_memory(random_state_t state, void *ptr0, size_t size)
{
    uint8_t *ptr = (uint8_t *)ptr0;
    uint8_t *e8 = (uint8_t *)state->e;

    while (size != 0)
    {
        if (state->e_idx >= sizeof(state->e))
        {
            generate_random(state);
            state->e_idx = 0;
        }
        *(ptr++) = e8[state->e_idx++];
        size--;
    }
}

/*
 * Generate more random bytes based on the XXTEA algorithm.
 */
#define RANDOM_ROUNDS               19
#define RANDOM_DELTA                0x9E3779B9
#define RANDOM_MIX(i, y, z, sum, k, e)                                  \
    (((z) >> 5 ^ (y) << 2) + ((y) >> 3 ^ (z) << 4)) ^ (((sum) ^ (y)) +  \
        ((k)[((i) & 0x03) ^ (e)] ^ (z)))
static void generate_random(random_state_t state)
{
    // Next value:
    state->v[0]++;
    if (state->v[0] == 0)
    {
        state->v[1]--;
    }

    // Encrypt the value:
    register uint32_t v0 = state->v[0], v1 = state->v[1], v2 = state->v[2],
        v3 = state->v[3];
    register uint32_t sum = 0, e;
    for (unsigned i = 0; i < RANDOM_ROUNDS; i++)
    {
        sum += RANDOM_DELTA;
        e = (sum >> 2) & 0x03;
        v0 += RANDOM_MIX(0, v1, v3, sum, state->k, e);
        v1 += RANDOM_MIX(1, v2, v0, sum, state->k, e);
        v2 += RANDOM_MIX(2, v3, v1, sum, state->k, e);
        v3 += RANDOM_MIX(3, v0, v2, sum, state->k, e);
    }

    // Write out encrypted data & xor with seed:
    state->e[0] = v0 ^ state->r[0];
    state->e[1] = v1 ^ state->r[1];
    state->e[2] = v2 ^ state->r[2];
    state->e[3] = v3 ^ state->r[3];
}

/****************************************************************************/

struct rand_state_s
{
    uint32_t z;
    uint32_t w;
    uint32_t e;
    size_t e_idx;
};

/*
 * Prototypes.
 */
static void generate_rand(rand_state_t state);

/*
 * Initialise the random number generator.
 */
rand_state_t rand_init(uint64_t seed)
{
    rand_state_t state = (rand_state_t)malloc(sizeof(struct rand_state_s));
    if (state == NULL)
    {
        error("unable to allocate " SIZE_T_FMT " bytes for random state",
            sizeof(struct rand_state_s));
        exit(EXIT_FAILURE);     // For server.
    }

    state->e_idx = sizeof(state->e);
    state->z = (uint32_t)seed;
    state->z = (state->z == 0? ~state->z: state->z);
    seed >>= 32;
    state->w = (uint32_t)seed;
    state->w = (state->w == 0? ~state->w: state->w);
    return state;
}

/*
 * Free the random number generator.
 */
void rand_free(rand_state_t state)
{
    free(state);
}

/*
 * Generic random functions:
 */
uint8_t rand_uint8(rand_state_t state)
{
    uint8_t r;
    rand_memory(state, &r, sizeof(r));
    return r;
}
uint16_t rand_uint16(rand_state_t state)
{
    uint16_t r;
    rand_memory(state, &r, sizeof(r));
    return r;
}
uint32_t rand_uint32(rand_state_t state)
{
    uint32_t r;
    rand_memory(state, &r, sizeof(r));
    return r;
}
uint64_t rand_uint64(rand_state_t state)
{
    uint64_t r;
    rand_memory(state, &r, sizeof(r));
    return r;
}

/*
 * Fast random number generator.
 */
void rand_memory(rand_state_t state, void *ptr0, size_t size)
{
    uint8_t *ptr = (uint8_t *)ptr0;
    uint8_t *e8 = (uint8_t *)&state->e;

    while (size != 0)
    {
        if (state->e_idx >= sizeof(state->e))
        {
            generate_rand(state);
            state->e_idx = 0;
        }
        *(ptr++) = e8[state->e_idx++];
        size--;
    }
}

/*
 * Generate more random bytes based on the Multiply-with-carry method.
 */
static void generate_rand(rand_state_t state)
{
    state->z = 36969 * (state->z & 0xFFFF) + (state->z >> 16);
    state->w = 18000 * (state->w & 0xFFFF) + (state->w >> 16);
    state->e = (state->z << 16) + state->w;
}

