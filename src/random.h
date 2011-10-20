/*
 * random.h
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

#ifndef __RANDOM_H
#define __RANDOM_H

#include <stdint.h>
#include <stdlib.h>

typedef struct random_state_s *random_state_t;
typedef struct rand_state_s   *rand_state_t;

/*
 * Cryptographically secure:
 */
random_state_t random_init(void);
void random_free(random_state_t state);
uint8_t random_uint8(random_state_t state);
uint16_t random_uint16(random_state_t state);
uint32_t random_uint32(random_state_t state);
uint64_t random_uint64(random_state_t state);
void random_memory(random_state_t state, void *ptr, size_t size);

/*
 * Faster but insecure:
 */
rand_state_t rand_init(uint64_t seed);
void rand_free(rand_state_t state);
uint8_t rand_uint8(rand_state_t state);
uint16_t rand_uint16(rand_state_t state);
uint32_t rand_uint32(rand_state_t state);
uint64_t rand_uint64(rand_state_t state);
void rand_memory(rand_state_t state, void *ptr, size_t size);

#endif      /* __RANDOM_H */
