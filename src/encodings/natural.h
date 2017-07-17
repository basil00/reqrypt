/*
 * natural.h
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
#ifndef __NATURAL_H
#define __NATURAL_H

#include <stdint.h>

/*
 * (Big) natural number type.
 */
typedef uint64_t    N;
typedef N*          N_t;

/*
 * Number of N digits in a 'normal' N_t.
 */
#define N_SIZE      19

/*
 * Prototypes.
 */
void N_set(const uint8_t *data, size_t size, N_t a);
void N_get(uint8_t *data, size_t size, N_t a);
void N_modexp(N_t b, N_t e, N_t m, N_t r);
bool N_lt2(N_t a, N_t b);
bool N_neq1(N_t a);

#endif      /* __NATURAL_H */
