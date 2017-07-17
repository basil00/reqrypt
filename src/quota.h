/*
 * quota.h
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

#ifndef __QUOTA_H
#define __QUOTA_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "cktp_encoding.h"

typedef struct quota_s *quota_t;

/*
 * Prototypes.
 */
quota_t quota_init(cktp_enc_lib_t lib, uint32_t timemin, uint32_t timemax,
    uint16_t numcounts, uint32_t rps);
void quota_free(quota_t quota);
bool quota_check(quota_t quota, cktp_enc_lib_t lib, random_state_t rng,
    uint32_t *ip, size_t ipsize);

#endif      /* __QUOTA_H */
