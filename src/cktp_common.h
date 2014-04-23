/*
 * cktp_common.h
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

#ifndef __CKTP_COMMON_H
#define __CKTP_COMMON_H

#include <stdint.h>

/*
 * Prototypes.
 */
uint16_t cktp_calculate_checksum(uint8_t *data, uint16_t length);
const char *cktp_error_to_string(uint8_t err);

#define cktp_checksum(message, length)                                        \
    cktp_calculate_checksum((uint8_t *)(&((message)->checksum) + 1),          \
        (length) - ((uint8_t *)(&((message)->checksum) + 1) -                 \
        (uint8_t *)(message)))

#endif      /* __CKTP_COMMON_H */
