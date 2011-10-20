/*
 * base64.h
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

#ifndef __BASE64_H
#define __BASE64_H

#include <stdint.h>
#include <stdlib.h>

/*
 * Prototypes.
 */
size_t base64_encode(const uint8_t *in, size_t insize, char *out);
size_t base64_decode(const char *in, size_t insize, uint8_t *out);

#endif      /* __BASE64_H */
