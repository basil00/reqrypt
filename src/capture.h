/*
 * capture.h
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

#ifndef __CAPTURE_H
#define __CAPTURE_H

#include <stdint.h>
#include <stdlib.h>

/*
 * Prototypes.
 */
void init_capture(void);
size_t get_packet(uint8_t *buff, size_t size);
void inject_packet(uint8_t *buff, size_t size);

#endif      /* __CAPTURE_H */
