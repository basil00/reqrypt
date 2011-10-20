/*
 * misc.h
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

#ifndef __MISC_H
#define __MISC_H

/*
 * Misc. system specific functions.
 */

#include <stdint.h>

#define SECONDS                     1000000L
#define MILLISECONDS                1000L
#define MICROSECONDS                1L

void random_ext_init(uint8_t *ptr, size_t size);
void chdir_home(void);
void launch_ui(uint16_t port);
uint64_t gettime(void);
void sleeptime(uint64_t us);
void quit(int status) __attribute__((noreturn));

#ifndef WINDOWS
#define BROWSER_FILENAME            PROGRAM_NAME ".browser.sh"
#endif

#endif      /* __MISC_H */
