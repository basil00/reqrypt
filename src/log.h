/*
 * log.h
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
#ifndef __LOG_H
#define __LOG_H

#include <stdbool.h>
#include <stdlib.h>

#include "http_server.h"

/*
 * Global flag indicates current log level.
 */
extern int __log_level;

/*
 * Log message types.
 */
#define LOG_MESSAGE_ERROR       ((int8_t)-1)
#define LOG_MESSAGE_WARNING     ((int8_t)-2)
#define LOG_MESSAGE_PANIC       ((int8_t)-3)
#define LOG_MESSAGE_NONE        ((int8_t)0)
#define LOG_MESSAGE_INFO        ((int8_t)1)
#define LOG_MESSAGE_PACKET      ((int8_t)2)
#define LOG_MESSAGE_TRACE       ((int8_t)3)

/*
 * Prototypes.
 */
void log_init(void);
void log_message(int8_t type, const char *message, ...)
    __attribute__ ((format (printf, 2, 3)));
bool log_html_message(http_buffer_t buff);

#define log_get_level()                                                 \
    (__log_level)
#define log_set_level(level)                                            \
    do {                                                                \
        __log_level = (level);                                          \
    } while (false)

#define make_string(s)        make_string_2(s)
#define make_string_2(s)      #s

#define error(message, ...)                                             \
    do {                                                                \
        log_message(LOG_MESSAGE_ERROR, message, ## __VA_ARGS__);        \
        exit(EXIT_FAILURE);                                             \
    } while (false)
#define warning(message, ...)                                           \
    do {                                                                \
        log_message(LOG_MESSAGE_WARNING, message, ## __VA_ARGS__);      \
    } while (false)
#define panic(message, ...)                                             \
    do {                                                                \
        log_message(LOG_MESSAGE_PANIC, __FILE__ ": "                    \
            make_string(__LINE__) ": " message, ## __VA_ARGS__);        \
        exit(EXIT_FAILURE);                                             \
    } while (false)
#define log(message, ...)                                               \
    do {                                                                \
        if (LOG_MESSAGE_INFO <= __log_level)                            \
            log_message(LOG_MESSAGE_INFO, message, ## __VA_ARGS__);     \
    } while (false)
#define packet(message, ...)                                            \
    do {                                                                \
        if (LOG_MESSAGE_PACKET <= __log_level)                          \
            log_message(LOG_MESSAGE_PACKET, message, ## __VA_ARGS__);   \
    } while (false)
#define trace(message, ...)                                             \
    do {                                                                \
        if (LOG_MESSAGE_TRACE <= __log_level)                           \
            log_message(LOG_MESSAGE_TRACE, message, ## __VA_ARGS__);    \
    } while (false)
#define log_enabled(level)                                              \
    ((level) <= __log_level)

#endif      /* __LOG_H */
