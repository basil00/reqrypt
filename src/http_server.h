/*
 * http_server.h
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
#ifndef __HTTP_SERVER_H
#define __HTTP_SERVER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * Key value pair for looking up enum values.
 */
struct http_pair_s
{
    const char *key;
    unsigned    val;
};
int http_pair_s_compare(const void *a, const void *b);

/*
 * Representation of the user key/value pair.
 */
struct http_user_var_s
{
    const char *var;
    const char *val;
};

/*
 * Representation of a set of user key/value pairs.
 */
#define MAX_USER_VARS   64
struct http_user_vars_s
{
    size_t size;
    bool   sorted;
    struct http_user_var_s vars[MAX_USER_VARS];
};

/*
 * A HTTP buffer.
 */
struct http_buffer_s
{
    bool    dynamic;
    size_t  get_pos;
    size_t  put_pos;
    size_t  size;
    char   *buff;
};
typedef struct http_buffer_s *http_buffer_t;

/*
 * Callbacks for program generated content.
 */
typedef bool (*http_callback_func_t)(http_buffer_t buff);
void http_register_callback(const char *name, http_callback_func_t func);

/*
 * Launch a http server that listens on the given port.
 */
void http_server(uint16_t port, void (*callback)(struct http_user_vars_s *));

/*
 * Helper functions for user vars.
 */
void http_user_vars_init(struct http_user_vars_s *vars);
void http_user_vars_free(struct http_user_vars_s *vars);
const char *http_user_var_lookup(const struct http_user_vars_s *vars,
    const char *var);
void http_user_var_insert(struct http_user_vars_s *vars, const char *var,
    const char *val);
bool http_get_string_var(const struct http_user_vars_s *vars,
    const char *var, const char **sval);
bool http_get_bool_var(const struct http_user_vars_s *vars,
    const char *var, bool *bval);
bool http_get_int_var(const struct http_user_vars_s *vars,
    const char *var, unsigned min, unsigned max, size_t size, void *ival);
bool http_get_enum_var(const struct http_user_vars_s *vars,
    const char *var, struct http_pair_s *def, size_t def_len, uint8_t *ival);

/*
 * Helper functions for buffer type.
 */
http_buffer_t http_buffer_open(void);
void http_buffer_close(http_buffer_t buff);
void http_buffer_putc(http_buffer_t buff, char c);
void http_buffer_puts(http_buffer_t buff, const char *s);
char http_buffer_getc(http_buffer_t buff);

#endif      /* __HTTP_SERVER_H */
