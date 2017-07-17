/*
 * server_table.h
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

#ifndef __SERVER_TABLE_H
#define __SERVER_TABLE_H

#include <stdbool.h>
#include <unistd.h>

#include "cfg.h"

#define SERVER_TABLE_FILENAME       PACKAGE_NAME ".tab"

#define SERVER_DEAD                 ((pid_t)(-1))
#define SERVER_SUSPENDED            ((pid_t)(-2))

/*
 * Server table entry: 
 */
struct server_entry_s
{
    pid_t                  pid;     // PID of server process
    char                  *url;     // URL of server
    struct server_entry_s *next;    // Next server or NULL
};
typedef struct server_entry_s *server_entry_t;

/*
 * Prototypes.
 */
void server_table_free(server_entry_t table);
void server_table_insert(server_entry_t *table_ptr, pid_t pid,
    const char *url);
pid_t server_table_delete(server_entry_t *table_ptr, const char *url);
server_entry_t server_table_read(void);
bool server_table_write(server_entry_t table);

#endif      /* __SERVER_TABLE_H */
