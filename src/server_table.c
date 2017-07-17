/*
 * server_table.c
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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

#include "cktp.h"
#include "server_table.h"

#define SERVER_TABLE_MAX_ENTRIES    4096
#define EXE_PATH_BUFF_SIZE          128

/*
 * Prototypes.
 */
static bool verify_pid(pid_t pid);
static void server_entry_print(FILE *file, pid_t pid, const char *url);
extern void error(const char *message, ...);

/*
 * Free a server table.
 */
void server_table_free(server_entry_t table)
{
    while (table != NULL)
    {
        server_entry_t old_table = table;
        table = table->next;
        free(old_table->url);
        free(old_table);
    }
}

/*
 * Insert an entry
 */
void server_table_insert(server_entry_t *table_ptr, pid_t pid, const char *url)
{
    server_entry_t entry = (server_entry_t)malloc(
        sizeof(struct server_entry_s));
    if (entry == NULL)
    {
        error("unable to allocate %zu bytes for server table entry",
            sizeof(struct server_entry_s));
        exit(EXIT_FAILURE);
    }
    entry->pid = pid;
    entry->url = strdup(url);
    if (entry->url == NULL)
    {
        error("unable to allocate %zu bytes for server table entry URL",
            strlen(url));
        exit(EXIT_FAILURE);
    }
    entry->next = *table_ptr;
    *table_ptr = entry;
}

/*
 * Delete an entry
 */
pid_t server_table_delete(server_entry_t *table_ptr, const char *url)
{
    server_entry_t table = *table_ptr, prev = NULL;
    while (table != NULL)
    {
        if (strcmp(table->url, url) == 0)
        {
            if (prev == NULL)
            {
                *table_ptr = table->next;
            }
            else
            {
                prev->next = table->next;
            }
            pid_t pid = table->pid;
            free(table->url);
            free(table);
            return pid;
        }
        prev = table;
        table = table->next;
    }

    return SERVER_DEAD;
}

/*
 * Read a server table.
 */
server_entry_t server_table_read(void)
{
    const char *filename = SERVER_TABLE_FILENAME;
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        if (errno != ENOENT)
        {
            error("unable to open server table file \"%s\" for reading",
                filename);
        }
        return NULL;
    }

    server_entry_t table = NULL;
    flock(fileno(file), LOCK_SH);
    for (size_t i = 0; i < SERVER_TABLE_MAX_ENTRIES; i++)
    {
        char c = getc(file);
        switch (c)
        {
            case EOF:
                if (feof(file))
                {
                    goto server_table_read_exit;
                }
                error("unable to read server table entry from file \"%s\"; "
                    "unexpected EOF", filename);
                goto server_table_read_exit;
            case '\n':
                continue;
            case '#':
                while ((c = getc(file)) != '\n' && c != EOF)
                    ;
                continue;
        }
        pid_t pid;
        if (c == '-')
        {
            pid = SERVER_SUSPENDED;
        }
        else
        {
            ungetc(c, file);
            if (fscanf(file, "%u", &pid) != 1)
            {
                error("unable to read server table entry from file \"%s\"; "
                    "bad PID", filename);
                break;
            }
           
            if (!verify_pid(pid))
            { 
                error("unable to verify process with PID %u is a %s server; "
                    "assuming PID %u is not a server", pid, PROGRAM_NAME, pid);
                pid = SERVER_SUSPENDED;
            }
        }

        c = getc(file);
        if (c != ' ' && c != '\t')
        {
            error("unable to read server table entry from file \"%s\"; "
                "expected a space character after PID", filename);
            break;
        }
        do
        {
            c = getc(file);
        }
        while (c == ' ' || c == '\t');

        char url[CKTP_MAX_URL_LENGTH+1];
        url[0] = c;
        size_t j = 0;
        while (url[j] != '\n' && i < CKTP_MAX_URL_LENGTH && !feof(file) &&
            !ferror(file))
        {
            j++;
            url[j] = getc(file);
        }
        c = url[j];
        url[j] = '\0';
        while (isspace(c) && c != '\n')
        {
            c = getc(file);
        }
        if (c != '\n')
        {
            error("unable to read server table entry from file \"%s\"; "
                "expected a newline after tunnel URL", filename);
            break;
        }

        server_table_insert(&table, pid, url);
    }
server_table_read_exit:

    flock(fileno(file), LOCK_UN);
    fclose(file);
    return table;
}

/*
 * Check if a pid is a server process.
 */
#define EXE_PATH_BUFF_SIZE      128
static bool verify_pid(pid_t pid)
{
    // This basically checks that the /proc/[pid]/exe symbol link
    // points to the server executable.
    const char *pid_path_format = "/proc/%u/exe";
    int pid_path_len = snprintf(NULL, 0, pid_path_format, pid);
    if (pid_path_len < 0)
    {
        return false;
    }
    char pid_path[pid_path_len+1];
    if (snprintf(pid_path, pid_path_len+1, pid_path_format, pid) !=
            pid_path_len)
    {
        return false;
    }
    char exe_path[EXE_PATH_BUFF_SIZE];
    ssize_t exe_path_len = readlink(pid_path, exe_path, sizeof(exe_path));
    if (exe_path_len <= 0 || strstr(exe_path, PROGRAM_NAME) == NULL)
    {
        return false;
    }

    return true;
}

/*
 * Write a server table.
 */
bool server_table_write(server_entry_t table)
{
    const char *filename = SERVER_TABLE_FILENAME;
    FILE *file = fopen(filename, "w");
    if (file == NULL)
    {
        error("unable to open server table file \"%s\" for writing",
            filename);
        return false;
    }

    flock(fileno(file), LOCK_EX);
    for (size_t i = 0; i < SERVER_TABLE_MAX_ENTRIES && table != NULL; i++)
    {
        server_entry_print(file, table->pid, table->url);
        table = table->next;
    }
    fflush(file);
    flock(fileno(file), LOCK_UN);

    fclose(file);
    return true;
}

/*
 * Print a server table entry.
 */
static void server_entry_print(FILE *file, pid_t pid, const char *url)
{
    switch (pid)
    {
        case SERVER_DEAD:
            return;
        case SERVER_SUSPENDED:
            fprintf(file, "-\t%s\n", url);
            return;
        default:
            fprintf(file, "%u\t%s\n", pid, url);
            return;
    }
}

