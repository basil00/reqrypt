/*
 * log.c
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

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfg.h"
#include "http_server.h"
#include "log.h"
#include "misc.h"
#include "thread.h"

#define MAX_MESSAGE_LENGTH          1024
#define MAX_MESSAGES_PER_REQUEST    32

/*
 * Log message entry structure.
 */
struct log_message_s
{
    struct log_message_s *next;
    int8_t                message_type;
    uint16_t              message_size;
    char                 *message;
};

/*
 * The global log-level
 */
int __log_level = LOG_MESSAGE_PACKET;

/*
 * The global log.
 */
#define MAX_GLOBAL_LOG  128
mutex_t               global_log_lock;
struct log_message_s *global_log     = NULL;
struct log_message_s *global_log_end = NULL;
unsigned              global_log_len = 0;

/*
 * Terminal colors (for unix)
 */
#ifndef WINDOWS
#define color_clear()       fputs("\33[0m", stderr)
#define color_error()       fputs("\33[31m", stderr)
#define color_warning()     fputs("\33[33m", stderr)
#define color_log()         fputs("\33[32m", stderr)
#define color_panic()       fputs("\33[31m", stderr)
#else   /* WINDOWS */
#include <wincon.h>
#define STDERR GetStdHandle(STD_ERROR_HANDLE)
#define color_clear()       SetConsoleTextAttribute(STDERR, FOREGROUND_RED | \
                                FOREGROUND_GREEN | FOREGROUND_BLUE)
#define color_error()       SetConsoleTextAttribute(STDERR, FOREGROUND_RED)
#define color_warning()     SetConsoleTextAttribute(STDERR, FOREGROUND_RED | \
                                FOREGROUND_GREEN)
#define color_log()         SetConsoleTextAttribute(STDERR, FOREGROUND_GREEN)
#define color_panic()       SetConsoleTextAttribute(STDERR, FOREGROUND_RED)
#endif  /* WINDOWS */
mutex_t print_log_lock;

/*
 * Initialise this logging module.
 */
void log_init(void)
{
    __log_level = LOG_MESSAGE_INFO;
    if (thread_lock_init(&global_log_lock) != 0 ||
        thread_lock_init(&print_log_lock) != 0)
    {
        error("unable to initialise locks for logging");
    }
    http_register_callback("log-entry.txt", log_html_message);
}

/*
 * Prints the log message to the given file.
 */
static void print_log_message(struct log_message_s *msg)
{
    switch (msg->message_type)
    {
        case LOG_MESSAGE_ERROR:
            color_error();
            fputs("error", stderr);
            color_clear();
            break;
        case LOG_MESSAGE_WARNING:
            color_warning();
            fputs("warning", stderr);
            color_clear();
            break;
        case LOG_MESSAGE_PANIC:
            color_panic();
            fputs("PANIC", stderr);
            color_clear();
            break;
        case LOG_MESSAGE_INFO:
            color_log();
            fputs("log", stderr);
            color_clear();
            break;
        case LOG_MESSAGE_PACKET:
            color_log();
            fputs("packet", stderr);
            color_clear();
            break;
        case LOG_MESSAGE_TRACE:
            color_log();
            fputs("trace", stderr);
            color_clear();
            break;
    }

    fprintf(stderr, ": %s\n", msg->message);
}

/*
 * Writes the log message to the given buffer.
 */
bool log_html_message(http_buffer_t buff)
{
    thread_lock(&global_log_lock);
    struct log_message_s *msg = global_log;
    while (msg != NULL)
    {
        switch (msg->message_type)
        {
            case LOG_MESSAGE_ERROR:
                http_buffer_puts(buff, "<span class=\"error\">error</span>: ");
                break;
            case LOG_MESSAGE_WARNING:
                http_buffer_puts(buff,
                    "<span class=\"warning\">warning</span>: ");
                break;
            case LOG_MESSAGE_PANIC:
                http_buffer_puts(buff, "<span class=\"panic\">PANIC</span>: ");
                break;
            case LOG_MESSAGE_INFO:
                http_buffer_puts(buff, "<span class=\"log\">log</span>: ");
                break;
            case LOG_MESSAGE_PACKET:
                http_buffer_puts(buff, "<span class=\"log\">packet</span>: ");
                break;
            case LOG_MESSAGE_TRACE:
                http_buffer_puts(buff, "<span class=\"log\">trace</span>: ");
                break;
        }
        http_buffer_puts(buff, msg->message);
        http_buffer_puts(buff, "<br>\n");
        msg = msg->next;
    }
    thread_unlock(&global_log_lock);
    return true;
}

/*
 * Report an error and then exit.
 */
void log_message(int8_t type, const char *message, ...)
{
    int errno_cpy = errno;
    errno = 0;

    va_list args;
    va_start(args, message);
    char buff[MAX_MESSAGE_LENGTH+1];

    int n = vsnprintf(buff, MAX_MESSAGE_LENGTH, message, args);

    if (errno_cpy && (type == LOG_MESSAGE_ERROR || type == LOG_MESSAGE_WARNING))
    {
        n += snprintf(buff + n, MAX_MESSAGE_LENGTH - n, ": %s",
            strerror(errno_cpy));
    }
#ifdef WINDOWS
    if (type == LOG_MESSAGE_ERROR || type == LOG_MESSAGE_WARNING)
    {
        int winerr = GetLastError();
        SetLastError(ERROR_SUCCESS);
        if (winerr)
        {
            LPTSTR err_str = NULL;
            DWORD err_len = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FROM_SYSTEM, 0, winerr, 0, (LPTSTR)&err_str, 0,
                0);
            if (err_len != 0)
            {
                if (err_str[err_len-1] == '\n')
                {
                    err_str[err_len-1] = '\0';
                }
                n += snprintf(buff + n, MAX_MESSAGE_LENGTH - n, ": %s",
                    err_str);
                LocalFree(err_str);
            }
        }
    }
#endif  /* WINDOWS */

    n = (n > MAX_MESSAGE_LENGTH? MAX_MESSAGE_LENGTH: n);
    
    // Print the message to stderr.
    struct log_message_s log_msg_temp;
    log_msg_temp.next         = NULL;
    log_msg_temp.message_type = type;
    log_msg_temp.message_size = n;
    log_msg_temp.message      = buff;
    thread_lock(&print_log_lock);
    print_log_message(&log_msg_temp);
    thread_unlock(&print_log_lock);

    // After this point we can call malloc (which may fail!)
    struct log_message_s *log_msg = 
        (struct log_message_s *)malloc(sizeof(struct log_message_s));
    if (log_msg == NULL)
    {
        error("unable to allocate " SIZE_T_FMT " bytes for log message",
            sizeof(struct log_message_s));
    }
    log_msg->next         = NULL;
    log_msg->message_type = type;
    log_msg->message_size = n;
    log_msg->message      = (char *)malloc(n+1);
    if (log_msg->message == NULL)
    {
        error("unable to allocate %u bytes for log message copy", n+1);
    }
    strcpy(log_msg->message, buff);

    // Update the global log:
    thread_lock(&global_log_lock);
    if (global_log_end == NULL)
    {
        global_log     = log_msg;
        global_log_end = log_msg;
        global_log_len = 1;
    }
    else
    {
        global_log_end->next = log_msg;
        global_log_end       = log_msg;
        global_log_len++;
        if (global_log_len > MAX_GLOBAL_LOG)
        {
            log_msg = global_log;
            global_log = global_log->next;
            global_log_len--;
            free(log_msg->message);
            free(log_msg);
        }
    }
    thread_unlock(&global_log_lock);

    if (type == LOG_MESSAGE_ERROR || type == LOG_MESSAGE_PANIC)
    {
        sleeptime(3*SECONDS);   // Allow message to be visible before exit
        quit(EXIT_FAILURE);
    }
}

