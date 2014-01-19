/*
 * http_server.c
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

/*
 * This module implements a simple, non-compliant, HTTP/web server for the
 * user interface.
 */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfg.h"
#include "http_server.h"
#include "log.h"
#include "misc.h"
#include "socket.h"

#define MAX_REQUEST_BUFF_SIZE   2048
#define MAX_CONTENT_NAME        32
#define MAX_MACRO_NAME          32
#define MAX_VAR_LENGTH          32
#define MAX_VAL_LENGTH          1024

#define HTTP_STATE_ERROR        0
#define HTTP_STATE_START        1
#define HTTP_STATE_GET          2
#define HTTP_STATE_POST         3
#define HTTP_STATE_URI          4
#define HTTP_STATE_VERSION      5
#define HTTP_STATE_HEADER_VAR   6
#define HTTP_STATE_HEADER_VAL   7
#define HTTP_STATE_CONTENT_VAR  8
#define HTTP_STATE_CONTENT_VAL  9
#define HTTP_STATE_FINAL        10

#define HTTP_METHOD_GET         0
#define HTTP_METHOD_POST        1

#define HTTP_TYPE_HTML          0
#define HTTP_TYPE_CSS           1
#define HTTP_TYPE_JAVASCRIPT    2
#define HTTP_TYPE_TEXT          3
#define HTTP_TYPE_SVG           4

/*
 * Include the static content.
 */
#include "http_data.c"

/*
 * Lookup some static content.
 */
static http_buffer_t http_lookup_static_data(const char *name)
{
    struct file_data_s key;
    if (name[0] == '\0')
    {
        name = "options.html";
    }
    key.name = name;

    struct file_data_s *data = bsearch(&key,
        file_data, sizeof(file_data) / sizeof(struct file_data_s),
        sizeof(struct file_data_s), file_data_s_compare);

    if (data == NULL)
    {
        return NULL;
    }
    http_buffer_t buff = http_buffer_open();
    memmove(buff, &data->buff, sizeof(struct http_buffer_s));
    return buff;
}

/*
 * A custom call-back function entry.
 */
struct http_callback_s
{
    const char           *name;
    http_callback_func_t  callback;
};

/*
 * Comparison function for struct http_callback_s.
 */
static int http_callback_s_compare(const void *a, const void *b)
{
    const struct http_callback_s *a1 = (const struct http_callback_s *)a;
    const struct http_callback_s *b1 = (const struct http_callback_s *)b;
    return strcmp(a1->name, b1->name);
};

/*
 * List of registered callbacks.
 */
#define MAX_CALLBACKS           8
struct http_callback_s callbacks[MAX_CALLBACKS];
size_t callbacks_length = 0;

/*
 * Register a new callback function.
 */
void http_register_callback(const char *name, http_callback_func_t func)
{
    if (callbacks_length >= MAX_CALLBACKS)
    {
        panic("maximum number of callbacks (%u) exceeded", MAX_CALLBACKS);
    }

    callbacks[callbacks_length].name     = strdup(name);
    callbacks[callbacks_length].callback = func;
    callbacks_length++;

    if (callbacks_length > 1)
    {
        qsort(callbacks, callbacks_length, sizeof(struct http_callback_s),
            http_callback_s_compare);
    }
}

/*
 * Lookup a callback function.
 */
static http_callback_func_t http_lookup_callback(const char *name)
{
    struct http_callback_s key;
    key.name = name;
    struct http_callback_s *callback = bsearch(&key,
        callbacks, callbacks_length, sizeof(struct http_callback_s),
        http_callback_s_compare);

    if (callback == NULL)
    {
        return NULL;
    }
    return callback->callback;
}

/*
 * Comparison function for struct http_user_var_s.
 */
int http_user_var_s_compare(const void *a, const void *b)
{
    const struct http_user_var_s *a1 = (const struct http_user_var_s *)a;
    const struct http_user_var_s *b1 = (const struct http_user_var_s *)b;
    return strcmp(a1->var, b1->var);
}

/*
 * A HTTP request.
 */
struct http_request_s
{
    uint8_t method;
    char name[MAX_CONTENT_NAME+1];
    struct http_user_vars_s vars;
};

/*
 * HTTP request parser.
 */
struct http_parser_s
{
    uint8_t state;
    int16_t state_pos;
    unsigned content_length;
    char var_buff[MAX_VAR_LENGTH+1];
    char val_buff[MAX_VAL_LENGTH+1];
    unsigned body_used;
    struct http_request_s request;
};

/*
 * Prototypes.
 */
static void http_parser_init(struct http_parser_s *parser);
static size_t http_parse_request(const char *request, size_t request_length,
    struct http_parser_s *parser);
static size_t http_parse_request(const char *request, size_t request_length,
    struct http_parser_s *parser);
static void http_handle_request(socket_t s,
    const struct http_request_s *request);
static void http_error(socket_t s, unsigned http_code,
    const struct http_request_s *request);
static bool http_send_response(socket_t s, unsigned http_code,
    http_buffer_t content, const struct http_request_s *request);
static int http_type(const char *name);
static void http_expand_content(http_buffer_t content,
    const struct http_request_s *request, http_buffer_t buff);
static void http_expand_macro(const char *macro_name, const char *arg,
    const struct http_request_s *request, http_buffer_t buff);

/*
 * Launch a http server that listens on the given port.
 */
void http_server(uint16_t port, void (*callback)(struct http_user_vars_s *),
    bool launch)
{
    socket_t s_listen = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s_listen == INVALID_SOCKET)
    {
        error("unable to create a socket for the configuration server");
    }
    struct sockaddr_in6 listen_addr;
    memset(&listen_addr, 0x0, sizeof(listen_addr));
    listen_addr.sin6_family = AF_INET6;
    listen_addr.sin6_port   = htons(port);
    listen_addr.sin6_addr   = in6addr_any;
    int on = 1;
    setsockopt(s_listen, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    // For Windows we must explicitly allow IPv4 connections
    on = 0;
    if (setsockopt(s_listen, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on,
            sizeof(on)) != 0)
    {
        warning("unable to allow incoming IPv4 connections to configuration "
            "server");
    }
    if (bind(s_listen, (const void *)&listen_addr, sizeof(listen_addr)) != 0)
    {
        error("unable to create configuation server; failed to bind to "
            "address localhost:%u", port);
    }

    if (listen(s_listen, 1) != 0)
    {
        error("unable to create configuation server; failed to listen to "
            "address localhost:%u", port);
    }

    // Launch the UI:
    if (launch)
    {
        launch_ui(port);
    }

    // Main server loop:
    while (true)
    {
        struct sockaddr_in6 accept_addr;
        socklen_t accept_len = sizeof(accept_addr);
        socket_t s = accept(s_listen, (struct sockaddr *)&accept_addr,
            &accept_len);
        if (s == INVALID_SOCKET)
        {
            warning("unable to accept incoming connection to configuration "
                "server localhost:%u", port);
            close_socket(s);
            continue;
        }
        static const struct in6_addr in6addr_loopbackv4 =
            {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}}};
        if (memcmp(&accept_addr.sin6_addr, &in6addr_loopback,
                sizeof(in6addr_loopback)) != 0 &&
            memcmp(&accept_addr.sin6_addr, &in6addr_loopbackv4,
                sizeof(in6addr_loopbackv4) - 3) != 0)
        {
            warning("unable to accept incoming connection to configuration "
                "server localhost:%u from non-local address", port);
            close_socket(s);
            continue;
        }
        char request[MAX_REQUEST_BUFF_SIZE];
        struct http_parser_s parser;
        http_parser_init(&parser);
        do
        {
            size_t n = recv(s, request, sizeof(request)-1, 0);
            if (n <= 0)
            {
                http_user_vars_free(&parser.request.vars);
                warning("unable to read request for configuration server "
                    "localhost:%u", port);
                close_socket(s);
                break;
            }
            request[n] = '\0';
            http_parse_request(request, n, &parser);
            switch (parser.state)
            {
                case HTTP_STATE_FINAL:
                    break;
                case HTTP_STATE_ERROR:
                    http_user_vars_free(&parser.request.vars);
                    warning("unable to parse request to configuration server "
                        "localhost:%u", port);
                    close_socket(s);
                    break;
                default:
                    continue;
            }
            http_callback_func_t generate;
            if (parser.request.method == HTTP_METHOD_GET &&
                (generate = http_lookup_callback(parser.request.name)) != NULL)
            {
                http_buffer_t content = http_buffer_open();
                if (generate(content))
                {
                    bool success = http_send_response(s, 200, content,
                        &parser.request);
                    if (!success)
                    {
                        http_error(s, 500, &parser.request);
                    }
                }
                else
                {
                    http_error(s, 404, &parser.request);
                }
                http_buffer_close(content);
            }
            else
            {
                callback(&parser.request.vars);
                http_handle_request(s, &parser.request);
            }
            shutdown(s, SHUT_RDWR);
            http_user_vars_free(&parser.request.vars);
            close_socket(s);
        } 
        while (false);
    }
}

/*
 * Given a set of user vars and a var name, return the var val if it exists,
 * or NULL otherwise.
 */
const char *http_user_var_lookup(const struct http_user_vars_s *vars,
    const char *var)
{
    if (!vars->sorted)
    {
        qsort((void *)vars->vars, vars->size, sizeof(struct http_user_var_s),
            http_user_var_s_compare);
        ((struct http_user_vars_s *)vars)->sorted = true;
    }
    struct http_user_var_s user_var_key;
    user_var_key.var = var;
    struct http_user_var_s *user_var = bsearch(&user_var_key,
        vars->vars, vars->size, sizeof(struct http_user_var_s),
        http_user_var_s_compare);
    if (user_var == NULL)
    {
        return NULL;
    }
    return user_var->val;
}

/*
 * Insert a user var into a user var set.
 */
void http_user_var_insert(struct http_user_vars_s *vars, const char *var,
    const char *val)
{
    if (vars->size >= MAX_USER_VARS)
    {
        warning("unable to store user variable %s=%s: store size %u exceeded",
            var, val, MAX_USER_VARS);
        return;
    }

    vars->vars[vars->size].var = strdup(var);
    vars->vars[vars->size].val = strdup(val);
    if (vars->vars[vars->size].var == NULL ||
        vars->vars[vars->size].val == NULL)
    {
        error("unable to allocate memory for user var %s=%s", var, val);
    }
    vars->size++;
    vars->sorted = false;
}

/*
 * Helper functions for user vars.
 */

bool http_get_string_var(const struct http_user_vars_s *vars,
    const char *var, const char **sval)
{
    const char *val = http_user_var_lookup(vars, var);
    if (val == NULL)
    {
        return false;
    }
    *sval = val;
    return true;
}

bool http_get_bool_var(const struct http_user_vars_s *vars,
    const char *var, bool *bval)
{
    const char *val = http_user_var_lookup(vars, var);
    if (val == NULL)
    {
        return false;
    }
    if (strcmp(val, "true") == 0)
    {
        *bval = true;
        return true;
    }
    if (strcmp(val, "false") == 0)
    {
        *bval = false;
        return true;
    }
    warning("unable to get boolean value of var \"%s\"; expected \"true\" "
        "or \"false\", found \"%s\"", var, val);
    return false;
}

bool http_get_int_var(const struct http_user_vars_s *vars,
    const char *var, unsigned min, unsigned max, size_t size, void *ival)
{
    const char *val = http_user_var_lookup(vars, var);
    if (val == NULL)
    {
        return false;
    }

    unsigned ival0 = 0, i;
    for (i = 0; val[i]; i++)
    {
        if (!isdigit(val[i]))
        {
            goto int_error;
        }
        unsigned ival1 = ival0 * 10 + (val[i] - '0');
        if (ival1 < ival0 || ival1 > max)
        {
            goto int_error;
        }
        ival0 = ival1;
    }
    if (i == 0)
    {
        goto int_error;
    }

    switch (size)
    {
        case 1:
            *((uint8_t *)ival) = (uint8_t)ival0;
            break;
        case 2:
            *((uint16_t *)ival) = (uint16_t)ival0;
            break;
        case 4:
            *((uint32_t *)ival) = (uint32_t)ival0;
            break;
        default:
            panic("expected size of 1, 2, or 4");
    }
    return true;

int_error:
    warning("unable to get integer value of var \"%s\"; expected an integer "
        "in range %u..%u, found \"%s\"", var, min, max, val);
    return false;
}

/*
 * Comparison function for struct macro_s.
 */
int http_pair_s_compare(const void *a, const void *b)
{
    const struct http_pair_s *a1 = (const struct http_pair_s *)a;
    const struct http_pair_s *b1 = (const struct http_pair_s *)b;
    return strcmp(a1->key, b1->key);
}

bool http_get_enum_var(const struct http_user_vars_s *vars,
    const char *var, struct http_pair_s *def, size_t def_len, uint8_t *ival)
{
    const char *val = http_user_var_lookup(vars, var);
    if (val == NULL)
    {
        return false;
    }

    struct http_pair_s pair_key;
    pair_key.key = val;
    struct http_pair_s *pair_val = bsearch(&pair_key, def, def_len,
        sizeof(struct http_pair_s), http_pair_s_compare);

    if (pair_val != NULL)
    {
        *ival = pair_val->val;
        return true;
    }

    warning("unable to get enum value of var \"%s\"; value \"%s\" is not "
        "valid", var, val);
    return false;
}

/*
 * Initialise a struct http_user_vars_s.
 */
void http_user_vars_init(struct http_user_vars_s *vars)
{
    vars->size   = 0;
    vars->sorted = true;
}

/*
 * Free all dynamic memory associated with a struct http_user_vars_s.
 */
void http_user_vars_free(struct http_user_vars_s *vars)
{
    for (size_t i = 0; i < vars->size; i++)
    {
        free((void *)vars->vars[i].var);
        free((void *)vars->vars[i].val);
    }
    vars->size = 0;
}

/*
 * Initialise a struct http_parser_s.
 */
void http_parser_init(struct http_parser_s *parser)
{
    parser->state     = HTTP_STATE_START;
    parser->state_pos = 0;
    parser->body_used = 1;
    http_user_vars_init(&parser->request.vars);
}

/*
 * Parse a HTTP request.
 */
size_t http_parse_request(const char *request, size_t request_length,
    struct http_parser_s *parser)
{
    size_t i;

    for (i = 0; i < request_length && parser->body_used; i++)
    {
        switch (parser->state)
        {
            case HTTP_STATE_START:
                parser->state_pos = 0;
                switch (request[i])
                {
                    case 'G':
                        parser->state = HTTP_STATE_GET;
                        break;
                    case 'P':
                        parser->state = HTTP_STATE_POST;
                        break;
                    default:
                        parser->state = HTTP_STATE_ERROR;
                        return i;
                }
                break;
            case HTTP_STATE_GET:
            {
                parser->state_pos++;
                static const char get[] = {'G', 'E', 'T', ' ', '/'};
                if (parser->state_pos >= sizeof(get) ||
                    request[i] != get[parser->state_pos])
                {
                    parser->state = HTTP_STATE_ERROR;
                    return i;
                }
                else if (parser->state_pos == sizeof(get)-1)
                {
                    parser->request.method = HTTP_METHOD_GET;
                    parser->state_pos = 0;
                    parser->state = HTTP_STATE_URI;
                }
                break;
            }
            case HTTP_STATE_POST:
            {
                parser->state_pos++;
                static const char post[] = {'P', 'O', 'S', 'T', ' ', '/'};
                if (parser->state_pos >= sizeof(post) ||
                    request[i] != post[parser->state_pos])
                {
                    parser->state = HTTP_STATE_ERROR;
                    return i;
                }
                else if (parser->state_pos == sizeof(post)-1)
                {
                    parser->request.method = HTTP_METHOD_POST;
                    parser->state_pos = 0;
                    parser->state = HTTP_STATE_URI;
                }
                break;
            }
            case HTTP_STATE_URI:
            {
                if (request[i] == ' ')
                {
                    parser->request.name[parser->state_pos] = '\0';
                    parser->state_pos = 0;
                    parser->state = HTTP_STATE_VERSION;
                }
                else if(parser->state_pos == MAX_CONTENT_NAME)
                {
                    parser->state = HTTP_STATE_ERROR;
                    return i;
                }
                else
                {
                    parser->request.name[parser->state_pos++] = request[i];
                }
                break;
            }
            case HTTP_STATE_VERSION:
            {
                static const char version[] =
                    {'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r'};
                if (parser->state_pos >= sizeof(version) ||
                    request[i] != version[parser->state_pos])
                {
                    parser->state = HTTP_STATE_ERROR;
                    return i;
                }
                else if (parser->state_pos == sizeof(version)-1)
                {
                    parser->state_pos = -1;
                    parser->state = HTTP_STATE_HEADER_VAR;
                }
                else
                {
                    parser->state_pos++;
                }
                break;
            }
            case HTTP_STATE_HEADER_VAR:
            {
                if (parser->state_pos == -1)
                {
                    if (request[i] != '\n')
                    {
                        parser->state = HTTP_STATE_ERROR;
                        return i;
                    }
                    parser->state_pos = 0;
                    break;
                }
                if (parser->state_pos == 0 && request[i] == '\r')
                {
                    if (parser->request.method == HTTP_METHOD_GET)
                    {
                        parser->state = HTTP_STATE_FINAL;
                        return i;
                    }
                    else
                    {
                        parser->state_pos = -1;
                        parser->state = HTTP_STATE_CONTENT_VAR;
                        parser->body_used = parser->content_length;
                        break;
                    }
                }
                unsigned idx = (parser->state_pos > MAX_VAR_LENGTH?
                    MAX_VAR_LENGTH: parser->state_pos);
                if (request[i] == ':')
                {
                    parser->var_buff[idx] = '\0';
                    parser->state_pos = -1;
                    parser->state = HTTP_STATE_HEADER_VAL;
                    break;
                }
                if (!isalnum(request[i]) && request[i] != '-')
                {
                    parser->state = HTTP_STATE_ERROR;
                    return i;
                }
                parser->var_buff[idx] = request[i];
                parser->state_pos++;
                break;
            }
            case HTTP_STATE_HEADER_VAL:
            {
                if (parser->state_pos == -1)
                {
                    if (request[i] != ' ')
                    {
                        parser->state = HTTP_STATE_ERROR;
                        return i;
                    }
                    parser->state_pos = 0;
                    break;
                }
                unsigned idx = (parser->state_pos > MAX_VAL_LENGTH?
                    MAX_VAL_LENGTH: parser->state_pos);
                if (request[i] == '\r')
                {
                    parser->val_buff[idx] = '\0';
                    if (strcasecmp(parser->var_buff, "Content-Length") == 0)
                    {
                        parser->content_length = atoi(parser->val_buff);
                    }
                    parser->state_pos = -1;
                    parser->state = HTTP_STATE_HEADER_VAR;
                    break;
                }
                parser->val_buff[idx] = request[i];
                parser->state_pos++;
                break;
            }
            case HTTP_STATE_CONTENT_VAR:
            {
                if (parser->state_pos == -1)
                {
                    if (request[i] != '\n')
                    {
                        parser->state = HTTP_STATE_ERROR;
                        return i;
                    }
                    parser->state_pos = 0;
                    break;
                }
                parser->body_used--;
                unsigned idx = (parser->state_pos > MAX_VAR_LENGTH?
                    MAX_VAR_LENGTH: parser->state_pos);
                if (request[i] == '=')
                {
                    parser->var_buff[idx] = '\0';
                    parser->state_pos = 0;
                    parser->state = HTTP_STATE_CONTENT_VAL;
                    break;
                }
                parser->var_buff[idx] = request[i];
                parser->state_pos++;
                break;
            }
            case HTTP_STATE_CONTENT_VAL:
            {
                parser->body_used--;
                unsigned idx = (parser->state_pos > MAX_VAL_LENGTH?
                    MAX_VAL_LENGTH: parser->state_pos);
                if (request[i] == '&')
                {
                    parser->val_buff[idx] = '\0';
                    http_user_var_insert(&parser->request.vars,
                        parser->var_buff, parser->val_buff);
                    parser->state_pos = 0;
                    parser->state = HTTP_STATE_CONTENT_VAR;
                    break;
                }
                parser->val_buff[idx] = request[i];
                // Handle escape sequences.
                if (idx >= 2)
                {
                    if (parser->val_buff[idx-2] == '%' &&
                        isxdigit(parser->val_buff[idx-1]) &&
                        isxdigit(parser->val_buff[idx]))
                    {
                        parser->val_buff[idx+1] = '\0';
                        parser->val_buff[idx-2] = (char)strtol(
                            parser->val_buff + idx - 1, NULL, 16);
                        parser->state_pos--;
                    }
                    else
                    {
                        parser->state_pos++;
                    }
                }
                else
                {
                    parser->state_pos++;
                }
                break;
            }
            default:
                return i;
        }
    }

    if (parser->body_used == 0)
    {
        switch (parser->state)
        {
            case HTTP_STATE_CONTENT_VAR:
                parser->state = HTTP_STATE_ERROR;
                return i;
            case HTTP_STATE_CONTENT_VAL:
            {
                unsigned idx = (parser->state_pos > MAX_VAL_LENGTH?
                    MAX_VAL_LENGTH: parser->state_pos);
                parser->val_buff[idx] = '\0';
                http_user_var_insert(&parser->request.vars,
                    parser->var_buff, parser->val_buff);
                parser->state = HTTP_STATE_FINAL;
                return i;
            }
        }
    }

    return i;
}

/*
 * Given the name of some resource, return its content.
 */
http_buffer_t http_lookup_content(const char *name)
{
    http_buffer_t buff = http_lookup_static_data(name);
    if (buff != NULL)
    {
        return buff;
    }

    http_callback_func_t callback = http_lookup_callback(name);
    if (callback != NULL)
    {
        buff = http_buffer_open();
        if (callback(buff))
        {
            return buff;
        }
        http_buffer_close(buff);
        return NULL;
    }
    return NULL;
}

/*
 * Handles a HTTP request.
 */
void http_handle_request(socket_t s, const struct http_request_s *request)
{
    http_buffer_t content = http_lookup_content(request->name);
    if (content == NULL)
    {
        http_error(s, 404, request);
        return;
    }
    bool success = http_send_response(s, 200, content, request);
    http_buffer_close(content);
    if (!success)
    {
        http_error(s, 500, request);
    }
}

/*
 * Handles an HTTP error.
 */
void http_error(socket_t s, unsigned http_code,
    const struct http_request_s *request)
{
    const char *content_filename;
    switch (http_code)
    {
        case 404:
            content_filename = "404.html";
            break;
        case 500:
            content_filename = "500.html";
            break;
        default:
            panic("unsupported HTTP code %u", http_code);
    }

    if (http_type(request->name) == HTTP_TYPE_HTML)
    {
        http_buffer_t content = http_lookup_content(content_filename);
        if (content != NULL)
        {
            if (http_send_response(s, http_code, content, request))
            {
                http_buffer_close(content);
                return;
            }
            http_buffer_close(content);
        }
    }

    // Emergency fall back:
    static const char http_header[] =
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Connection: close\r\n"
        "\r\n";
    size_t http_header_length = sizeof(http_header)-1;
    if (send(s, http_header, http_header_length, 0) != http_header_length)
    {
        warning("unable to send HTTP 500 response of size " SIZE_T_FMT
            " bytes", http_header_length);
    }
}

/*
 * Send a HTTP response.
 */
bool http_send_response(socket_t s, unsigned http_code,
    http_buffer_t content, const struct http_request_s *request)
{
    const char *http_response_header;
    switch (http_code)
    {
        case 200:
            http_response_header = "HTTP/1.1 200 OK";
            break;
        case 404:
            http_response_header = "HTTP/1.1 404 Not Found";
            break;
        case 500:
            http_response_header = "HTTP/1.1 500 Internal Server Error";
            break;
        default:
            return false;
    }
    const char *http_content_type;
    int type = http_type(request->name);
    switch (type)
    {
        default:
        case HTTP_TYPE_HTML:
            http_content_type = "text/html";
            break;
        case HTTP_TYPE_CSS:
            http_content_type = "text/css";
            break;
        case HTTP_TYPE_JAVASCRIPT:
            http_content_type = "text/javascript";
            break;
        case HTTP_TYPE_TEXT:
            http_content_type = "text/plain";
            break;
        case HTTP_TYPE_SVG:
            http_content_type = "image/svg+xml";
            break;
    }
    http_buffer_t buff;
    if (type == HTTP_TYPE_HTML || type == HTTP_TYPE_JAVASCRIPT)
    {
        buff = http_buffer_open();
        http_expand_content(content, request, buff);
    }
    else
    {
        buff = content;
    }
    const char *http_header_format =
        "%s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "Content-Type: %s\r\n"
        "Cache-Control: no-cache, must-revalidate\r\n"
        "Server: " PROGRAM_NAME_LONG "\r\n"
        "\r\n";
    size_t http_body_length = buff->put_pos;
    size_t http_header_length = snprintf(NULL, 0, http_header_format,
        http_response_header, http_body_length, http_content_type);
    size_t http_response_length = http_header_length + http_body_length;
    char *http_response = (char *)malloc(http_response_length);
    if (http_response == NULL)
    {
        error("unable to allocate " SIZE_T_FMT " bytes for HTTP response "
            "buffer", http_response_length);
    }
    snprintf(http_response, http_response_length, http_header_format,
        http_response_header, http_body_length, http_content_type);
    memmove(http_response + http_header_length, buff->buff, http_body_length);
    if (buff != content)
    {
        http_buffer_close(buff);
    }
    bool ret_val = true;
    if (send(s, http_response, http_response_length, 0)
        != http_response_length)
    {
        warning("unable to send HTTP %u response of size " SIZE_T_FMT " bytes",
            http_code, http_response_length);
        ret_val = false;
    }
    free(http_response);
    return ret_val;
}

/*
 * Determine the content type based on the content name.
 */
int http_type(const char *name)
{
    unsigned i;
    for (i = 0; name[i] && name[i] != '.'; i++)
        ;
    if (!name[i])
    {
        return HTTP_TYPE_HTML;
    }
    if (strcmp(name+i, ".html") == 0)
    {
        return HTTP_TYPE_HTML;
    }
    if (strcmp(name+i, ".css") == 0)
    {
        return HTTP_TYPE_CSS;
    }
    if (strcmp(name+i, ".js") == 0)
    {
        return HTTP_TYPE_JAVASCRIPT;
    }
    if (strcmp(name+i, ".txt") == 0)
    {
        return HTTP_TYPE_TEXT;
    }
    if (strcmp(name+i, ".svg") == 0)
    {
        return HTTP_TYPE_SVG;
    }
    return HTTP_TYPE_HTML;
}

/*
 * Expands html content.
 */
void http_expand_content(http_buffer_t content,
    const struct http_request_s *request, http_buffer_t buff)
{
    char c;

    // Copy data and expand macros.
    while ((c = http_buffer_getc(content)) != EOF)
    {
        if (c == '$')
        {
            // Found a macro?
            char macro[MAX_MACRO_NAME+1];
            unsigned i;
            for (i = 0; i < MAX_MACRO_NAME &&
                 (c = http_buffer_getc(content)) != EOF &&
                 (isupper(c) || c == '_'); i++)
            {
                macro[i] = c;
            }
            macro[i] = '\0';
            if (c == '(')
            {
                char macro_arg[MAX_MACRO_NAME+1];
                for (i = 0; i < MAX_MACRO_NAME &&
                     (c = http_buffer_getc(content)) != EOF && c != ')'; i++)
                {
                    macro_arg[i] = c;
                }
                macro_arg[i] = '\0';
                if (c != ')')
                {
                    continue;
                }
                http_expand_macro(macro, macro_arg, request, buff);
            }
            else
            {
                http_expand_macro(macro, NULL, request, buff);
                http_buffer_putc(buff, c);
            }
        }
        else
        {
            http_buffer_putc(buff, c);
        }
    }
}

/****************************************************************************/
/* MACRO HANDLING                                                           */
/****************************************************************************/

typedef uint16_t macro_t;
#define MACRO_INCLUDE       0
#define MACRO_NAME          1
#define MACRO_PLATFORM      2
#define MACRO_PROGRAM       3
#define MACRO_VERSION       4

struct macro_s
{
    const char *name;
    bool    needs_arg;
    macro_t macro;
};

struct macro_s macros[] = 
{
    {"INCLUDE",   true, MACRO_INCLUDE},
    {"NAME",     false, MACRO_NAME},
    {"PLATFORM", false, MACRO_PLATFORM},
    {"PROGRAM",  false, MACRO_PROGRAM},
    {"VERSION",  false, MACRO_VERSION}
};

/*
 * Comparison function for struct macro_s.
 */
int macro_s_compare(const void *a, const void *b)
{
    const struct macro_s *a1 = (const struct macro_s *)a;
    const struct macro_s *b1 = (const struct macro_s *)b;
    return strcmp(a1->name, b1->name);
}

/*
 * Expand the given macro.
 */
void http_expand_macro(const char *macro_name, const char *arg,
    const struct http_request_s *request, http_buffer_t buff)
{
    struct macro_s macro_key;
    macro_key.name = macro_name;
    struct macro_s *macro = bsearch(&macro_key, macros,
        sizeof(macros) / sizeof(struct macro_s), sizeof(struct macro_s),
        macro_s_compare);

    if (macro != NULL)
    {
        if ((macro->needs_arg && arg == NULL) || 
            (!macro->needs_arg && arg != NULL))
        {
            return;
        }

        switch (macro->macro)
        {
            case MACRO_INCLUDE:
            {
                http_buffer_t content = http_lookup_content(arg);
                if (content != NULL)
                {
                    http_expand_content(content, request, buff);
                    http_buffer_close(content);
                }
                return;
            }
            case MACRO_NAME:
                http_buffer_puts(buff, request->name);
                return;
            case MACRO_PLATFORM:
                http_buffer_puts(buff, PLATFORM);
                return;
            case MACRO_PROGRAM:
                http_buffer_puts(buff, PROGRAM_NAME_LONG);
                return;
            case MACRO_VERSION:
                http_buffer_puts(buff, PROGRAM_VERSION);
                return;
        }
    }

    if (arg != NULL || request == NULL)
    {
        return;
    }

    // Not a built-in macro, try a user var:
    const char *user_val = http_user_var_lookup(&request->vars, macro_name);
    if (user_val != NULL)
    {
        http_buffer_puts(buff, user_val);
    }
    return;
}

/*
 * Write a character to the given buffer.
 */
void http_buffer_putc(http_buffer_t buff, char c)
{
    if (buff->put_pos >= buff->size)
    {
        if (!buff->dynamic)
        {
            return;
        }
        if (buff->size == 0)
        {
            buff->size = 512;
        }
        buff->size *= 2;
        buff->buff = (char *)realloc(buff->buff, buff->size);
        if (buff->buff == NULL)
        {
            error("unable to resize HTTP output buffer to new size of "
                SIZE_T_FMT " bytes", buff->size);
        }
    }

    buff->buff[buff->put_pos++] = c;
}

/*
 * Write a string to the given buffer.
 */
void http_buffer_puts(http_buffer_t buff, const char *s)
{
    while (*s)
    {
        http_buffer_putc(buff, *s);
        s++;
    }
}

/*
 * Read a character from the given buffer.
 */
char http_buffer_getc(http_buffer_t buff)
{
    if (buff->get_pos == buff->put_pos)
    {
        return EOF;
    }
    return buff->buff[buff->get_pos++];
}

/*
 * Open a buffer.
 */
http_buffer_t http_buffer_open(void)
{
    http_buffer_t buff = (http_buffer_t)malloc(sizeof(struct http_buffer_s));
    if (buff == NULL)
    {
        error("unable to allocate " SIZE_T_FMT " bytes for HTTP buffer",
            sizeof(struct http_buffer_s));
    }
    memset(buff, 0, sizeof(struct http_buffer_s));
    buff->dynamic = true;
    return buff;
}

/*
 * Close a buffer.
 */
void http_buffer_close(http_buffer_t buff)
{
    if (buff->dynamic)
    {
        free(buff->buff);
    }
    free(buff);
}

