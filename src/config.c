/*
 * config.c
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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "http_server.h"
#include "log.h"
#include "packet_protocol.h"
#include "thread.h"
#include "tunnel.h"

#define CONFIG_BAK_FILENAME     CONFIG_FILENAME ".bak"
#define CONFIG_TMP_FILENAME     CONFIG_FILENAME ".tmp"

/*
 * Variable names.
 */
#define VAR_POST                "post"
#define VAR_SAVE                "save"
#define VAR_ENABLED             "ENABLED"
#define VAR_HIDE_TCP            "HIDE_TCP"
#define VAR_HIDE_TCP_DATA       "HIDE_TCP_DATA"
#define VAR_HIDE_TCP_SYN        "HIDE_TCP_SYN"
#define VAR_HIDE_TCP_ACK        "HIDE_TCP_ACK"
#define VAR_HIDE_TCP_PSH        "HIDE_TCP_PSH"
#define VAR_HIDE_TCP_FIN        "HIDE_TCP_FIN"
#define VAR_HIDE_TCP_RST        "HIDE_TCP_RST"
#define VAR_HIDE_UDP            "HIDE_UDP"
#define VAR_TUNNEL              "TUNNEL"
#define VAR_SPLIT_MODE          "SPLIT_MODE"
#define VAR_LOG_LEVEL           "LOG_LEVEL"
#define VAR_GHOST_MODE          "GHOST_MODE"
#define VAR_GHOST_CHECK         "GHOST_CHECK"
#define VAR_GHOST_SET_TTL       "GHOST_SET_TTL"
#define VAR_GHOST_TTL           "GHOST_TTL"
#define VAR_FRAG_MODE           "FRAG_MODE"
#define VAR_TCP_PORT            "TCP_PORT"
#define VAR_TCP_PROTO           "TCP_PROTO"
#define VAR_TCP_PORT_2          "TCP_PORT_2"
#define VAR_TCP_PROTO_2         "TCP_PROTO_2"
#define VAR_UDP_PORT            "UDP_PORT"
#define VAR_UDP_PROTO           "UDP_PROTO"
#define VAR_MTU                 "MTU"
#define VAR_LAUNCH_UI           "LAUNCH_UI"
#define VAR_ADD_URL             "ADD_URL"
#define VAR_DEL_URL             "DEL_URL"

/*
 * Parser definitions.
 */
typedef uint8_t token_t;
#define TOKEN_END               0
#define TOKEN_VAR               1
#define TOKEN_EQ                2
#define TOKEN_VAL               3
#define TOKEN_ERROR_IO          4
#define TOKEN_ERROR_INVALID     5
#define TOKEN_ERROR_TOO_LONG    6
#define MAX_TOKEN_LENGTH        512

/*
 * Global configuration.
 */
mutex_t config_lock;
struct config_s config;

/*
 * Default configuration values.
 * This configuration is likely to work out-of-the-box for most filters.
 */
const struct config_s config_default =
{
    .enabled = true,
    .hide_tcp = true,
    .hide_tcp_data = false,
    .hide_tcp_syn = FLAG_SET,
    .hide_tcp_ack = FLAG_SET,
    .hide_tcp_psh = FLAG_SET,
    .hide_tcp_fin = FLAG_SET,
    .hide_tcp_rst = FLAG_SET,
    .hide_udp = false,
    .tunnel = false,
    .split = SPLIT_PARTIAL,
    .ghost = GHOST_NAT,
    .ghost_check = true,
    .ghost_set_ttl = true,
    .ghost_ttl = 2,
    .fragment = FRAG_TRANSPORT,
    .tcp_port = 80,
    .tcp_proto = PROTOCOL_TCP_DEFAULT,
    .tcp_port_2 = 443,
    .tcp_proto_2 = PROTOCOL_TCP_2_DEFAULT,
    .udp_port = 53,
    .udp_proto = PROTOCOL_UDP_DEFAULT,
    .mtu = 1492,
    .launch_ui = true
};

/*
 * Enum definitions:
 */
struct http_pair_s flag_def[] =
{
    {FLAG_UNSET_NAME,           FLAG_UNSET},
    {FLAG_SET_NAME,             FLAG_SET},
    {FLAG_DONT_CARE_NAME,       FLAG_DONT_CARE}
};
struct http_pair_s split_def[] = 
{
    {SPLIT_NONE_NAME,           SPLIT_NONE},
    {SPLIT_FULL_NAME,           SPLIT_FULL},
    {SPLIT_PARTIAL_NAME,        SPLIT_PARTIAL}
};
struct http_pair_s log_level_def[] =
{
    {LOGLEVEL_ALL_NAME,         LOGLEVEL_ALL},
    {LOGLEVEL_PACKETS_NAME,     LOGLEVEL_PACKETS},
    {LOGLEVEL_INFO_NAME,        LOGLEVEL_INFO},
    {LOGLEVEL_WARNINGS_NAME,    LOGLEVEL_WARNINGS},
    {LOGLEVEL_NONE_NAME,        LOGLEVEL_NONE}
};
struct http_pair_s ghost_def[] =
{
    {GHOST_NONE_NAME,           GHOST_NONE},
    {GHOST_NAT_NAME,            GHOST_NAT},
    {GHOST_ALWAYS_NAME,         GHOST_ALWAYS}
};
struct http_pair_s frag_def[] =
{
    {FRAG_NETWORK_NAME,         FRAG_NETWORK},
    {FRAG_TRANSPORT_NAME,       FRAG_TRANSPORT}
};
#define DEF_SIZE(def)   (sizeof(def) / sizeof(struct http_pair_s))

/*
 * Prototypes.
 */
static void load_config(struct http_user_vars_s *vars,
    struct config_s *config);
static void write_config(struct config_s *config);
static void read_config(struct config_s *config);
static token_t expect_token(const char *filename, FILE *file, char *token,
    token_t expected, bool allow_eof);
static const char *token_to_string(token_t token);
static token_t read_token(FILE *file, char *token);

/*
 * Initialise this module.
 */
void config_init(void)
{
    thread_lock_init(&config_lock);
    qsort(flag_def, DEF_SIZE(flag_def), sizeof(struct http_pair_s),
        http_pair_s_compare);
    qsort(split_def, DEF_SIZE(split_def), sizeof(struct http_pair_s),
        http_pair_s_compare);
    qsort(log_level_def, DEF_SIZE(log_level_def), sizeof(struct http_pair_s),
        http_pair_s_compare);
    qsort(ghost_def, DEF_SIZE(ghost_def), sizeof(struct http_pair_s),
        http_pair_s_compare);
    qsort(frag_def, DEF_SIZE(frag_def), sizeof(struct http_pair_s),
        http_pair_s_compare);
    read_config(&config);
}

/*
 * Get the current configuration.
 */
void config_get(struct config_s *config_copy)
{
    thread_lock(&config_lock);
    memmove(config_copy, &config, sizeof(struct config_s));
    thread_unlock(&config_lock);
}

/*
 * Convert a Boolean into a string.
 */
static const char *bool_to_string(bool b)
{
    return (b? "true": "false");
}

/*
 * Convert an Enum into a string.
 */
static const char *enum_to_string(config_enum_t e, struct http_pair_s *def,
    size_t def_size)
{
    for (size_t i = 0; i < def_size; i++)
    {
        if (def[i].val == e)
        {
            return def[i].key;
        }
    }
    panic("undefined enum value 0x%X", e);
}

/*
 * Call-back from the configuration server; save the configuration state.
 */
void config_callback(struct http_user_vars_s *vars)
{
    bool should_save;
    if (http_user_var_lookup(vars, VAR_POST) == NULL)
    {
        // This is a GET request -- initialise variables:
        char buff[32];
        http_user_var_insert(vars, VAR_ENABLED,
            bool_to_string(config.enabled));
        http_user_var_insert(vars, VAR_HIDE_TCP,
            bool_to_string(config.hide_tcp));
        http_user_var_insert(vars, VAR_HIDE_TCP_DATA,
            bool_to_string(config.hide_tcp_data));
        http_user_var_insert(vars, VAR_HIDE_TCP_SYN,
            enum_to_string(config.hide_tcp_syn, flag_def, DEF_SIZE(flag_def)));
        http_user_var_insert(vars, VAR_HIDE_TCP_ACK,
            enum_to_string(config.hide_tcp_ack, flag_def, DEF_SIZE(flag_def)));
        http_user_var_insert(vars, VAR_HIDE_TCP_PSH,
            enum_to_string(config.hide_tcp_psh, flag_def, DEF_SIZE(flag_def)));
        http_user_var_insert(vars, VAR_HIDE_TCP_FIN,
            enum_to_string(config.hide_tcp_fin, flag_def, DEF_SIZE(flag_def)));
        http_user_var_insert(vars, VAR_HIDE_TCP_RST,
            enum_to_string(config.hide_tcp_rst, flag_def, DEF_SIZE(flag_def)));
        http_user_var_insert(vars, VAR_TUNNEL,
            bool_to_string(config.tunnel));
        http_user_var_insert(vars, VAR_SPLIT_MODE,
            enum_to_string(config.split, split_def, DEF_SIZE(split_def)));
        http_user_var_insert(vars, VAR_LOG_LEVEL,
            enum_to_string((config_enum_t)log_get_level(), log_level_def,
            DEF_SIZE(log_level_def)));
        http_user_var_insert(vars, VAR_HIDE_UDP,
            bool_to_string(config.hide_udp));
        http_user_var_insert(vars, VAR_GHOST_MODE,
            enum_to_string(config.ghost, ghost_def, DEF_SIZE(ghost_def)));
        http_user_var_insert(vars, VAR_GHOST_CHECK,
            bool_to_string(config.ghost_check));
        http_user_var_insert(vars, VAR_GHOST_SET_TTL,
            bool_to_string(config.ghost_set_ttl));
        snprintf(buff, sizeof(buff)-1, "%u", config.ghost_ttl);
        http_user_var_insert(vars, VAR_GHOST_TTL, buff);
        http_user_var_insert(vars, VAR_FRAG_MODE,
            enum_to_string(config.fragment, frag_def, DEF_SIZE(frag_def)));
        snprintf(buff, sizeof(buff)-1, "%u", config.tcp_port);
        http_user_var_insert(vars, VAR_TCP_PORT, buff);
        http_user_var_insert(vars, VAR_TCP_PROTO,
            protocol_get_name(config.tcp_proto));
        snprintf(buff, sizeof(buff)-1, "%u", config.tcp_port_2);
        http_user_var_insert(vars, VAR_TCP_PORT_2, buff);
        http_user_var_insert(vars, VAR_TCP_PROTO_2,
            protocol_get_name(config.tcp_proto_2));
        snprintf(buff, sizeof(buff)-1, "%u", config.udp_port);
        http_user_var_insert(vars, VAR_UDP_PORT, buff);
        http_user_var_insert(vars, VAR_UDP_PROTO,
            protocol_get_name(config.udp_proto));
        snprintf(buff, sizeof(buff)-1, "%u", config.mtu);
        http_user_var_insert(vars, VAR_MTU, buff);
        http_user_var_insert(vars, VAR_LAUNCH_UI,
            bool_to_string(config.launch_ui));

    }
    else if (http_get_bool_var(vars, VAR_SAVE, &should_save) && should_save)
    {
        // This is a POST request that wishes to save a new configuration:
        struct config_s config_temp;
        memmove(&config_temp, &config, sizeof(struct config_s));
        load_config(vars, &config_temp);

        // Copy to the global configuration state.
        thread_lock(&config_lock);
        memmove(&config, &config_temp, sizeof(struct config_s));
        thread_unlock(&config_lock);

        // Save the new configuration to disk.
        write_config(&config_temp);

        // Handle add/del of tunnel URLs
        const char *url;
        if (http_get_string_var(vars, VAR_ADD_URL, &url) && url[0] != '\0')
        {
            tunnel_add(url);
        }
        else if (http_get_string_var(vars, VAR_DEL_URL, &url) &&
                    url[0] != '\0')
        {
            tunnel_delete(url);
        }
    }
}

/*
 * Reads the configuration from a set of vars.
 */
static void load_config(struct http_user_vars_s *vars, struct config_s *config)
{
    http_get_bool_var(vars, VAR_ENABLED, &config->enabled);
    http_get_bool_var(vars, VAR_HIDE_TCP, &config->hide_tcp);
    http_get_bool_var(vars, VAR_HIDE_TCP_DATA, &config->hide_tcp_data);
    http_get_enum_var(vars, VAR_HIDE_TCP_SYN, flag_def, DEF_SIZE(flag_def),
        &config->hide_tcp_syn);
    http_get_enum_var(vars, VAR_HIDE_TCP_ACK, flag_def, DEF_SIZE(flag_def),
        &config->hide_tcp_ack);
    http_get_enum_var(vars, VAR_HIDE_TCP_PSH, flag_def, DEF_SIZE(flag_def),
        &config->hide_tcp_psh);
    http_get_enum_var(vars, VAR_HIDE_TCP_FIN, flag_def, DEF_SIZE(flag_def),
        &config->hide_tcp_fin);
    http_get_enum_var(vars, VAR_HIDE_TCP_RST, flag_def, DEF_SIZE(flag_def),
        &config->hide_tcp_rst);
    http_get_bool_var(vars, VAR_TUNNEL, &config->tunnel);
    http_get_enum_var(vars, VAR_SPLIT_MODE, split_def, DEF_SIZE(split_def),
        &config->split);
    config_enum_t log_level;
    if (http_get_enum_var(vars, VAR_LOG_LEVEL, log_level_def,
        DEF_SIZE(log_level_def), &log_level))
    {
        log_set_level(log_level);
    }
    http_get_bool_var(vars, VAR_HIDE_UDP, &config->hide_udp);
    http_get_enum_var(vars, VAR_GHOST_MODE, ghost_def, DEF_SIZE(ghost_def),
        &config->ghost);
    http_get_bool_var(vars, VAR_GHOST_CHECK, &config->ghost_check);
    http_get_bool_var(vars, VAR_GHOST_SET_TTL, &config->ghost_set_ttl);
    http_get_int_var(vars, VAR_GHOST_TTL, 0, UINT8_MAX,
        sizeof(config->ghost_ttl), &config->ghost_ttl);
    http_get_enum_var(vars, VAR_FRAG_MODE, frag_def, DEF_SIZE(frag_def),
        &config->fragment);
    http_get_int_var(vars, VAR_TCP_PORT, 0, UINT16_MAX,
        sizeof(config->tcp_port), (uint8_t *)&config->tcp_port);
    const char *tcp_proto_name;
    if (http_get_string_var(vars, VAR_TCP_PROTO, &tcp_proto_name))
    {
        config->tcp_proto = protocol_get(tcp_proto_name);
    }
    http_get_int_var(vars, VAR_TCP_PORT_2, 0, UINT16_MAX,
        sizeof(config->tcp_port_2), (uint8_t *)&config->tcp_port_2);
    const char *tcp_proto_2_name;
    if (http_get_string_var(vars, VAR_TCP_PROTO_2, &tcp_proto_2_name))
    {
        config->tcp_proto_2 = protocol_get(tcp_proto_2_name);
    }
    http_get_int_var(vars, VAR_UDP_PORT, 0, UINT16_MAX,
        sizeof(config->udp_port), &config->udp_port);
    const char *udp_proto_name;
    if (http_get_string_var(vars, VAR_UDP_PROTO, &udp_proto_name))
    {
        config->udp_proto = protocol_get(udp_proto_name);
    }
    http_get_int_var(vars, VAR_MTU, 0, UINT16_MAX, sizeof(config->mtu),
        (uint8_t *)&config->mtu);
    http_get_bool_var(vars, VAR_LAUNCH_UI, &config->launch_ui);
}

/*
 * Write a configuration to the config file.
 */
static void write_config(struct config_s *config)
{
#ifdef WINDOWS
    remove(CONFIG_BAK_FILENAME);    // For windows rename() bug.
#endif
    if (rename(CONFIG_FILENAME, CONFIG_BAK_FILENAME) != 0 && errno != ENOENT)
    {
        warning("unable to back-up old configuation file \"%s\" to \"%s\"",
            CONFIG_FILENAME, CONFIG_BAK_FILENAME);
    }
    errno = 0;

    FILE *file = fopen(CONFIG_TMP_FILENAME, "w");
    if (file == NULL)
    {
        warning("unable to open configuration file \"%s\" for writing",
            CONFIG_TMP_FILENAME);
        return;
    }
    fprintf(file, "# %s configuration file\n", PROGRAM_NAME_LONG);
    fputs("# AUTOMATICALLY GENERATED, DO NOT EDIT\n", file);
    fputc('\n', file);
    fprintf(file, "%s = \"%s\"\n", VAR_ENABLED,
        bool_to_string(config->enabled));
    fprintf(file, "%s = \"%s\"\n", VAR_HIDE_TCP,
        bool_to_string(config->hide_tcp));
    fprintf(file, "%s = \"%s\"\n", VAR_HIDE_TCP_DATA,
        bool_to_string(config->hide_tcp_data));
    fprintf(file, "%s = \"%s\"\n", VAR_HIDE_TCP_SYN,
        enum_to_string(config->hide_tcp_syn, flag_def, DEF_SIZE(flag_def)));
    fprintf(file, "%s = \"%s\"\n", VAR_HIDE_TCP_ACK,
        enum_to_string(config->hide_tcp_ack, flag_def, DEF_SIZE(flag_def)));
    fprintf(file, "%s = \"%s\"\n", VAR_HIDE_TCP_PSH,
        enum_to_string(config->hide_tcp_psh, flag_def, DEF_SIZE(flag_def)));
    fprintf(file, "%s = \"%s\"\n", VAR_HIDE_TCP_FIN,
        enum_to_string(config->hide_tcp_fin, flag_def, DEF_SIZE(flag_def)));
    fprintf(file, "%s = \"%s\"\n", VAR_HIDE_TCP_RST,
        enum_to_string(config->hide_tcp_rst, flag_def, DEF_SIZE(flag_def)));
    fprintf(file, "%s = \"%s\"\n", VAR_HIDE_UDP,
        bool_to_string(config->hide_udp));
    fprintf(file, "%s = \"%s\"\n", VAR_TUNNEL,
        bool_to_string(config->tunnel));
    fprintf(file, "%s = \"%s\"\n", VAR_SPLIT_MODE,
        enum_to_string(config->split, split_def, DEF_SIZE(split_def)));
    fprintf(file, "%s = \"%s\"\n", VAR_LOG_LEVEL,
        enum_to_string((config_enum_t)log_get_level(), log_level_def,
        DEF_SIZE(log_level_def)));
    fprintf(file, "%s = \"%s\"\n", VAR_GHOST_MODE,
        enum_to_string(config->ghost, ghost_def, DEF_SIZE(ghost_def)));
    fprintf(file, "%s = \"%s\"\n", VAR_GHOST_CHECK,
        bool_to_string(config->ghost_check));
    fprintf(file, "%s = \"%s\"\n", VAR_GHOST_SET_TTL,
        bool_to_string(config->ghost_set_ttl));
    fprintf(file, "%s = \"%u\"\n", VAR_GHOST_TTL, config->ghost_ttl);
    fprintf(file, "%s = \"%s\"\n", VAR_FRAG_MODE,
        enum_to_string(config->fragment, frag_def, DEF_SIZE(frag_def)));
    fprintf(file, "%s = \"%u\"\n", VAR_TCP_PORT, config->tcp_port);
    fprintf(file, "%s = \"%s\"\n", VAR_TCP_PROTO,
        protocol_get_name(config->tcp_proto));
    fprintf(file, "%s = \"%u\"\n", VAR_TCP_PORT_2, config->tcp_port_2);
    fprintf(file, "%s = \"%s\"\n", VAR_TCP_PROTO_2,
        protocol_get_name(config->tcp_proto_2));
    fprintf(file, "%s = \"%u\"\n", VAR_UDP_PORT, config->udp_port);
    fprintf(file, "%s = \"%s\"\n", VAR_UDP_PROTO,
        protocol_get_name(config->udp_proto));
    fprintf(file, "%s = \"%u\"\n", VAR_MTU, config->mtu);
    fprintf(file, "%s = \"%s\"\n", VAR_LAUNCH_UI,
        bool_to_string(config->launch_ui));
    fclose(file);

#ifdef WINDOWS
    remove(CONFIG_FILENAME);
#endif
    if (rename(CONFIG_TMP_FILENAME, CONFIG_FILENAME) != 0)
    {
        warning("unable to move temporary configuration file \"%s\" to \"%s\"",
            CONFIG_TMP_FILENAME, CONFIG_FILENAME);
    }
}

/*
 * Read the configuration from the config file.
 */
static void read_config(struct config_s *config)
{
    // Copy the default configuration values:
    memmove(config, &config_default, sizeof(struct config_s));

    // Find a configuration file:
    const char *filename = CONFIG_FILENAME;
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        warning("unable to open configuration file \"%s\" for reading; "
            "will use backup configuration file", filename);
        filename = CONFIG_BAK_FILENAME;
        file = fopen(filename, "r");
        if (file == NULL)
        {
            warning("unable to open backup configuration file \"%s\" for "
                "reading", filename);
            return;
        }
    }

    // Parse the configuration file:
    struct http_user_vars_s vars;
    http_user_vars_init(&vars);
    char var[MAX_TOKEN_LENGTH+1];
    char val[MAX_TOKEN_LENGTH+1];
    bool success;
    while (true)
    {
        token_t t = expect_token(filename, file, var, TOKEN_VAR, true);
        if (t == TOKEN_END)
        {
            success = true;
            break;
        }
        if (t != TOKEN_VAR ||
            TOKEN_EQ != expect_token(filename, file, NULL, TOKEN_EQ, false) ||
            TOKEN_VAL != expect_token(filename, file, val, TOKEN_VAL, false))
        {
            success = false;
            break;
        }
        http_user_var_insert(&vars, var, val);
    }
    fclose(file);

    // Load the configuration:
    load_config(&vars, config);
    http_user_vars_free(&vars);
}

/*
 * Read a token.  Report a parse error if it doesn't match the expected token.
 */
static token_t expect_token(const char *filename, FILE *file, char *token,
    token_t expected, bool allow_eof)
{
    token_t t = read_token(file, token);

    if (t != expected && (!allow_eof || t != TOKEN_END))
    {
        warning("unable to parse configuration file \"%s\": expected a %s "
            "token; found %s token", filename, token_to_string(expected),
            token_to_string(t));
    }

    return t;
}

/*
 * Convert a token into a string.
 */
static const char *token_to_string(token_t token)
{
    switch (token)
    {
        case TOKEN_END:
            return "end-of-file";
        case TOKEN_VAR:
            return "configuration variable";
        case TOKEN_EQ:
            return "`='";
        case TOKEN_VAL:
            return "configuration value";
        case TOKEN_ERROR_IO:
            return "error (I/O)";
        case TOKEN_ERROR_INVALID:
            return "error (invalid)";
        case TOKEN_ERROR_TOO_LONG:
            return "error (too long)";
        default:
            panic("unknown token val 0x%X", token);
    }
}

/*
 * Read a configuration token.
 */
static token_t read_token(FILE *file, char *token)
{
    char c;
    // Consume whitespace and comments:
    while (true)
    {
        c = getc(file);
        switch (c)
        {
            case ' ': case '\t': case '\n': case '\r':
                continue;
            case EOF:
                break;
            case '#':
                do
                {
                    c = getc(file);
                } 
                while (c != EOF && c != '\n');
                if (c == EOF)
                {
                    break;
                }
                continue;
        }
        break;
    }

    if (isalpha(c))
    {
        if (token != NULL)
        {
            token[0] = c;
        }
        for (unsigned i = 1; i < MAX_TOKEN_LENGTH; i++)
        {
            c = getc(file);
            if (!isalnum(c) && c != '_')
            {
                if (c != EOF)
                {
                    ungetc(c, file);
                }
                if (token != NULL)
                {
                    token[i] = '\0';
                }
                return TOKEN_VAR;
            }
            if (token != NULL)
            {
                token[i] = c;
            }
        }
        return TOKEN_ERROR_TOO_LONG;
    }
    else
    {
        switch (c)
        {
            case EOF:
                return (feof(file)? TOKEN_END: TOKEN_ERROR_IO);
            case '=':
                return TOKEN_EQ;
            case '\"':
                for (unsigned i = 0; i < MAX_TOKEN_LENGTH; i++)
                {
                    c = getc(file);
                    if (c == '\"')
                    {
                        if (token != NULL)
                        {
                            token[i] = '\0';
                        }
                        return TOKEN_VAL;
                    }
                    if (c == EOF)
                    {
                        return TOKEN_ERROR_INVALID;
                    }
                    if (token != NULL)
                    {
                        token[i] = c;
                    }
                }
                return TOKEN_ERROR_TOO_LONG;
            default:
                if (token != NULL)
                {
                    token[0] = c;
                    token[1] = '\0';
                }
                return TOKEN_ERROR_INVALID;
        }
    }
}

