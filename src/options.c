/*
 * options.c
 * (C) 2018, all rights reserved,
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
 * NOTE: MinGW64 doesn't support getopt, so we implement our own solution.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfg.h"
#include "misc.h"
#include "options.h"

typedef void *opt_val_t;
typedef uint8_t opt_type_t;
#define OPT_BOOL    0
#define OPT_INT     1

/*
 * Representation of an option.
 */
struct opt_info_s
{
    const char *name;
    opt_type_t  type;
    bool       *seen;
    void       *val;
};

/*
 * Comparison function for opt_info_s.
 */
static int opt_info_s_compare(const void *a, const void *b)
{
    const struct opt_info_s *a1 = (const struct opt_info_s *)a;
    const struct opt_info_s *b1 = (const struct opt_info_s *)b;
    return strcmp(a1->name, b1->name);
}

/*
 * Global options table.
 */
struct options_s options = {0};

/*
 * Table of all options.  Must be in alphabetical order.
 */
struct opt_info_s opt_info[] =
{
    {"help",         OPT_BOOL, &options.seen_help,         NULL},
    {"no-capture",   OPT_BOOL, &options.seen_no_capture,   NULL},
#ifdef FREEBSD
    {"no-pf",        OPT_BOOL, &options.seen_no_pf,        NULL},
#endif    
#ifdef LINUX
    {"no-iptables",  OPT_BOOL, &options.seen_no_iptables,  NULL},
#endif
    {"no-launch-ui", OPT_BOOL, &options.seen_no_launch_ui, NULL},
    {"no-ui",        OPT_BOOL, &options.seen_no_ui,        NULL},
    {"num-threads",  OPT_INT,  &options.seen_num_threads,
        &options.val_num_threads},
    {"ui-port",      OPT_INT,  &options.seen_ui_port,
        &options.val_ui_port},
    {"version",      OPT_BOOL, &options.seen_version,      NULL}
};

/*
 * Prototypes.
 */
static void usage(void);
static void help(void);

/*
 * Process any command line options.
 */
void options_init(int argc, char **argv)
{
    bool err = false;
    for (int i = 1; i < argc; i++)
    {
        const char *arg = argv[i];
        if (arg[0] != '-' || arg[1] != '-')
        {
            fprintf(stderr, "%s: expected an option; found \"%s\"\n", argv[0],
                arg);
            err = true;
            break;
        }

        struct opt_info_s key;
        key.name = arg + 2;
        struct opt_info_s *info = bsearch(&key, opt_info,
            sizeof(opt_info) / sizeof(struct opt_info_s),
            sizeof(struct opt_info_s), opt_info_s_compare);
        if (info == NULL)
        {
            fprintf(stderr, "%s: unrecognized option \"%s\"\n", PROGRAM_NAME,
                arg);
            err = true;
            break;
        }

        *info->seen = true;

        if (info->type != OPT_BOOL)
        {
            i++;
            if (i == argc)
            {
                fprintf(stderr, "%s: option \"%s\" missing argument",
                    PROGRAM_NAME, arg);
                err = true;
                break;
            }

            arg = argv[i];
            switch (info->type)
            {
                case OPT_INT:
                {
                    errno = 0;
                    int val = strtol(arg, NULL, 10);
                    if (errno)
                    {
                        fprintf(stderr, "%s: option \"%s\" expects an "
                            "integer argument", PROGRAM_NAME, arg);
                        err = true;
                        break;
                    }
                    *(int *)info->val = val;
                }
            }

            if (err)
            {
                break;
            }
        }
    }

    if (err)
    {
        usage();
        quit(EXIT_FAILURE);
    }

    if (options.seen_help)
    {
        help();
        quit(EXIT_SUCCESS);
    }

    if (options.seen_version)
    {
        quit(EXIT_SUCCESS);
    }
}

/*
 * Get the processed options.
 */
const struct options_s *options_get(void)
{
    return &options;
}

/*
 * Print the usage message.
 */
static void usage(void)
{
    fprintf(stderr, "usage: %s [OPTIONS]\n", PROGRAM_NAME);
    fprintf(stderr, "Run `%s --help' for more information.\n", PROGRAM_NAME);
}

/*
 * Print the help message.
 */
static void help(void)
{
    printf("\nusage: %s [OPTIONS]\n\n", PROGRAM_NAME);
    puts("OPTIONS are:");
    puts("\t--help");
    puts("\t\tPrint this helpful message.");
    puts("\t--no-capture");
    puts("\t\tDo not capture and tunnel packets (this option effectively");
    printf("\t\tdisables %s).\n", PROGRAM_NAME);
#ifdef FREEBSD
    puts("\t--no-pf");
    printf("\t\tPrevent %s from issuing pf commands.\n", PROGRAM_NAME);
    puts("\t\tUse this option if you wish to configure pf manually.");
#endif
#ifdef LINUX
    puts("\t--no-iptables");
    printf("\t\tPrevent %s from issuing iptables commands.\n", PROGRAM_NAME);
    puts("\t\tUse this option if you wish to configure iptables manually.");
#endif
    puts("\t--no-launch-ui");
    puts("\t\tDo not automatically launch the user interface.");
    puts("\t--no-ui");
    puts("\t\tDisable the user interface.");
    puts("\t--num-threads NUMBER");
    puts("\t\tUse NUMBER threads to process packets.");
    puts("\t--ui-port PORT");
    puts("\t\tUse PORT for the user interface.");
    puts("\t--version");
    puts("\t\tPrint version information and exit.");
    putchar('\n');
}

