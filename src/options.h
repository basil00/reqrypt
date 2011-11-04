/*
 * options.h
 * (C) 2011, all rights reserved,
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
#ifndef __OPTIONS_H
#define __OPTIONS_H

#include <stdbool.h>

#include "cfg.h"

/*
 * Options table.
 */
struct options_s
{
    bool seen_help;
    bool seen_no_capture;
#ifdef FREEBSD
    bool seen_no_ipfw;
#endif
#ifdef LINUX
    bool seen_no_iptables;
#endif
    bool seen_no_launch_ui;
    bool seen_no_ui;
    bool seen_ui_port;
    int val_ui_port;
    bool seen_version;
};

/*
 * Prototypes.
 */
void options_init(int argc, char **argv);
const struct options_s *options_get(void);

#endif      /* __OPTIONS_H */
