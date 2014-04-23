/*
 * install.h
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "encodings/crypt.h"
#include "install.h"
#include "log.h"
#include "misc.h"
#include "tunnel.h"

#ifdef WINDOWS
#define SKIP_data_install_browser_sh    1
#endif

#include "install_data.c"

/*
 * Prototypes.
 */
static void install_file(const char *keyname, const char *filename);

/*
 * Install files (if required).
 */
void install_files(void)
{
    FILE *file = fopen(CONFIG_FILENAME, "r");
    if (file == NULL && errno == ENOENT)
    {
        log("installing \"%s\"", CONFIG_FILENAME);
        install_file("install.config", CONFIG_FILENAME);
    }
    else if (file != NULL)
    {
        fclose(file);
    }

    file = fopen(TUNNELS_FILENAME, "r");
    if (file == NULL && errno == ENOENT)
    {
        log("installing \"%s\"", TUNNELS_FILENAME);
        install_file("install.cache", TUNNELS_FILENAME);
    }
    else if (file != NULL)
    {
        fclose(file);
    }

    file = fopen(CRYPT_CERT_CACHE_FILENAME, "r");
    if (file == NULL && errno == ENOENT)
    {
        log("installing \"%s\"", CRYPT_CERT_CACHE_FILENAME);
        install_file("install.crypt.cache", CRYPT_CERT_CACHE_FILENAME);
    }
    else if (file != NULL)
    {
        fclose(file);
    }

#ifndef WINDOWS
    file = fopen(BROWSER_FILENAME, "r");
    if (file == NULL && errno == ENOENT)
    {
        log("installing \"%s\"", BROWSER_FILENAME);
        install_file("install.browser.sh", BROWSER_FILENAME);
    }
    else if (file != NULL)
    {
        fclose(file);
    }
#endif /* WINDOWS */
}

/*
 * Install a file.
 */
static void install_file(const char *keyname, const char *filename)
{
    struct file_data_s key;
    key.name = keyname;

    struct file_data_s *data = bsearch(&key,
        file_data, sizeof(file_data) / sizeof(struct file_data_s),
        sizeof(struct file_data_s), file_data_s_compare);

    if (data == NULL)
    {
        warning("unable to find install data for \"%s\"", filename);
        return;
    }

    FILE *file = fopen(filename, "w");
    if (file == NULL)
    {
        warning("unable to install file \"%s\"", filename);
        return;
    }
    fputs(data->buff.buff, file);
    fclose(file);
    return;
}

