/*
 * misc.c
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

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "cfg.h"
#include "log.h"
#include "misc.h"

/*
 * Initialise a buffer with random data from /dev/urandom
 */
void random_ext_init(uint8_t *ptr, size_t size)
{
    const char *rand_dev = "/dev/urandom";
    FILE *rand = fopen(rand_dev, "r");

    if (rand == NULL)
    {
        error("unable to open random number device \"%s\"", rand_dev);
    }

    if (fread(ptr, sizeof(uint8_t), size, rand) != size)
    {
        error("unable to read %zu bytes from random number device \"%s\"",
            size, rand_dev);
    }
    
    fclose(rand);
}

/*
 * Change to home directory (and create it if required).
 */
void chdir_home(void)
{
#ifdef CLIENT
    const char *home_dir = getenv("HOME");
    if (home_dir == NULL)
    {
        warning("unable to find home directory; $HOME environment variable is "
            "not set");
        goto chdir_home_error;
    }
    if (chdir(home_dir) != 0)
    {
        warning("unable to change to home directory %s", home_dir);
        goto chdir_home_error;
    }
    if (chdir(PROGRAM_DIR) != 0)
    {
        if (errno == ENOENT)
        {
            log("creating program directory %s", PROGRAM_DIR);
            if (mkdir(PROGRAM_DIR, S_IRUSR | S_IWUSR | S_IXUSR) != 0)
            {
                warning("unable to create program directory %s",
                    PROGRAM_DIR);
                goto chdir_home_error;
            }
            if (chdir(PROGRAM_DIR) == 0)
            {
                return;
            }
        }
        warning("unable to change to program directory %s", PROGRAM_DIR);
        goto chdir_home_error;
    }
    return;

chdir_home_error:
    warning("using /tmp as the program directory");
    if (chdir("/tmp") != 0)
    {
        error("unable to change to program directory %s", "/tmp");
    }
#endif      /* CLIENT */
}

/*
 * Launch the UI.
 */
void launch_ui(uint16_t port)
{
#ifdef CLIENT
    bool err_exit = false;
    pid_t pid = fork();
    if (pid == -1)
    {
        goto launch_ui_error;
    }

    if (pid > 0)
    {
        return;
    }

    const char url_fmt[] = "http://localhost:%u/";
    char url[sizeof(url_fmt) - 2 + 5];      // - "%u" + 5 port digits
    snprintf(url, sizeof(url), url_fmt, port);
#ifdef MACOSX
    setenv("BROWSER", "open", false);
#endif
    execlp("/bin/sh", "/bin/sh", BROWSER_FILENAME, url, NULL);
    err_exit = true;

launch_ui_error:
    warning("unable to launch user interface http://localhost:%u/", port);
    if (err_exit)
    {
        exit(EXIT_FAILURE);
    }
#endif      /* CLIENT */
}

/*
 * Gets the current time in microseconds.
 */
uint64_t gettime(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return tv.tv_sec*1000000 + tv.tv_usec;
}

/*
 * Sleep for the given number of microseconds.
 */
void sleeptime(uint64_t us)
{
    uint64_t ns = 1000*us;
    struct timespec ts;
    ts.tv_sec  = ns / 1000000000;
    ts.tv_nsec = ns % 1000000000;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
}

/*
 * Quit this application.
 */
void quit(int status)
{
    exit(status);
}

