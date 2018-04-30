/*
 * capture.c
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
 * Filtering, packet capture, and re-injection for FreeBSD
 *
 * FILTERING:
 *      Filtering is achieved by issuing pfctl commands to redirect packets 
 *      to IP_DIVERT sockets.
 *
 * CAPTURING/RE-INJECTION:
 *      This is all handled by IP_DIVERT sockets.
 *      (I really wish Linux would implement this...)
 */

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

#include "capture.h"
#include "log.h"
#include "options.h"
#include "socket.h"

/*
 * Divert port
 */
#define DIVERT_PORT     40403

/*
 * PFCTL commands.
 */
#define PFCTL_BUFFSIZE   256
#define PFCTL_ARGS_MAX   32
static const char *pfctl_divert =
    "/sbin/pactl -a reqrypt -f ./pf.conf";
static const char *pfctl_undo =
    "/sbin/pfctl -a reqrypt -F rules";

/*
 * Prototypes.
 */
static void pfctl(const char *command);
static void pfctl_undo_on_signal(int sig);
static void pfctl_undo_flush(void);

/*
 * Global divert socket for capture/injection.
 */
static int socket_divert;

/*
 * Cleaned up pf state?
 */
static bool pf_clean = true;

/*
 * Initialise packet capturing.
 */
void init_capture(void)
{
    // Set-up divert socket.
    trace("[" PLATFORM "] setting up divert socket to port %d", DIVERT_PORT);
    
    socket_divert = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (socket_divert < 0)
    {
        error("unable to create a divert socket");
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0x0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(DIVERT_PORT);

    if (bind(socket_divert, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        error("unable to bind divert socket to port %d", DIVERT_PORT);
    }

    // Initialise packet capture/redirection with pf.
#ifndef DEBUG
    signal(SIGINT, pfctl_undo_on_signal);
    signal(SIGQUIT, pfctl_undo_on_signal);
    signal(SIGHUP, pfctl_undo_on_signal);
    signal(SIGILL, pfctl_undo_on_signal);
    signal(SIGFPE, pfctl_undo_on_signal);
    signal(SIGABRT, pfctl_undo_on_signal);
    signal(SIGSEGV, pfctl_undo_on_signal);
    signal(SIGTERM, pfctl_undo_on_signal);
    signal(SIGPIPE, pfctl_undo_on_signal);
    signal(SIGALRM, pfctl_undo_on_signal);
#endif      /* DEBUG */
    pfctl(pfctl_divert);
    pf_clean = false;
    atexit(pfctl_undo_flush);
}

/*
 * Get a captured packet.
 */
size_t get_packet(uint8_t *buff, size_t size)
{
    if (size <= sizeof(struct ethhdr))
    {
        return 0;
    }

    ssize_t result;
    do
    {
        result = recv(socket_divert, buff + sizeof(struct ethhdr),
            size - sizeof(struct ethhdr), 0);
        if (result < 0)
        {
            warning("failed to read packet from netfilter socket");
            continue;
        }
    }
    while (false);

    // Add fake ethhdr
    struct ethhdr *eth_header = (struct ethhdr *)buff;
    memset(&eth_header->h_dest, 0x0, ETH_ALEN);
    memset(&eth_header->h_source, 0x0, ETH_ALEN);
    eth_header->h_proto = htons(ETH_P_IP);

    return (size_t)result + sizeof(struct ethhdr);
}

/*
 * Re-inject a packet.
 */
void inject_packet(uint8_t *buff, size_t size)
{
    struct ethhdr *eth_header = (struct ethhdr *)buff;
    struct iphdr *ip_header = (struct iphdr *)(eth_header + 1);
    size -= sizeof(struct ethhdr);

    struct sockaddr_in to_addr;
    memset(&to_addr, 0x0, sizeof(to_addr));
    to_addr.sin_family      = AF_INET;
    to_addr.sin_port        = htons(DIVERT_PORT);
    to_addr.sin_addr.s_addr = INADDR_ANY;
    
    int n = sendto(socket_divert, ip_header, size, 0,
        (struct sockaddr *)(&to_addr), sizeof(to_addr));
    if (n < 0)
    {
        warning("unable to re-inject packet of size %zu", size);
    }
}

/*
 * Execute an pfctl command.
 */
static void pfctl(const char *command)
{
    if (options_get()->seen_no_pf)
    {
        return;
    }

    char buff[PFCTL_BUFFSIZE];
    if (snprintf(buff, sizeof(buff), command, DIVERT_PORT, getuid()) >=
            sizeof(buff))
    {
        panic("pfctl buffer is too small");
    }
    log("[" PLATFORM "] executing pfctl command \"%s\"", buff);

    // Note: never use system() because we have setuid as root.
    char *args[PFCTL_ARGS_MAX];
    args[0] = buff;
    int i, j;
    for (i = 0, j = 1; buff[i] && j < PFCTL_ARGS_MAX-1; i++)
    {
        if(buff[i] == ' ')
        {
            buff[i] = '\0';
            if (buff[i+1] != '\0')
            {
                args[j++] = buff+i+1;
            }
        }
    }
    args[j] = NULL;

    pid_t pid = fork();
    if (pid == -1)
    {
        error("unable to execute pfctl command; failed to fork current "
            "process");
    }
    else if (pid == 0)
    {
        if (setgid(0) != 0)
        {
            error("unable to set the group ID to 0 (root) for pfctl command");
        }
        if (setuid(0) != 0)
        {
            error("unable to set the user ID to 0 (root) for pfctl command");
        }
        execv("/sbin/pfctl", args);
        error("unable to execute pfctl command");
    }

    int exit_status;
    while (waitpid(pid, &exit_status, 0) < 0)
    {
        if (errno != EINTR)
        {
            error("unable to execute pfctl command; failed to wait for pfctl "
                "to complete");
        }
    }
    if(exit_status != 0)
    {
        error("pfctl command returned non-zero exit status %d", exit_status);
    }
}

/*
 * Undo pfctl commands on signal then exit.
 */
static void pfctl_undo_on_signal(int sig)
{
    log("[" PLATFORM "] caught deadly signal %d; cleaning up pf state", sig);
    pfctl_undo_flush();
    error("caught deadly signal %d; exitting", sig);
}

/*
 * Undo pfctl commands.
 */
static void pfctl_undo_flush(void)
{
    if (!pf_clean)
    {
        pfctl(pfctl_undo);
        pf_clean = true;
    }
}

