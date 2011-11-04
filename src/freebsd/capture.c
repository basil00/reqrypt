/*
 * capture.c
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
 * Filtering, packet capture, and re-injection for FreeBSD
 *
 * FILTERING:
 *      Filtering is achieved by issuing ipfw commands to redirect packets 
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
 * IPFW commands.
 */
#define IPFW_BUFFSIZE   256
#define IPFW_ARGS_MAX   32
#ifndef MACOSX
static const char *ipfw_divert_tcp =
    "/sbin/ipfw 40405 add divert %d out proto tcp dst-port 80 uid %d";
static const char *ipfw_divert_udp =
    "/sbin/ipfw 40406 add divert %d out proto udp dst-port 53 uid %d";
#else
// MACOSX uid is buggy
static const char *ipfw_divert_tcp =
    "/sbin/ipfw 40405 add divert %d out proto tcp dst-port 80";
static const char *ipfw_divert_udp =
    "/sbin/ipfw 40406 add divert %d out proto udp dst-port 53";
#endif      /* MACOSX */
static const char *ipfw_filter_icmp =
    "/sbin/ipfw 40407 add deny in icmptypes 11";
static const char *ipfw_undo =
    "/sbin/ipfw delete 40405 40406 40407";

/*
 * Prototypes.
 */
static void ipfw(const char *command);
static void ipfw_undo_on_signal(int sig);
static void ipfw_undo_flush(void);

/*
 * Global divert socket for capture/injection.
 */
static int socket_divert;

/*
 * Cleaned up ipfw state?
 */
static bool ipfw_clean = true;

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

    // Initialise packet capture/redirection with ipfw.
#ifndef DEBUG
    signal(SIGINT, ipfw_undo_on_signal);
    signal(SIGQUIT, ipfw_undo_on_signal);
    signal(SIGHUP, ipfw_undo_on_signal);
    signal(SIGILL, ipfw_undo_on_signal);
    signal(SIGFPE, ipfw_undo_on_signal);
    signal(SIGABRT, ipfw_undo_on_signal);
    signal(SIGSEGV, ipfw_undo_on_signal);
    signal(SIGTERM, ipfw_undo_on_signal);
    signal(SIGPIPE, ipfw_undo_on_signal);
    signal(SIGALRM, ipfw_undo_on_signal);
#endif      /* DEBUG */
    ipfw(ipfw_divert_tcp);
    ipfw(ipfw_divert_udp);
    ipfw(ipfw_filter_icmp);
    ipfw_clean = false;
    atexit(ipfw_undo_flush);
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
 * Execute an ipfw command.
 */
static void ipfw(const char *command)
{
    if (options_get()->seen_no_ipfw)
    {
        return;
    }

    char buff[IPFW_BUFFSIZE];
    if (snprintf(buff, sizeof(buff), command, DIVERT_PORT, getuid()) >=
            sizeof(buff))
    {
        panic("ipfw buffer is too small");
    }
    log("[" PLATFORM "] executing ipfw command \"%s\"", buff);

    // Note: never use system() because we have setuid as root.
    char *args[IPFW_ARGS_MAX];
    args[0] = buff;
    int i, j;
    for (i = 0, j = 1; buff[i] && j < IPFW_ARGS_MAX-1; i++)
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
        error("unable to execute ipfw command; failed to fork current "
            "process");
    }
    else if (pid == 0)
    {
        if (setgid(0) != 0)
        {
            error("unable to set the group ID to 0 (root) for ipfw command");
        }
        if (setuid(0) != 0)
        {
            error("unable to set the user ID to 0 (root) for ipfw command");
        }
        execv("/sbin/ipfw", args);
        error("unable to execute ipfw command");
    }

    int exit_status;
    while (waitpid(pid, &exit_status, 0) < 0)
    {
        if (errno != EINTR)
        {
            error("unable to execute ipfw command; failed to wait for ipfw "
                "to complete");
        }
    }
    if(exit_status != 0)
    {
        error("ipfw command returned non-zero exit status %d", exit_status);
    }
}

/*
 * Undo ipfw commands on signal then exit.
 */
static void ipfw_undo_on_signal(int sig)
{
    log("[" PLATFORM "] caught deadly signal %d; cleaning up ipfw state", sig);
    ipfw_undo_flush();
    error("caught deadly signal %d; exitting", sig);
}

/*
 * Undo ipfw commands.
 */
static void ipfw_undo_flush(void)
{
    if (!ipfw_clean)
    {
        ipfw(ipfw_undo);
        ipfw_clean = true;
    }
}

