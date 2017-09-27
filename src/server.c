/*
 * server.c
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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include "cfg.h"
#include "config.h"
#include "cktp.h"
#include "cktp_server.h"
#include "cktp_url.h"
#include "server_table.h"

#define OPTION_NONE             0
#define OPTION_ADD              1
#define OPTION_HELP             2
#define OPTION_INIT_START       3
#define OPTION_INIT_STOP        4
#define OPTION_LIST             5
#define OPTION_REMOVE           6

#define COLOR_RED               31
#define COLOR_GREEN             32
#define COLOR_YELLOW            33

#define MAX_ADDRS               8

/*
 * Prototypes.
 */
static int add_servers(int argc, char **argv, int optind,
    const uint32_t *addrs);
static int remove_servers(int argc, char **argv, int optind,
    const uint32_t *addrs);
static int list_servers(const uint32_t *addrs);
static int init_start_servers(const uint32_t *addrs);
static int init_stop_servers(const uint32_t *addrs);
static int start_server(const char *url);
static void help(const char *progname);
static void usage(const char *progname);
void error(const char *message, ...);
void log_message(uint8_t __unused, const char *message, ...);
static void error_message(const char *message, va_list args);
static bool get_ip_addrs(uint32_t *addrs, size_t addrssize);
static void print_urls(const char *command, int color, const char *url,
    const char *name, const uint32_t *addrs);
static void print_url(const char *url, const char *name);
static bool become_daemon(void);

/*
 * Server entry:
 */
int main(int argc, char **argv)
{
    // Print a GPL intro:
    printf("%s %s Copyright (C) 2017 basil\n", PROGRAM_NAME, PROGRAM_VERSION);
    puts("License GPLv3+: GNU GPL version 3 or later "
        "<http://gnu.org/licenses/gpl.html>.");
    puts("This is free software: you are free to change and redistribute it.");
    puts("There is NO WARRANTY, to the extent permitted by law.");
    putchar('\n');

    // Initialise syslog:
    openlog(PROGRAM_NAME, LOG_PID | LOG_NDELAY, LOG_USER);

    // Process command line arguments:
    static struct option options[] =
    {
        {"add",         0,  NULL,   OPTION_ADD},
        {"help",        0,  NULL,   OPTION_HELP},
        {"init-start",  0,  NULL,   OPTION_INIT_START},
        {"init-stop",   0,  NULL,   OPTION_INIT_STOP},
        {"list",        0,  NULL,   OPTION_LIST},
        {"remove",      0,  NULL,   OPTION_REMOVE},
        {NULL,          0,  NULL,   0}
    };
    int command = OPTION_NONE;

    while (true)
    {
        int option_idx = 0;
        int option = getopt_long(argc, argv, "", options, &option_idx);
        
        if (option == -1)
        {
            break;
        }

        switch (option)
        {
            case OPTION_HELP:
                help(argv[0]);
                return EXIT_SUCCESS;
            case OPTION_ADD: case OPTION_REMOVE: case OPTION_LIST:
            case OPTION_INIT_START: case OPTION_INIT_STOP:
                if (command != OPTION_NONE)
                {
                    error("unable to parse options; only one of `--add', "
                        "`--remove', `--list', `--init-start', or "
                        "`--init-stop' may be used at once; try `%s --help' "
                        "for more information", argv[0]);
                    return EXIT_FAILURE;
                }
                command = option;
                break;
            default:
                error("unable to parse options; try `%s --help' for more "
                    "information", argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (optind > argc)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Check if we are root, bail otherwise
    if (getuid() != 0)
    {
        error("unable to continue; you must be root to run %s", PROGRAM_NAME);
        return EXIT_FAILURE;
    }

    // Change to working directory
    if (chdir(PROGRAM_DIR) != 0)
    {
        error("unable to change to directory \"%s\"", PROGRAM_DIR);
        return EXIT_FAILURE;
    }

    // Get IP addresses for publishing URLs
    uint32_t addrs[MAX_ADDRS];
    if (!get_ip_addrs(addrs, MAX_ADDRS))
    {
        error("unable to get IP addresses for this machine; will not echo "
            "tunnel URLs");
        addrs[0] = 0x0;
    }

    // Execute command:
    switch (command)
    {
        case OPTION_ADD: default:
            return add_servers(argc, argv, optind, addrs);
        case OPTION_REMOVE:
            return remove_servers(argc, argv, optind, addrs);
        case OPTION_LIST:
            return list_servers(addrs);
        case OPTION_INIT_START:
            return init_start_servers(addrs);
        case OPTION_INIT_STOP:
            return init_stop_servers(addrs);
    }
}

/*
 * Add servers.
 */
static int add_servers(int argc, char **argv, int optind, 
    const uint32_t *addrs)
{
    server_entry_t table = server_table_read();
    
    while (optind < argc)
    {
        const char *url = argv[optind++];

        // Check the server table:
        pid_t pid = server_table_delete(&table, url);
        switch (pid)
        {
            case SERVER_DEAD: case SERVER_SUSPENDED:
                break;
            default:
                error("unable to start server for URL %s; server already "
                    "exists with PID %u", url, pid);
                server_table_insert(&table, pid, url);
                continue;
        }

        // Check that the url is valid:
        char server_name[CKTP_MAX_URL_LENGTH+1];
        if (!cktp_parse_url(url, NULL, server_name, NULL, NULL))
        {
            continue;
        }

        // Print the URL + aliases:
        print_urls("ADD", COLOR_GREEN, url, server_name, addrs);

        // Spawn server process: 
        pid = fork();
        if (pid == (pid_t)-1)
        {
            error("unable to fork server for URL %s", url);
            return EXIT_FAILURE;
        }
        if (pid == 0)
        {
            // Child:
            server_table_free(table);
            return start_server(url);
        }

        // Parent:
        server_table_insert(&table, pid, url);
    }

    server_table_write(table);
    return EXIT_SUCCESS;
}

/*
 * Start a server instance.
 */
static int start_server(const char *url)
{
    // Read the configuration file:
    config_init();
    struct config_s config;
    config_get(&config);
    unsigned threads = config.threads;
    size_t bps = (config.kb_per_sec == 0? SIZE_MAX: 
        (size_t)config.kb_per_sec * 1000);

    // Open the tunnel
    cktp_tunnel_t tunnel = cktp_open_tunnel(url, bps);
    if (tunnel == NULL)
    {
        return EXIT_FAILURE;
    }

    // Open RAW socket for packet forwarding:
    int socket_out = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket_out < 0)
    {
        error("unable to create RAW socket for packet forwarding");
        return EXIT_FAILURE;
    }
    int on = 1;
    if(setsockopt(socket_out, IPPROTO_IP, IP_HDRINCL, &on,
       sizeof(on)) != 0)
    {
        error("unable to enable header inclusion RAW socket option for "
            "packet forwarding");
        return EXIT_FAILURE;
    }

    // Open ICMP socket for packet reflection:
    int socket_icmp = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_icmp < 0)
    {
        error("unable to create RAW ICMP socket for packet reflection");
        return EXIT_FAILURE;
    }

    // Success -- become a daemon:
    if (!become_daemon())
    {
        error("unable to become a daemon process");
        return EXIT_FAILURE;
    }

    // Become user 'nobody'
    struct passwd *entry = getpwnam("nobody");
    if (entry == NULL)
    {
        error("unable to find /etc/passwd entry for user \"nobody\"");
        return EXIT_FAILURE;
    }
    if (setgid(entry->pw_gid) != 0 || setuid(entry->pw_uid) != 0)
    {
        error("unable to set user to \"nobody\"");
        return EXIT_FAILURE;
    }

    // Start serving requests:
    cktp_listen(tunnel, socket_out, socket_icmp, threads);

    return EXIT_SUCCESS;
}

/*
 * Remove servers.
 */
static int remove_servers(int argc, char **argv, int optind,
    const uint32_t *addrs)
{
    server_entry_t table = server_table_read();

    while (optind < argc)
    {
        const char *url = argv[optind++];

        // Check that the url is valid:
        char server_name[CKTP_MAX_URL_LENGTH+1];
        if (!cktp_parse_url(url, NULL, server_name, NULL, NULL))
        {
            continue;
        }

        pid_t pid = server_table_delete(&table, url);
        switch (pid)
        {
            case SERVER_DEAD:
                error("unable to remove tunnel URL %s; tunnel URL does not "
                    "exist in %s", url, PROGRAM_DIR SERVER_TABLE_FILENAME);
                break;
            case SERVER_SUSPENDED:
                print_urls("REMOVE", COLOR_RED, url, server_name, addrs);
                break;
            default: 
                if (kill(pid, SIGTERM) == 0)
                {
                    print_urls("REMOVE", COLOR_RED, url, server_name, addrs);
                }
                else
                {
                    error("unable to remove server URL %s", url);
                }
                break;
        }
    }

    server_table_write(table);
    return EXIT_SUCCESS;
}

/*
 * Start servers on bootup.
 */
static int init_start_servers(const uint32_t *addrs)
{
    server_entry_t table = server_table_read();

    server_entry_t entry = table;
    while (entry != NULL)
    {
        // Check that the url is valid:
        char server_name[CKTP_MAX_URL_LENGTH+1];
        if (!cktp_parse_url(entry->url, NULL, server_name, NULL, NULL))
        {
            entry->pid = SERVER_SUSPENDED;
            entry = entry->next;
            continue;
        }

        switch (entry->pid)
        {
            case SERVER_DEAD: case SERVER_SUSPENDED:
                break;
            default:
                error("unable to start server for URL %s; server already "
                    "exists with PID %u", entry->url, entry->pid);
                entry = entry->next;
                continue;
        }

        // Print the URL + aliases
        print_urls("START", COLOR_YELLOW, entry->url, server_name, addrs);

        // Spawn server process: 
        pid_t pid = fork();
        if (pid == (pid_t)-1)
        {
            error("unable to fork server for URL %s", entry->url);
            return EXIT_FAILURE;
        }
        if (pid == 0)
        {
            // Child:
            char url[strlen(entry->url)+1];
            strcpy(url, entry->url);
            server_table_free(table);
            return start_server(url);
        }

        // Parent:
        entry->pid = pid;
        entry = entry->next;
    }

    server_table_write(table);
    return EXIT_SUCCESS;
}

/*
 * List all servers
 */
static int list_servers(const uint32_t *addrs)
{
    server_entry_t table = server_table_read();

    server_entry_t entry = table;
    while (entry != NULL)
    {
        // Check that the url is valid:
        char server_name[CKTP_MAX_URL_LENGTH+1];
        if (!cktp_parse_url(entry->url, NULL, server_name, NULL, NULL))
        {
            entry = entry->next;
            continue;
        }

        print_urls("TUNNEL", COLOR_YELLOW, entry->url, server_name, addrs);
        entry = entry->next;
    }

    return EXIT_SUCCESS;
}

/*
 * Stop servers for shutdown.
 */
static int init_stop_servers(const uint32_t *addrs)
{
    server_entry_t table = server_table_read();
    
    server_entry_t entry = table;
    while (entry != NULL)
    {
        if (entry->pid != SERVER_DEAD || entry->pid != SERVER_SUSPENDED)
        {
            // Check that the url is valid:
            char server_name[CKTP_MAX_URL_LENGTH+1];
            if (!cktp_parse_url(entry->url, NULL, server_name, NULL, NULL))
            {
                entry = entry->next;
                continue;
            }

            if (kill(entry->pid, SIGTERM) == 0)
            {
                print_urls("STOP", COLOR_YELLOW, entry->url, server_name,
                    addrs);
            }
            else
            {
                error("unable to suspend server URL %s", entry->url);
            }
            entry->pid = SERVER_SUSPENDED;
        }
        entry = entry->next;
    }

    server_table_write(table);
    return EXIT_SUCCESS;
}

/*
 * Print help message.
 */
static void help(const char *progname)
{
    printf("\nusage: %s [COMMAND] [OPTIONS] URL [URL ...]\n\n", progname);
    puts("COMMAND is:");
    puts("\t--add");
    puts("\t\tAdd the tunnel URLs. [default]");
    puts("\t--remove");
    puts("\t\tRemove the tunnel URLs.");
    puts("\t--list");
    puts("\t\tList all tunnel URLs.");
    puts("\t--init-start, --init-stop");
    puts("\t\tUndocumented.  [used by init.d interface]\n");
    puts("OPTIONS are:");
    puts("\t--help");
    puts("\t\tPrint this helpful message.");
    putchar('\n');
}

/*
 * Print usage message.
 */
static void usage(const char *progname)
{
    fprintf(stderr, "usage: %s [COMMAND] [OPTIONS] URL [URL ...]\n", progname);
    fprintf(stderr, "Run `%s --help' for more information.\n", progname);
}

/*
 * Print an error message.
 */
void error(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    error_message(message, args);
    va_end(args);
}

/*
 * Print an error message.
 */
void log_message(uint8_t __unused, const char *message, ...)
{
    va_list args;
    va_start(args, message);
    error_message(message, args);
    va_end(args);
}

/*
 * Print an error message.
 */
#define MAX_ERROR_MESSAGE   1024
static void error_message(const char *message, va_list args)
{
    char buff[MAX_ERROR_MESSAGE+1];
    const char *errstr = "error: ";
    int errsave = errno;
    strcpy(buff, errstr);
    size_t size = strlen(errstr);
    size += vsnprintf(buff + size, sizeof(buff) - size, message, args);
    if (errsave != 0)
    {
        snprintf(buff + size, sizeof(buff) - size, ": %s", strerror(errsave));
    }
    buff[MAX_ERROR_MESSAGE] = '\0';
    syslog(LOG_ERR, "%s", buff);
    fprintf(stderr, "%s\n", buff);
    errno = 0;
}

/*
 * Get public IP addresses of this machine.
 */
static bool get_ip_addrs(uint32_t *addrs, size_t addrssize)
{
    int socket_tmp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_tmp < 0)
    {
        return false;
    }

    struct ifconf ifc;
    memset(&ifc, 0x0, sizeof(ifc));
    ifc.ifc_ifcu.ifcu_req = NULL;
    ifc.ifc_len = 0;

    // Get the number of interfaces.
    if (ioctl(socket_tmp, SIOCGIFCONF, &ifc) != 0)
    {
        close(socket_tmp);
        return false;
    }
    size_t num_if = ifc.ifc_len / sizeof(struct ifreq);
    struct ifreq ifr[num_if];
    ifc.ifc_ifcu.ifcu_req = ifr;

    if (ioctl(socket_tmp, SIOCGIFCONF, &ifc) != 0)
    {
        close(socket_tmp);
        return false;
    }
    close(socket_tmp);
    
    if (num_if != ifc.ifc_len / sizeof(struct ifreq))
    {
        return false;
    }
    size_t i;
    for (i = 0; i < num_if && i < addrssize-1; i++)
    {
        struct ifreq *req = ifr + i;
        struct sockaddr_in *addr = (struct sockaddr_in *)&req->ifr_addr;
        addrs[i] = ntohl(addr->sin_addr.s_addr);
    }
    addrs[i] = 0x0;

    return true;
}

/*
 * Print URLs.
 */
static void print_urls(const char *command, int color, const char *url,
    const char *name, const uint32_t *addrs)
{
    // Lookup the server's name
    struct hostent *host = gethostbyname(name);
    bool found = false;
    if (host != NULL && host->h_length == sizeof(uint32_t))
    {
        for (size_t i = 0; !found && host->h_addr_list[i] != NULL; i++)
        {
            for (size_t j = 0; !found && addrs[j] != 0x0; j++)
            {
                uint32_t addr;
                memmove(&addr, host->h_addr_list[i], sizeof(uint32_t));
                if (addr == htonl(addrs[j]))
                {
                    found = true;
                }
            }
        }
    }

    // Print domain name version:
    if (!found)
    {
        error("unable to match domain name \"%s\" with any IP address for "
            "this server", name);
    }
    bool terminal = (bool)isatty(fileno(stdout));
    if (terminal)
    {
        printf("\33[%dm", color);
    }
    printf("%s ", command);
    if (terminal)
    {
        fputs("\33[0m", stdout);
    }
    print_url(url, name);


    // Print URL aliases:
    for (size_t i = 0; addrs[i] != 0x0; i++)
    {
        if (!cktp_is_ipv4_addr_public(htonl(addrs[i])))
        {
            continue;
        }
        struct in_addr addr;
        addr.s_addr = htonl(addrs[i]);
        for (size_t j = 0; command[j]; j++)
        {
            putchar(' ');
        }
        putchar(' ');
        print_url(url, inet_ntoa(addr));
    }
}

/*
 * Print a URL with the server name substituted.
 */
static void print_url(const char *url, const char *name)
{
    const char *transport_ptr = strstr(url, "://");
    if (transport_ptr == NULL)
    {
        putchar('\n');
        return;
    }
    for (const char *ptr = url; ptr < transport_ptr; ptr++)
    {
        putchar(*ptr);
    }
    const char *end_ptr = strchr(transport_ptr+1, ':');
    if (end_ptr == NULL)
    {
        putchar('\n');
        return;
    }
    printf("://%s%s\n", name, end_ptr);
}

/*
 * Make the current process a daemon (after fork).
 */
static bool become_daemon(void)
{
    // Obtain new process group:
    if (setsid() == (pid_t)(-1))
    {
        return false;
    }

    // (re)open stdin, stdout, stderr 
    if (freopen("/dev/null", "w", stdout) == NULL ||
        freopen("/dev/null", "w", stderr) == NULL ||
        freopen("/dev/null", "r", stdin) == NULL)
    {
        return false;
    }

    // Set new umask
    umask(027);
    
    // Ignore some signals.
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);

    return true;
}

