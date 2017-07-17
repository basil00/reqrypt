/*
 * client.c
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "capture.h"
#include "cfg.h"
#include "config.h"
#include "http_server.h"
#include "install.h"
#include "log.h"
#include "misc.h"
#include "options.h"
#include "packet.h"
#include "packet_dispatch.h"
#include "packet_filter.h"
#include "packet_track.h"
#include "random.h"
#include "thread.h"
#include "tunnel.h"

#define NUM_THREADS_DEFAULT     3
#define NUM_THREADS_MAX         16

/*
 * Prototypes.
 */
static void allow_packets(bool log, struct ethhdr **packets);
static void *configuration_thread(void *arg);
static void *worker_thread(void *arg);
static bool user_exit(http_buffer_t buff);
void log_packet(const uint8_t *packet);

/*
 * Global configuration.
 */
mutex_t config_lock;
struct config_s config;

/*
 * Main entry point:
 */
int MAIN(int argc, char **argv)
{
    // First print GPL information:
    printf("%s %s [%s] Copyright (C) 2017 basil\n", PROGRAM_NAME_LONG,
        PROGRAM_VERSION, PLATFORM);
    puts("License GPLv3+: GNU GPL version 3 or later "
        "<http://gnu.org/licenses/gpl.html>.");
    puts("This is free software: you are free to change and redistribute it.");
    puts("There is NO WARRANTY, to the extent permitted by law.");
    putchar('\n');

    // Process options:
    options_init(argc, argv);

    // Initialise various components (order is important!).
    log_init();
    trace("changing to home directory %s", PROGRAM_DIR);
    chdir_home();
    trace("installing files (if required)");
    install_files();
    trace("initialising user configuration");
    config_init();
    trace("initialising tunnel management");
    tunnel_init();

    // Initialise the sockets library (if required on this platform).
    trace("initialising sockets");
    init_sockets();

    // Get number of threads.
    int num_threads =
        (options_get()->seen_num_threads?  options_get()->val_num_threads:
            NUM_THREADS_DEFAULT);
    if (num_threads < 1 || num_threads > NUM_THREADS_MAX)
    {
        error("unable to spawn %d threads; expected a number within the "
            "range 1..%u", num_threads, NUM_THREADS_MAX);
    }

    // Create configuration server thread.
    trace("launching configuration server thread");
    if (thread_lock_init(&config_lock))
    {
        error("unable to initialise global configuration lock");
    }
    thread_t config_thread;
    if (!options_get()->seen_no_ui &&
        thread_create(&config_thread, configuration_thread, NULL) != 0)
    {
        error("unable to create configuration server thread");
    }

    // Open the packet capture/injection device driver.
    trace("initialising packet capture");
    if (!options_get()->seen_no_capture)
    {
        init_capture();
    }

    // Open the tunnels.
    trace("initialising tunnels");
    tunnel_file_read();
    tunnel_open();

    // Go to sleep if we are not capturing packets.
    while (options_get()->seen_no_capture)
    {
        sleeptime(UINT64_MAX);
    }

    // Start worker threads.
    for (int i = 1; i < num_threads; i++)
    {
        thread_t work_thread;
        if (thread_create(&work_thread, worker_thread, NULL) != 0)
        {
            error("unable to create worker thread");
        }
    }
    worker_thread((void *)0);

    return EXIT_SUCCESS;
}


static void *worker_thread(void *arg)
{
    // RNG for packet_dispatch
    random_state_t rng = random_init();

    // The main loop.  
    // Handles either incoming packets, or requests from the configuration
    // server.
    while (true)
    {
        uint8_t packet[CKTP_MAX_PACKET_SIZE + sizeof(struct ethhdr)];
        uint8_t packet_buff[PACKET_BUFF_SIZE];
        size_t packet_len = get_packet(packet, sizeof(packet));

        struct config_s config;
        config_get(&config);

        // Do we need to tunnel this packet?
        if (!packet_filter(&config, packet, packet_len))
        {
            inject_packet(packet, packet_len);
            continue;
        }

        // Is there a tunnel available for use?
        if (config.tunnel && !tunnel_ready())
        {
            warning("unable to tunnel packet (no suitable tunnel is open); "
                "the packet will be sent via the normal route");
            inject_packet(packet, packet_len);
            continue;
        }

        // Is this packet a repeat or not?
        uint64_t packet_hash;
        unsigned packet_rep;
        packet_track(packet, &packet_hash, &packet_rep);

        // Dispatch the packet (fragments)
        struct ethhdr *allowed_packets[DISPATCH_MAX_FRAGMENTS+1];
        struct ethhdr *tunneled_packets[DISPATCH_MAX_FRAGMENTS+1];
        allowed_packets[0]  = NULL;
        tunneled_packets[0] = NULL;
        packet_dispatch(&config, rng, packet, packet_len, packet_hash,
            packet_rep, allowed_packets, tunneled_packets, packet_buff);

        // Tunnel the packets
        if (config.tunnel)
        {
            if (!tunnel_packets(packet, (uint8_t **)tunneled_packets,
                packet_hash, packet_rep, config.mtu))
            {
                continue;
            }
        }
        else
        {
            allow_packets(true, tunneled_packets);
        }

        // Allow packets.
        allow_packets(false, allowed_packets);
    }

    return NULL;
}

/*
 * Inject packets.
 */
static void allow_packets(bool log, struct ethhdr **packets)
{
    for (int i = 0; packets[i] != NULL; i++)
    {
        struct iphdr *ip_header = (struct iphdr *)(packets[i] + 1);
        size_t tot_len = sizeof(struct ethhdr) + ntohs(ip_header->tot_len);
        if (log)
            log_packet(ip_header);
        inject_packet((uint8_t *)packets[i], tot_len);
    }
}

/*
 * Configuration thread.
 */
static void *configuration_thread(void *arg)
{
    int port = (options_get()->seen_ui_port? options_get()->val_ui_port:
        PROGRAM_UI_PORT);
    if (port <= 0 || port > UINT16_MAX)
    {
        error("unable to start user interface server; expected a port number "
            "0..%u, found %d", UINT16_MAX, port);
    }
    struct config_s config;
    config_get(&config);
    bool launch = !options_get()->seen_no_launch_ui && config.launch_ui;

    // Register an exit handler.
    http_register_callback("exit", user_exit);

    log("starting %s user interface http://localhost:%u/", PROGRAM_NAME, port);
    http_server(port, config_callback, launch);
    return NULL;
}

/*
 * User interface exit handler.
 */
static bool user_exit(http_buffer_t buff)
{
    quit(EXIT_SUCCESS);
}

