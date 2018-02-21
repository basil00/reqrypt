/*
 * tunnel.c
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cktp.h"
#include "cktp_client.h"
#include "cktp_url.h"
#include "http_server.h"
#include "log.h"
#include "misc.h"
#include "packet.h"
#include "random.h"
#include "socket.h"
#include "thread.h"
#include "tunnel.h"

#define TUNNELS_BAK_FILENAME        TUNNELS_FILENAME ".bak"
#define TUNNELS_TMP_FILENAME        TUNNELS_FILENAME ".tmp"

#define MAX_ACTIVE_TUNNELS          8

typedef uint8_t state_t;

#define TUNNEL_STATE_CLOSED         0   // Tunnel is closed.
#define TUNNEL_STATE_OPENING        1   // Tunnel is being opened.
#define TUNNEL_STATE_OPEN           2   // Tunnel is open and ready for use.
#define TUNNEL_STATE_DEAD           3   // Tunnel is closed and not for use.
#define TUNNEL_STATE_CLOSING        4   // Tunnel is scheduled to be closed.
#define TUNNEL_STATE_DELETING       5   // Tunnel is scheduled to be deleted.

#define TUNNEL_INIT_AGE             16

#define TUNNEL_NO_TIMEOUT           0

struct tunnel_s
{
    cktp_tunnel_t    tunnel;            // Underlying CKTP tunnel
    state_t          state;             // Tunnel's state
    bool             reconnect;         // True if we are reconnecting
    bool             enabled;           // True if tunnel can be opened
    uint16_t         id;                // Tunnel's ID
    uint8_t          age;               // Tunnel's age
    double           weight;            // Tunnel's weight
    char             url[CKTP_MAX_URL_LENGTH+1];
};

/*
 * Implementation of a set of tunnels.
 */
struct tunnel_set_s
{
    tunnel_t *tunnels;                  // Array of tunnels.
    size_t    size;                     // Array allocated size.
    size_t    length;                   // Array length
};
typedef struct tunnel_set_s *tunnel_set_t;
#define TUNNEL_SET_INIT         {NULL, 0, 0}
#define TUNNEL_SET_INIT_SIZE    16

/*
 * Tunnel history.
 */
struct tunnel_history_s
{
    uint32_t hash;
    uint16_t id;
};

#define TUNNEL_HISTORY_SIZE     1024

/*
 * Tunnel sets.
 */
static mutex_t tunnels_lock;
static struct tunnel_set_s tunnels_cache = TUNNEL_SET_INIT;
static uint64_t tunnel_flow_offset = 0;
static random_state_t rng = NULL;

/*
 * Prototypes.
 */
static bool tunnel_html(http_buffer_t buff, tunnel_set_t tunnel_set);
static void tunnel_set_insert(tunnel_set_t tunnel_set, tunnel_t tunnel);
static tunnel_t tunnel_set_replace(tunnel_set_t tunnel_set, tunnel_t tunnel);
static tunnel_t tunnel_set_delete(tunnel_set_t tunnel_set, const char *url);
static tunnel_t tunnel_set_lookup(tunnel_set_t tunnel_set, const char *url);
static bool tunnel_set_ready(tunnel_set_t tunnel_set);
static tunnel_t tunnel_create(const char *url, uint8_t age, bool enabled);
static void tunnel_free(tunnel_t tunnel);
static void *tunnel_activate_manager(void *unused);
static void *tunnel_activate(void *tunnel_ptr);
static state_t tunnel_try_activate(tunnel_t tunnel, bool reopen);
static tunnel_t tunnel_get(uint64_t hash, unsigned repeat);
static void *tunnel_reconnect_manager(void *unused);
static void *tunnel_reconnect(void *tunnel_ptr);

/*
 * Print all tunnels as HTML.
 */
static bool tunnel_html(http_buffer_t buff, tunnel_set_t tunnel_set)
{
    thread_lock(&tunnels_lock);
    for (size_t i = 0; i < tunnel_set->length; i++)
    {
        tunnel_t tunnel = tunnel_set->tunnels[i];;
        http_buffer_puts(buff, "<option style=\"background-color: ");
        switch (tunnel->state)
        {
            case TUNNEL_STATE_OPEN:
                http_buffer_puts(buff, "#aaffaa");
                break;
            case TUNNEL_STATE_OPENING:
                http_buffer_puts(buff, "#ffffaa");
                break;
            default:
                http_buffer_puts(buff, "#ffaaaa");
                break;
        }
        http_buffer_puts(buff, "\" title=\"Tunnel ");
        http_buffer_puts(buff, tunnel->url);
        http_buffer_puts(buff, " is ");
        switch (tunnel->state)
        {
            case TUNNEL_STATE_OPEN:
                http_buffer_puts(buff, "open");
                break;
            case TUNNEL_STATE_OPENING:
                http_buffer_puts(buff, "opening");
                break;
            default:
                http_buffer_puts(buff, "closed");
                if (!tunnel->enabled)
                {
                    http_buffer_puts(buff, " and disabled");
                }
                break;
        }
        http_buffer_puts(buff, ".\" value=\"");
        http_buffer_puts(buff, tunnel_set->tunnels[i]->url);
        http_buffer_puts(buff, "\">");
        http_buffer_puts(buff, tunnel_set->tunnels[i]->url);
        http_buffer_puts(buff, "</option>\n");
    }
    thread_unlock(&tunnels_lock);
    return true;
}

/*
 * Print all tunnels as HTML.
 */
bool tunnel_all_html(http_buffer_t buff)
{
    return tunnel_html(buff, &tunnels_cache);
}

/*
 * Add a tunnel to a tunnel_set_s.
 */
static void tunnel_set_insert(tunnel_set_t tunnel_set, tunnel_t tunnel)
{
    if (tunnel_set->length >= tunnel_set->size)
    {
        tunnel_set->size = (tunnel_set->size == 0? TUNNEL_SET_INIT_SIZE:
            tunnel_set->size*2);
        size_t alloc_size = tunnel_set->size * sizeof(tunnel_t);
        tunnel_set->tunnels = (tunnel_t *)realloc(tunnel_set->tunnels,
            alloc_size);
        if (tunnel_set->tunnels == NULL)
        {
            error("unable to reallocate " SIZE_T_FMT " bytes for tunnel set",
                alloc_size);
        }
    }
    tunnel_set->tunnels[tunnel_set->length++] = tunnel;
}

/*
 * Replace a tunnel in a tunnel_set_s.
 */
static tunnel_t tunnel_set_replace(tunnel_set_t tunnel_set, tunnel_t tunnel)
{
    for (size_t i = 0; i < tunnel_set->length; i++)
    {
        tunnel_t tunnel_old = tunnel_set->tunnels[i];
        if ((tunnel_old->state == TUNNEL_STATE_OPEN ||
             tunnel_old->state == TUNNEL_STATE_CLOSED) &&
            strcmp(tunnel_old->url, tunnel->url) == 0)
        {
            tunnel_set->tunnels[i] = tunnel;
            return tunnel_old;
        }
    }

    return NULL;
}

/*
 * Remove a tunnel from a tunnel_set_s.
 */
static tunnel_t tunnel_set_delete(tunnel_set_t tunnel_set, const char *url)
{
    for (size_t i = 0; i < tunnel_set->length; i++)
    {
        if (strcmp(tunnel_set->tunnels[i]->url, url) == 0)
        {
            tunnel_t tunnel = tunnel_set->tunnels[i];
            for (; i < tunnel_set->length-1; i++)
            {
                tunnel_set->tunnels[i] = tunnel_set->tunnels[i+1];
            }
            tunnel_set->length--;
            return tunnel;
        }
    }
    return NULL;
}

/*
 * Find a tunnel in a tunnel_set_s.
 */
static tunnel_t tunnel_set_lookup(tunnel_set_t tunnel_set, const char *url)
{
    for (size_t i = 0; i < tunnel_set->length; i++)
    {
        if (strcmp(tunnel_set->tunnels[i]->url, url) == 0)
        {
            return tunnel_set->tunnels[i];
        }
    }
    return NULL;
}

/*
 * Test if any tunnel is ready.
 */
static bool tunnel_set_ready(tunnel_set_t tunnel_set)
{
    for (size_t i = 0; i < tunnel_set->length; i++)
    {
        if (tunnel_set->tunnels[i]->state == TUNNEL_STATE_OPEN)
        {
            return true;
        }
    }
    return false;
}

/*
 * Initialise this module.
 */
void tunnel_init(void)
{
    thread_lock_init(&tunnels_lock);
    rng = random_init();
    http_register_callback("tunnels-all.html", tunnel_all_html);
    tunnel_flow_offset = random_uint64(rng);
}

/*
 * Tunnel file load.
 */
void tunnel_file_read(void)
{
    const char *filename = TUNNELS_FILENAME;
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        warning("unable to open tunnel cache file \"%s\" for reading; "
            "will use backup tunnel cache file \"%s\"", TUNNELS_FILENAME,
            TUNNELS_BAK_FILENAME);
        filename = TUNNELS_BAK_FILENAME;
        file = fopen(filename, "r");
        if (file == NULL)
        {
            warning("unable to open backup tunnel cache file \"%s\" for "
                "reading", filename);
            return;
        }
    }

    while (true)
    {
        char url[CKTP_MAX_URL_LENGTH+1];
        size_t i = 0;
        url[i] = getc(file);
        if (url[i] == EOF)
        {
            if (ferror(file))
            {
                warning("unable to read tunnel URL from file \"%s\"",
                    filename);
                break;
            }
            if (feof(file))
            {
                break;
            }
        }
        if (url[i] == '\n')
        {
            continue;
        }
        if (url[i] == '#')
        {
            char c;
            while ((c = getc(file)) != '\n' && c != EOF)
                ;
            continue;
        }
        while (url[i] != ' ' && i < CKTP_MAX_URL_LENGTH && !feof(file) &&
                !ferror(file))
        {
            i++;
            url[i] = getc(file);
        }
        if (i == 0 || url[i] != ' ')
        {
            warning("unable to read tunnel URL from file \"%s\"; expected "
                "1 or more URL characters followed by a space character",
                filename);
            break;
        }
        url[i] = '\0';

        unsigned age;
        if (fscanf(file, "%u", &age) != 1 || age > UINT8_MAX)
        {
            warning("unable to read age for tunnel %s from file \"%s\"",
                url, filename);
            break;
        }
        unsigned enabled;
        if (fscanf(file, "%u", &enabled) != 1 || enabled > 1)
        {
            warning("unable to read enaled status for tunnel %s from file "
                "\"%s\"", url, filename);
            break;
        }
        if (getc(file) != '\n')
        {
            warning("unable to read tunnel %s file from file \"%s\"; "
                "missing end-of-line character", url, filename);
            break;
        }

        tunnel_t tunnel = tunnel_create(url, (uint8_t)age, (enabled != 0));
        thread_lock(&tunnels_lock);
        tunnel_set_insert(&tunnels_cache, tunnel);
        thread_unlock(&tunnels_lock);
    }

    fclose(file);
}

/*
 * Tunnels file write.
 */
void tunnel_file_write(void)
{
    thread_lock(&tunnels_lock);
#ifdef WINDOWS
    remove(TUNNELS_BAK_FILENAME);
#endif
    if (rename(TUNNELS_FILENAME, TUNNELS_BAK_FILENAME) != 0)
    {
        warning("unable to backup old tunnel cache file \"%s\" to \"%s\"",
            TUNNELS_FILENAME, TUNNELS_BAK_FILENAME);
    }
    FILE *file = fopen(TUNNELS_TMP_FILENAME, "w");
    if (file == NULL)
    {
        warning("unable to open tunnel cache file \"%s\" for writing",
            TUNNELS_FILENAME);
        return;
    }

    fprintf(file, "# %s tunnel cache\n", PROGRAM_NAME_LONG);
    fputs("# AUTOMATICALLY GENERATED, DO NOT EDIT\n\n", file);
    for (size_t i = 0; i < tunnels_cache.length; i++)
    {
        tunnel_t tunnel = tunnels_cache.tunnels[i];
        if (tunnel->age != 0)
        {
            fprintf(file, "# AGE = %u, ENABLED = %s\n", tunnel->age,
                (tunnel->enabled? "true": "false"));
            fprintf(file, "%s %u %u\n\n", tunnel->url, tunnel->age,
                tunnel->enabled);
        }
    }
    fclose(file);

#ifdef WINDOWS
    remove(TUNNELS_FILENAME);   // For windows rename() bug.
#endif
    if (rename(TUNNELS_TMP_FILENAME, TUNNELS_FILENAME) != 0)
    {
        warning("unable to move temporary tunnel cache file \"%s\" to \"%s\"",
            TUNNELS_TMP_FILENAME, TUNNELS_FILENAME);
    }
    thread_unlock(&tunnels_lock);
}

/*
 * Initialise a tunnel.
 */
static tunnel_t tunnel_create(const char *url, uint8_t age, bool enabled)
{
    tunnel_t tunnel = (tunnel_t)malloc(sizeof(struct tunnel_s));
    if (tunnel == NULL)
    {
        error("unable to allocate " SIZE_T_FMT " bytes for tunnel data "
            "structure", sizeof(struct tunnel_s));
    }

    static uint16_t id = 0;
    tunnel->tunnel    = NULL;
    tunnel->age       = age;
    tunnel->state     = TUNNEL_STATE_CLOSED;
    tunnel->enabled   = enabled;
    tunnel->reconnect = false;
    tunnel->id        = id++;
    tunnel->weight    = 1.0;
    strncpy(tunnel->url, url, CKTP_MAX_URL_LENGTH);
    tunnel->url[CKTP_MAX_URL_LENGTH] = '\0';
    return tunnel;
}

/*
 * Close a tunnel.
 */
static void tunnel_free(tunnel_t tunnel)
{
    free(tunnel);
}

/*
 * Open (activate) some tunnels for use.
 */
void tunnel_open(void)
{
    thread_t thread1;
    thread_create(&thread1, tunnel_activate_manager, NULL);
    thread_t thread2;
    thread_create(&thread2, tunnel_reconnect_manager, NULL);
}

/*
 * Check if there is currently an active tunnel available or not.
 */
bool tunnel_ready(void)
{
    thread_lock(&tunnels_lock);
    bool result = tunnel_set_ready(&tunnels_cache);
    thread_unlock(&tunnels_lock);
    return result;
}

/*
 * Tunnel activator thread.
 */
static void *tunnel_activate_manager(void *unused)
{
    while (true)
    {
        // Attempt to open new tunnels.
        thread_lock(&tunnels_lock);
        size_t j = 0;
        for (size_t i = 0; i < tunnels_cache.length; i++)
        {
            tunnel_t tunnel = tunnels_cache.tunnels[i];
            if (tunnel->enabled && tunnel->state == TUNNEL_STATE_CLOSED)
            {
                j++;
                tunnel->state = TUNNEL_STATE_OPENING;
                thread_t thread;
                thread_create(&thread, tunnel_activate, (void *)tunnel);
            }
        }
        uint64_t stagger = random_uint64(rng);
        thread_unlock(&tunnels_lock);

        // Wait for some tunnels to open:
        sleeptime(150*SECONDS + (stagger % 10000) * MILLISECONDS);
    }

    return NULL;
}

/*
 * Queue a tunnel for use.
 */
static void *tunnel_activate(void *tunnel_ptr)
{
    tunnel_t tunnel = (tunnel_t)tunnel_ptr;
    tunnel_try_activate(tunnel, false);
    return NULL;
}

/*
 * Attempt to activate the given tunnel.
 */
#define MAX_RETRIES                 4
static state_t tunnel_try_activate(tunnel_t tunnel, bool reopen)
{
    const char *re = (reopen? "(re)": "");
    unsigned retries = MAX_RETRIES;
    cktp_tunnel_t ctunnel = NULL;
    thread_lock(&tunnels_lock);
    uint64_t stagger = (random_uint32(rng) % 1000) * MILLISECONDS;
    uint64_t retry_time_us = 10*SECONDS + stagger;
    tunnel->tunnel = NULL;
    const char *url = tunnel->url;
    while (tunnel->state == TUNNEL_STATE_OPENING)
    {
        thread_unlock(&tunnels_lock);
        log("attempting to %sopen tunnel %s", re, url);
        ctunnel = cktp_open_tunnel(url);
        thread_lock(&tunnels_lock);
        if (ctunnel != NULL)
        {
            break;
        }
        if (tunnel->state != TUNNEL_STATE_OPENING)
        {
            break;
        }
        retries--;
        if (retries == 0)
        {
            tunnel->state = TUNNEL_STATE_CLOSED;
            tunnel->enabled = false;
            thread_unlock(&tunnels_lock);
            log("unable to %sopen tunnel %s; giving up", re, url);
            return TUNNEL_STATE_CLOSED;
        }
        thread_unlock(&tunnels_lock);
        log("unable to %sopen tunnel %s; retrying in %.1f seconds", re, url,
            (double)retry_time_us / (double)SECONDS);
        sleeptime(retry_time_us);
        retry_time_us *= 6;
    }
    switch (tunnel->state)
    {
        case TUNNEL_STATE_OPENING:
            tunnel->tunnel = ctunnel;
            tunnel->state  = TUNNEL_STATE_OPEN;
            tunnel->age    = TUNNEL_INIT_AGE;
            thread_unlock(&tunnels_lock);
            log("successfully %sopened tunnel %s", re, url);
            return TUNNEL_STATE_OPEN;
        case TUNNEL_STATE_DELETING:
            tunnel->state = TUNNEL_STATE_DEAD;
            thread_unlock(&tunnels_lock);
            tunnel_free(tunnel);
            cktp_close_tunnel(ctunnel);
            return TUNNEL_STATE_DEAD;
        case TUNNEL_STATE_CLOSING:
            tunnel->state = TUNNEL_STATE_CLOSED;
            thread_unlock(&tunnels_lock);
            cktp_close_tunnel(ctunnel);
            return TUNNEL_STATE_CLOSED;
        default:
            panic("unexpected tunnel state %u", tunnel->state);
    }
}

/*
 * TCP flow hash function.
 */
static uint64_t tunnel_flow_hash(uint32_t daddr, uint16_t dest,
    uint16_t src)
{
    return (uint64_t)daddr * 3609501316222574897ull +
           (uint64_t)dest * 14072897357666528627ull +
           (uint64_t)src * 13265529554866849861ull +
           tunnel_flow_offset;
}

/*
 * Tunnel a packet.
 */
bool tunnel_packets(uint8_t *packet, uint8_t **packets, uint64_t hash,
    unsigned repeat, uint16_t config_mtu, bool config_multi)
{
    if (!config_multi)
    {
        struct iphdr *ip_header = NULL;
        struct tcphdr *tcp_header = NULL;
        packet_init(packet, true, NULL, &ip_header, NULL, &tcp_header, NULL,
            NULL, NULL, NULL);
        if (ip_header != NULL && tcp_header != NULL)
        {
            hash = tunnel_flow_hash(ip_header->daddr, tcp_header->dest,
                tcp_header->source);
        }
    }
 
    thread_lock(&tunnels_lock);

    // Select a tunnel for this packet:
    tunnel_t tunnel = tunnel_get(hash, repeat);
    if (tunnel == NULL)
    {
        thread_unlock(&tunnels_lock);
        warning("unable to tunnel packet (no suitable tunnel is open); "
            "the packet will be dropped");
        return false;
    }

    // Check if any tunneled packet is too big:
    uint16_t mtu = cktp_tunnel_get_mtu(tunnel->tunnel, config_mtu);
    if (mtu == 0)
    {
        return false;
    }
    bool fit = true;
    for (size_t i = 0; packets[i] != NULL; i++)
    {
        struct ethhdr *eth_header = (struct ethhdr *)packets[i];
        struct iphdr *ip_header = (struct iphdr *)(eth_header + 1);
        size_t tot_len = ntohs(ip_header->tot_len);
        fit = fit && (tot_len <= mtu);
        if (!fit)
        {
            log("unable tunnel packet of size " SIZE_T_FMT " bytes; maximum "
                "allowed packet size is %u bytes", tot_len, mtu);
        }
    }
    if (!fit)
    {
        cktp_fragmentation_required(tunnel->tunnel, mtu, packet);
        thread_unlock(&tunnels_lock);
        return true;
    }
    
    // Tunnel the packets:
    for (size_t i = 0; packets[i] != NULL; i++)
    {
        struct ethhdr *eth_header = (struct ethhdr *)packets[i];
        struct iphdr *ip_header = (struct iphdr *)(eth_header + 1);
        cktp_tunnel_packet(tunnel->tunnel, (uint8_t *)ip_header);
    }

    thread_unlock(&tunnels_lock);
    return true;
}

/*
 * Given a hash, return a tunnel to use.  Return NULL if none are avaiable.
 */
static tunnel_t tunnel_get(uint64_t hash, unsigned repeat)
{
    static struct tunnel_history_s tunnel_history[TUNNEL_HISTORY_SIZE];

    if (tunnels_cache.length == 0)
    {
        return NULL;
    }
    size_t hist_idx = (size_t)(hash % TUNNEL_HISTORY_SIZE);
    uint32_t hist_hash = (uint32_t)(hash ^ (hash >> 32));
    uint32_t weight_hash = hist_hash * (repeat + 1);
    double total_weight = 0.0;
    for (size_t i = 0; i < tunnels_cache.length; i++)
    {
        if (tunnels_cache.tunnels[i]->state == TUNNEL_STATE_OPEN)
        {
            total_weight += tunnels_cache.tunnels[i]->weight;
        }
    }
    double pick = ((double)weight_hash / (double)UINT32_MAX) * total_weight;

    size_t idx;
    for (idx = 0; idx < tunnels_cache.length &&
            pick >= tunnels_cache.tunnels[idx]->weight; idx++)
    {
        if (tunnels_cache.tunnels[idx]->state == TUNNEL_STATE_OPEN)
        {
            pick -= tunnels_cache.tunnels[idx]->weight;
        }
    }
    tunnel_t tunnel = tunnels_cache.tunnels[idx];

    if (repeat != 0)
    {
        // This packet has been repeated.  This can be for many reasons,
        // but here we factor in the possibility that the tunnel is down, or
        // congested.  We adjust weights to make it less likely the last
        // selected tunnel will be chosen again in the future.
        tunnel_t bad_tunnel = NULL;
        if (tunnel_history[hist_idx].hash == hist_hash)
        {
            // Punish the tunnel that failed to send the packet:
            for (size_t i = 0; i < tunnels_cache.length; i++)
            {
                if (tunnels_cache.tunnels[i]->id ==
                        tunnel_history[hist_idx].id)
                {
                    bad_tunnel = tunnels_cache.tunnels[i];
                    pick -= bad_tunnel->weight;
                    bad_tunnel->weight = bad_tunnel->weight * 0.75;
                    bad_tunnel->weight = (bad_tunnel->weight < 0.005?
                        0.005: bad_tunnel->weight);
                    break;
                }
            }
        }
    }

    // Assume success -- adjust weight accordingly
    tunnel->weight = tunnel->weight + 0.15 * tunnel->weight;
    tunnel->weight = (tunnel->weight > 1.0? 1.0: tunnel->weight);

    // Record this packet into the tunnel history:
    tunnel_history[hist_idx].hash = hist_hash;
    tunnel_history[hist_idx].id   = tunnel->id;

    return tunnel;
}

/*
 * Open a tunnel URL.
 */
void tunnel_open_url(const char *url)
{
    // First check if the URL is syntactically valid:
    if (!cktp_parse_url(url, NULL, NULL, NULL, NULL))
    {
        return;
    }

    thread_lock(&tunnels_lock);
    tunnel_t tunnel = tunnel_set_lookup(&tunnels_cache, url);
    if (tunnel == NULL)
    {
        tunnel = tunnel_create(url, TUNNEL_INIT_AGE, true);
        tunnel_set_insert(&tunnels_cache, tunnel);
    }
    else
    {
        tunnel->enabled = true;
        switch (tunnel->state)
        {
            case TUNNEL_STATE_OPEN:
            case TUNNEL_STATE_OPENING:
                thread_unlock(&tunnels_lock);
                warning("unable to open tunnel %s; tunnel is already open or "
                    "opening", url);
                return;
            case TUNNEL_STATE_CLOSING:
            case TUNNEL_STATE_DELETING:
                tunnel->state = TUNNEL_STATE_OPENING;
                thread_unlock(&tunnels_lock);
                return;
        }
    }
    tunnel->state = TUNNEL_STATE_OPENING;
    thread_unlock(&tunnels_lock);
    thread_t thread;
    thread_create(&thread, tunnel_activate, (void *)tunnel);
    tunnel_file_write();
}

/*
 * Close a tunnel URL.
 */
void tunnel_close_url(const char *url)
{
    cktp_tunnel_t ctunnel = NULL;
    thread_lock(&tunnels_lock);
    tunnel_t tunnel = tunnel_set_lookup(&tunnels_cache, url);
    if (tunnel != NULL)
    {
        switch (tunnel->state)
        {
            case TUNNEL_STATE_OPEN:
                ctunnel = tunnel->tunnel;
                tunnel->tunnel = NULL;
                tunnel->state = TUNNEL_STATE_CLOSED;
                break;
            case TUNNEL_STATE_OPENING:
                tunnel->state = TUNNEL_STATE_CLOSING;
                break;
            default:
                break;
        }
        tunnel->enabled = false;
    }
    thread_unlock(&tunnels_lock);
    if (ctunnel != NULL)
    {
        cktp_close_tunnel(ctunnel);
    }
    log("closed tunnel %s", url);
    tunnel_file_write();
}

/*
 * Delete a tunnel URL.
 */
void tunnel_delete_url(const char *url)
{
    cktp_tunnel_t ctunnel = NULL;
    thread_lock(&tunnels_lock);
    tunnel_t tunnel = tunnel_set_delete(&tunnels_cache, url);
    if (tunnel != NULL)
    {
        switch (tunnel->state)
        {
            case TUNNEL_STATE_OPEN:
                ctunnel = tunnel->tunnel;
                tunnel->tunnel = NULL;
                tunnel->state = TUNNEL_STATE_DEAD;
                break;
            case TUNNEL_STATE_OPENING:
            case TUNNEL_STATE_CLOSING:
                tunnel->state = TUNNEL_STATE_DELETING;
                break;
            default:
                break;
        }
    }
    thread_unlock(&tunnels_lock);
    if (ctunnel != NULL)
    {
        cktp_close_tunnel(ctunnel);
        tunnel_free(tunnel);
    }
    log("deleted tunnel %s", url);
    tunnel_file_write();
}

/*
 * Reconnection manager.
 */
static void *tunnel_reconnect_manager(void *unused)
{
    // This is the simplest possible algorithm: continiously poll each tunnel
    // to see if it needs to reconnect.  We could implement something more
    // sophisticated here -- however that's a lot of implementation effort for
    // almost no benefit.  This loop will consume very little CPU time.
    while (true)
    {
        thread_lock(&tunnels_lock);
        uint64_t stagger = (random_uint32(rng) % 1000) * MILLISECONDS;
        thread_unlock(&tunnels_lock);
        sleeptime(1*SECONDS + stagger);
        thread_lock(&tunnels_lock);
        uint64_t currtime = gettime();
        for (size_t i = 0; i < tunnels_cache.length; i++)
        {
            tunnel_t tunnel = tunnels_cache.tunnels[i];
            
            // tunnel->reconnect ensures we only try to reconnect once.
            if (tunnel->state == TUNNEL_STATE_OPEN &&
                !tunnel->reconnect &&
                cktp_tunnel_timeout(tunnel->tunnel, currtime))
            {
                tunnel->reconnect = true;
                char *url = strdup(tunnel->url);
                thread_t thread;
                thread_create(&thread, tunnel_reconnect, (void *)url);
            }
        }
        thread_unlock(&tunnels_lock);
    }

    return NULL;
}

/*
 * Reconnect the tunnel.
 */
static void *tunnel_reconnect(void *url_ptr)
{
    // Attempt to reconnect to the given URL.  This basically works by
    // creating a completely new tunnel instance, and then replacing the
    // old instance.

    char *url = (char *)url_ptr;
    tunnel_t tunnel = tunnel_create(url, TUNNEL_INIT_AGE, true);
    tunnel->state = TUNNEL_STATE_OPENING;
    state_t state = tunnel_try_activate(tunnel, true);
    if (state == TUNNEL_STATE_OPEN)
    {
        // Success, replace the old tunnel with the new version:
        thread_lock(&tunnels_lock);
        tunnel_t replaced_tunnel = tunnel_set_replace(&tunnels_cache, tunnel);
        if (replaced_tunnel != NULL)
        {
            switch (replaced_tunnel->state)
            {
                case TUNNEL_STATE_CLOSED:
                    tunnel->state = replaced_tunnel->state;
                    replaced_tunnel->tunnel = tunnel->tunnel;
                    tunnel->tunnel = NULL;
                    // Fallthrough
                case TUNNEL_STATE_OPEN:
                    thread_unlock(&tunnels_lock);
                    cktp_close_tunnel(replaced_tunnel->tunnel);
                    replaced_tunnel->tunnel = NULL;
                    replaced_tunnel->state = TUNNEL_STATE_DEAD;
                    tunnel_free(replaced_tunnel);
                    break;
                default:
                    panic("unexpected tunnel state %u", tunnel->state);
            }
            thread_unlock(&tunnels_lock);
            free(url);
            return NULL;
        }
        else
        {
            // Old tunnel must be in an *ING state, meaning that the state
            // was changed by the user.  If so, we can ignore the reopened
            // tunnel.
            cktp_tunnel_t ctunnel = tunnel->tunnel;
            tunnel->tunnel = NULL;
            tunnel->state  = TUNNEL_STATE_DEAD;
            thread_unlock(&tunnels_lock);
            warning("unable to (re)open tunnel %s; tunnel state was changed",
                url);
            cktp_close_tunnel(ctunnel);
            tunnel_free(tunnel);
            free(url);
            return NULL;
        }
    }
    else
    {
        // Failure, we could not (re)open the tunnel.  We assume the tunnel
        // is now dead, so deactivate it here.
        warning("unable to (re)open tunnel %s; tunnel will now be closed",
            url);
        tunnel_close_url(url);
        tunnel->state = TUNNEL_STATE_DEAD;
        tunnel_free(tunnel);
        free(url);
        return NULL;
    }
}

