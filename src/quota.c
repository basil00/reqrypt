/*
 * quota.c
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
#include <stdlib.h>
#include <string.h>

#include "cookie.h"
#include "cktp_encoding.h"
#include "misc.h"
#include "quota.h"
#include "thread.h"

/*
 * Quota structure:
 */
struct quota_s
{
    random_state_t rng;             // RNG
    struct cookie_gen_s salt;       // Salt for hashing
    mutex_t  lock;                  // Lock
    uint32_t rps;                   // Requests-per-second
    uint32_t timemin;               // Reset time min (ms)
    uint32_t timemax;               // Reset time max (ms)
    uint64_t starttime;             // Start time
    uint64_t totaltime;             // Total time until reset
    uint64_t maxcount;              // Maximum count
    uint16_t countssize;            // Counts size
    uint64_t counts[];              // Counts
};

/*
 * Prototypes.
 */
static uint64_t quota_hash(quota_t quota, uint32_t *ip, size_t ipsize);
extern void error(const char *message, ...);

/*
 * Create and initialise a quota_t.
 */
quota_t quota_init(uint32_t timemin, uint32_t timemax,
    uint16_t numcounts, uint32_t rps)
{
    size_t quota_size = sizeof(struct quota_s) + numcounts*sizeof(uint64_t);
    quota_t quota = (quota_t)malloc(quota_size);
    if (quota == NULL)
    {
        error("unable to allocation %zu bytes for quota tracker", quota_size);
        exit(EXIT_FAILURE);
    }
    memset(quota, 0, quota_size);
    if (thread_lock_init(&quota->lock) != 0)
    {
        error("unable to initialise lock for quota tracker");
        exit(EXIT_FAILURE);
    }
    uint64_t currtime = gettime()/1000;
    quota->rng = random_init();
    quota->timemin = timemin;
    quota->timemax = timemax;
    quota->countssize = numcounts;
    quota->starttime = currtime;
    quota->totaltime = 0;               // Ensure reset.
    quota->rps = rps;
    quota->maxcount = 0;

    debug_log = fopen("/tmp/quota.DEBUG", "a");
    if (debug_log == NULL)
        debug_log = stderr;

    return quota;
}

/*
 * Free a quota_t.
 */
void quota_free(quota_t quota)
{
    thread_lock_free(&quota->lock);
    free(quota);
}

/*
 * Check if we should accept the request or not.
 */
bool quota_check(quota_t quota, uint32_t *ip, size_t ipsize, uint16_t delta)
{
    uint64_t currtime = gettime()/1000;
    uint64_t usedtime = currtime - quota->starttime;
    uint64_t hash = quota_hash(quota, ip, ipsize);
    size_t idx = hash % quota->countssize;

    thread_lock(&quota->lock);
    if (usedtime >= quota->totaltime)
    {
        uint64_t r64 = random_uint64(quota->rng);
        uint64_t resettime = currtime +
            r64 % (quota->timemax - quota->timemin) + quota->timemin;
        quota->starttime = currtime;
        quota->totaltime = resettime - quota->starttime;
        quota->maxcount = (quota->rps * quota->totaltime) / 1000 + 1;
        random_memory(quota->rng, &quota->salt, sizeof(quota->salt));
        memset(quota->counts, 0x0, quota->countssize*sizeof(uint64_t));
    }

    uint64_t count = quota->counts[idx];
    uint64_t starttime = quota->starttime;
    uint64_t resettime = quota->starttime + quota->totaltime;
    uint64_t maxcount  = quota->maxcount;
    uint64_t totaltime = quota->totaltime;
    if (count <= maxcount / 4)
    {
        quota->counts[idx] += delta;
        thread_unlock(&quota->lock);
        return true;
    }
    if (count > maxcount)
    {
        thread_unlock(&quota->lock);
        return false;
    }

    uint64_t difftime = currtime - starttime;
    difftime += (difftime == 0? 1: 0);
    uint64_t remtime = resettime - currtime;
    remtime += (remtime == 0? 1: 0);

    // rate = current rate
    double rate      = (double)count / (double)difftime;
    double projected = rate * (double)totaltime;
    if (projected <= (double)maxcount)
    {
        quota->counts[idx] += delta;
        thread_unlock(&quota->lock);
        return true;
    }

    // rate2 = max allowable rate to stay below maxcount
    double rate2 = (double)(maxcount - count) / (double)remtime;
    if (rate2 >= rate)
    {
        quota->counts[idx] += delta;
        thread_unlock(&quota->lock);
        return true;
    }
    double ratio = rate2 / rate;
    if (ratio < 1.0 / (double)UINT8_MAX)
    {
        thread_unlock(&quota->lock);
        return false;
    }

    // Probablistic throttle:
    uint8_t r8 = random_uint8(quota->rng);
    bool allow = (double)r8 < ((double)UINT8_MAX * ratio);
    if (allow)
        quota->counts[idx] += delta;
    thread_unlock(&quota->lock);
    
    return allow;
}

/*
 * Compute the hash value.
 */
static uint64_t quota_hash(quota_t quota, uint32_t *ip, size_t ipsize)
{
    return generate_cookie64(&quota->salt, ip, ipsize / sizeof(uint32_t));
}

