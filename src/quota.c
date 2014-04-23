/*
 * quota.c
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

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cookie.h"
#include "cktp_encoding.h"
#include "quota.h"
#include "thread.h"

/*
 * Quota structure:
 */
struct quota_s
{
    struct cookie_gen_s salt;       // Salt for hashing
    mutex_t  lock;                  // Lock for resets
    uint32_t rps;                   // Requests-per-second
    uint32_t timemin;               // Reset time min (ms)
    uint32_t timemax;               // Reset time max (ms)
    uint64_t starttime;             // Start time
    uint64_t resettime;             // Reset time
    uint16_t countssize;            // Counts size
    uint16_t counts[];              // Counts
};

/*
 * Prototypes.
 */
static uint16_t quota_hash(quota_t quota, uint32_t *ip, size_t ipsize);
extern void error(const char *message, ...);

/*
 * Create and initialise a quota_t.
 */
quota_t quota_init(cktp_enc_lib_t lib, uint32_t timemin, uint32_t timemax,
    uint16_t numcounts, uint32_t rps)
{
    size_t quota_size = sizeof(struct quota_s) + numcounts*sizeof(uint16_t);
    quota_t quota = (quota_t)malloc(quota_size);
    if (quota == NULL)
    {
        error("unable to allocation %zu bytes for quota tracker", quota_size);
        exit(EXIT_FAILURE);
    }
    if (thread_lock_init(&quota->lock) != 0)
    {
        error("unable to initialise lock for quota tracker");
        exit(EXIT_FAILURE);
    }
    quota->timemin = timemin;
    quota->timemax = timemax;
    quota->countssize = numcounts;
    quota->resettime = lib->gettime()-1;    // Ensure reset.
    quota->rps = (rps * 1024) / 1000;       // Redefine second = 1024ms
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
 * true = accept
 * false = reject
 */
bool quota_check(quota_t quota, cktp_enc_lib_t lib, random_state_t rng,
    uint32_t *ip, size_t ipsize)
{
    uint64_t currtime = lib->gettime();
    if (currtime > quota->resettime)
    {
        // We only implement partial thread safety for speed.
        // Worst case the wrong counter will be updated
        uint64_t r64;
        lib->random(rng, &r64, sizeof(r64));
        thread_lock(&quota->lock);
        quota->resettime = currtime + r64 % (quota->timemax - quota->timemin)
            + quota->timemin;
        quota->starttime = currtime;
        thread_unlock(&quota->lock);
        lib->random(rng, &quota->salt, sizeof(quota->salt));
        memset(quota->counts, 0x0, quota->countssize*sizeof(uint16_t));
    }

    uint16_t hash = quota_hash(quota, ip, ipsize);
    uint16_t count = quota->counts[hash];
    if (count == 0)
    {
        quota->counts[hash] = 1;
        return true;
    }
    else
    {
        uint64_t difftime = currtime - quota->starttime;
        uint64_t totaltime = quota->resettime - quota->starttime;
        uint64_t limit = ((quota->rps - 1) * difftime) / 1024 +
            totaltime / 1024 + 1;
        if (count <= limit)
        {
            quota->counts[hash]++;
            return true;
        }
        else
        {
            return false;
        }
    }
}

/*
 * Compute the hash value.
 */
static uint16_t quota_hash(quota_t quota, uint32_t *ip, size_t ipsize)
{
    return generate_cookie16(&quota->salt, ip, sizeof(ip)) % quota->countssize;
}

