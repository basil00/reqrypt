/*
 * queue.c
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

#include "queue.h"

static void queue_init(struct queue_s *Q)
{
    Q->first = 0;
    Q->last  = 0;
}

static bool queue_empty(struct queue_s *Q)
{
    return Q->first == Q->last;
}

static bool queue_full(struct queue_s *Q)
{
    return Q->first == (Q->last + 1) % QUEUE_MAX;
}

static void queue_push(struct queue_s *Q, PVOID elem)
{
    if (!queue_full(Q))
    {
        Q->entries[Q->last] = elem;
        Q->last = (Q->last + 1) % QUEUE_MAX;
    }
}

static PVOID queue_pop(struct queue_s *Q)
{
    PVOID elem;
    if (queue_empty(Q))
    {
        return NULL;
    }
    elem = Q->entries[Q->first];
    Q->first = (Q->first + 1) % QUEUE_MAX;
    return elem;
}

static uint16_t queue_length(struct queue_s *Q)
{
    uint16_t min = Q->first;
    uint16_t max = Q->last;
    if (max < min)
    {
        max += QUEUE_MAX;
    }
    return max - min;
}

static PVOID queue_get(struct queue_s *Q, uint16_t idx)
{
    if (idx >= queue_length(Q))
    {
        return NULL;
    }
    idx = (idx + Q->first) % QUEUE_MAX;
    return Q->entries[idx];
}

static void queue_del(struct queue_s *Q, uint16_t idx)
{
    uint16_t i;

    for (i = idx; i < queue_length(Q); i++)
    {
        Q->entries[(Q->first + i) % QUEUE_MAX] =
            Q->entries[(Q->first + i + 1) % QUEUE_MAX];
    }
    Q->last = (Q->last == 0? QUEUE_MAX-1: Q->last - 1);
}

