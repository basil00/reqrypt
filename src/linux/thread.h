/*
 * thread.h
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
#ifndef __THREAD_H
#define __THREAD_H

#include <pthread.h>

typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;

static inline int thread_create(thread_t *thread, void *(*start)(void *),
    void *arg)
{
    int result = pthread_create(thread, NULL, start, arg);
    if (result == 0)
    {
        result = pthread_detach(*thread);
    }
    return result;
}

static inline int thread_lock_init(mutex_t *lock)
{
    return pthread_mutex_init(lock, NULL);
}

static inline int thread_lock_free(mutex_t *lock)
{
    return pthread_mutex_destroy(lock);
}

static inline int thread_lock(mutex_t *lock)
{
    return pthread_mutex_lock(lock);
}

static inline int thread_unlock(mutex_t *lock)
{
    return pthread_mutex_unlock(lock);
}

#endif      /* __THREAD_H */
