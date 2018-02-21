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

#include <windows.h>

typedef HANDLE thread_t;
typedef HANDLE mutex_t;

static inline int thread_create(thread_t *thread, void *(*start)(void *),
    void *arg)
{
    *thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)start, (LPVOID)arg,
        0, NULL);
    if (*thread != NULL)
    {
        CloseHandle(*thread);
    }
    return (*thread == NULL? -1: 0);
}

static inline int thread_lock_init(mutex_t *lock)
{
    *lock = CreateMutex(NULL, FALSE, NULL);
    return (*lock == NULL? -1: 0);
}

static inline int thread_lock_free(mutex_t *lock)
{
    return (CloseHandle(*lock)? 0: -1);
}

static inline int thread_lock(mutex_t *lock)
{
    DWORD result = WaitForSingleObject(*lock, INFINITE);
    return (result == WAIT_OBJECT_0? 0: -1);
}

static inline int thread_unlock(mutex_t *lock)
{
    return (ReleaseMutex(*lock)? 0: -1);
}

#endif          /* __THREAD_H */
