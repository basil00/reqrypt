/*
 * natural.c
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

/*
 * Relatively simple big-natural number implementation.
 * We could use a big-int library (e.g. GMP) but that would introduce another
 * dependency.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "natural.h"

#define N_RADIX             (0x0100000000000000UL)
#define N_RADIX_MASK        (0x00FFFFFFFFFFFFFFUL)
#define N_RADIX_SHIFT       56
#define N_RADIX_SIZE        (N_RADIX_SHIFT/8)
#define N_RADIX_FORMAT      "%.14lX"

/*
 * Prototypes.
 */
static void N_mul(N_t a, N_t b, N_t c);
static void N_mod(N_t a, N_t b, N_t c);
static int N_cmp(N_t a, N_t b, unsigned a_bits, unsigned b_bits);
static unsigned N_shift_right(N_t a, unsigned a_bits, unsigned shift);
static unsigned N_shift_left(N_t a, unsigned a_bits, unsigned shift);
static void N_sub(N_t n, unsigned n_bits, N_t d);
static unsigned N_bits(N_t a, unsigned bits);
// static void N_print(N_t a, size_t size);

/*
 * Setup an N_t
 */
void N_set(const uint8_t *data, size_t size, N_t a)
{
    size_t extra = size % N_RADIX_SIZE;
    size_t last = size / N_RADIX_SIZE;
    for (size_t i = 0; i < last; i++)
    {
        a[i] = (*(N *)(data + i * N_RADIX_SIZE)) & N_RADIX_MASK;
    }
    if (last < N_SIZE)
    {
        a[last] = 0;
    }
    if (extra)
    {
        memmove(a + last, data + last * N_RADIX_SIZE, extra);
    }
    for (size_t i = last + 1; i < N_SIZE; i++)
    {
        a[i] = 0;
    }
}

/*
 * Get from an N_t
 */
void N_get(uint8_t *data, size_t size, N_t a)
{
    for (size_t i = 0; i < N_SIZE; i++)
    {
        N digit = a[i];
        for (size_t j = 0; size > 0 && j < N_RADIX_SIZE; size--, j++)
        {
            *data++ = (uint8_t)digit;
            digit >>= 8;
        }
    }
}

/*
 * c := a * b
 */
#define N_MUL_RADIX_SHIFT       (N_RADIX_SHIFT / 2)
#define N_MUL_RADIX_MASK        (N_RADIX_MASK >> N_MUL_RADIX_SHIFT)
static void N_mul(N_t a, N_t b, N_t c)
{
    N am[2*N_SIZE], bm[2*N_SIZE], cm[4*N_SIZE];
    memset(cm, 0x0, sizeof(cm));

    for (unsigned i = 0; i < N_SIZE; i++)
    {
        am[2*i]   = a[i] & N_MUL_RADIX_MASK;
        am[2*i+1] = (a[i] >> N_MUL_RADIX_SHIFT) & N_MUL_RADIX_MASK;
        bm[2*i]   = b[i] & N_MUL_RADIX_MASK;
        bm[2*i+1] = (b[i] >> N_MUL_RADIX_SHIFT) & N_MUL_RADIX_MASK;
    }
    
    for (unsigned i = 0; i < 2*N_SIZE; i++)
    {
        for (unsigned j = 0; j < 2*N_SIZE; j++)
        {
            cm[i+j] += am[i] * bm[j];
        }

        // Normalise:
        for (unsigned j = 0; j < 2*N_SIZE-1; j++)
        {
            cm[i+j+1] += (cm[i+j] >> N_MUL_RADIX_SHIFT);
            cm[i+j] &= N_MUL_RADIX_MASK;
        }
        if (i+2*N_SIZE < 4*N_SIZE)
        {
            cm[i+2*N_SIZE] += (cm[i+2*N_SIZE-1] >> N_MUL_RADIX_SHIFT);
        }
        cm[i+2*N_SIZE-1] &= N_MUL_RADIX_MASK;
    }

    for (unsigned i = 0; i < 2*N_SIZE; i++)
    {
        c[i] = cm[2*i] | (cm[2*i+1] << N_MUL_RADIX_SHIFT);
    }
}

/*
 * r = b^e % m
 */
void N_modexp(N_t b, N_t e, N_t m, N_t r)
{
    N a[2*N_SIZE];
    memmove(a, b, N_SIZE*sizeof(N));
    memset(a + N_SIZE, 0x0, N_SIZE*sizeof(N));

    N t[2*N_SIZE];
    memset(t+1, 0x0, (2*N_SIZE-1)*sizeof(N));
    t[0] = 1;

    unsigned e_bits = N_bits(e, N_SIZE*N_RADIX_SHIFT);
    for (unsigned i = 0; i < e_bits; )
    {
        N w = e[i / N_RADIX_SHIFT];
        for (unsigned j = 0; i < e_bits && j < N_RADIX_SHIFT; i++, j++)
        {
            N u[2*N_SIZE];
            if (w & 1)
            {
                N_mul(t, a, u);
                N_mod(u, m, t);
            }
            N_mul(a, a, u);
            N_mod(u, m, a);
            w >>= 1;
        }
    }
    memmove(r, t, N_SIZE*sizeof(N));
}

/*
 * c := a % b
 */
static void N_mod(N_t a, N_t b, N_t c)
{
    N n[2*N_SIZE];
    memmove(n, a, 2*N_SIZE*sizeof(N));

    N d[2*N_SIZE];
    memset(d, 0x0, N_SIZE*sizeof(N));
    memmove(d + N_SIZE, b, N_SIZE*sizeof(N));

    unsigned n_bits = N_bits(n, 2*N_SIZE*N_RADIX_SHIFT);
    unsigned d_bits = N_bits(d, 2*N_SIZE*N_RADIX_SHIFT);
    unsigned b_bits = N_bits(b, N_SIZE*N_RADIX_SHIFT);

    if (d_bits < n_bits)
    {
        d_bits = N_shift_left(d, d_bits, n_bits - d_bits);
    }

    while (N_cmp(n, b, n_bits, b_bits) > 0)
    {
        if (d_bits > n_bits)
        {
            d_bits = N_shift_right(d, d_bits, d_bits - n_bits);
        }
        if (N_cmp(d, n, d_bits, n_bits) > 0)
        {
            d_bits = N_shift_right(d, d_bits, 1);
        }
        N_sub(n, n_bits, d);
        n_bits = N_bits(n, n_bits);
    }
    memmove(c, n, N_SIZE*sizeof(N));
}

/*
 * a := a >> s
 */
static unsigned N_shift_right(N_t a, unsigned a_bits, unsigned shift)
{
    if (shift == 0)
    {
        return a_bits;
    }
    unsigned a_size_old = (a_bits - 1) / N_RADIX_SHIFT + 1;
    a_bits -= shift;
    unsigned a_size = (a_bits - 1) / N_RADIX_SHIFT + 1;
    unsigned shift_index  = shift / N_RADIX_SHIFT;
    unsigned shift_offset = shift % N_RADIX_SHIFT;
    unsigned i;

    for (i = 0; i < a_size-1; i++)
    {
        a[i] = a[i + shift_index] >> shift_offset;
        a[i] |= (a[i + shift_index + 1] << (N_RADIX_SHIFT - shift_offset)) &
            N_RADIX_MASK;
    }
    a[i] = a[i + shift_index] >> shift_offset;
    if (i + shift_index + 1 < 2*N_SIZE)
    {
        a[i] |= (a[i + shift_index + 1] << (N_RADIX_SHIFT - shift_offset)) &
            N_RADIX_MASK;
    }
    for (unsigned j = 0; j < a_size_old - a_size; j++)
    {
        a[i + j + 1] = 0;
    }
    return a_bits;
}

/*
 * a := a << s
 */
static unsigned N_shift_left(N_t a, unsigned a_bits, unsigned shift)
{
    if (shift == 0)
    {
        return a_bits;
    }
    a_bits += shift;
    unsigned a_size = (a_bits - 1) / N_RADIX_SHIFT + 1;
    unsigned shift_index  = shift / N_RADIX_SHIFT;
    unsigned shift_offset = shift % N_RADIX_SHIFT;

    int i = (int)a_size - 1;
    for (; i - shift_index >= 1; i--)
    {
        a[i] = (a[i - shift_index] << shift_offset) & N_RADIX_MASK;
        a[i] |= a[i - shift_index - 1] >> (N_RADIX_SHIFT - shift_offset);
    }
    a[i] = (a[i - shift_index] << shift_offset) & N_RADIX_MASK;
    for (i--; i >= 0; i-- )
    {
        a[i] = 0;
    }

    return a_bits;
}

/*
 * n := n - d;
 */
static void N_sub(N_t n, unsigned n_bits, N_t d)
{
    unsigned n_size = (n_bits - 1) / N_RADIX_SHIFT + 1;
    for (unsigned i = 0; i < n_size; i++)
    {
        n[i] -= d[i];
    }
    for (unsigned i = 0; i < n_size-1; i++)
    {
        int64_t carry = (int64_t)n[i] >> N_RADIX_SHIFT;
        n[i+1] = (int64_t)n[i+1] + carry;
        n[i] &= N_RADIX_MASK;
    }
    n[n_size-1] &= N_RADIX_MASK;
}

/*
 * True if a is within [2..b-2]
 */
bool N_lt2(N_t a, N_t b)
{
    // Decrement b.
    N t[N_SIZE];
    bool carry = true;
    for (size_t i = 0; i < N_SIZE; i++)
    {
        if (carry)
        {
            if (b[i] == 0)
            {
                t[i] = N_RADIX_MASK;
            }
            else
            {
                t[i] = b[i] - 1;
                carry = false;
            }
        }
        else
        {
            t[i] = b[i];
        }
    }
    unsigned a_bits = N_bits(a, N_SIZE*N_RADIX_SHIFT);
    unsigned t_bits = N_bits(t, N_SIZE*N_RADIX_SHIFT);
    if (N_cmp(a, t, a_bits, t_bits) >= 0)
    {
        return false;
    }
    if (a_bits > 2)
    {
        return true;
    }
    return (a[0] == 0x03);
}

/*
 * True if a != 1
 */
bool N_neq1(N_t a)
{
    unsigned a_bits = N_bits(a, N_SIZE*N_RADIX_SHIFT);
    return (a_bits != 1);
}

/*
 * Compare a and b.
 */
static int N_cmp(N_t a, N_t b, unsigned a_bits, unsigned b_bits)
{
    if (a_bits > b_bits)
    {
        return 1;
    }
    if (a_bits < b_bits)
    {
        return -1;
    }

    int end_idx = (a_bits - 1) / N_RADIX_SHIFT;
    for (int i = end_idx; i >= 0; i--)
    {
        if (a[i] > b[i])
        {
            return 1;
        }
        if (a[i] < b[i])
        {
            return -1;
        }
    }
    return 0;
}

/*
 * Count how many bits are in the given number.  The initial 'bits' is an
 * upper bound.
 */
static unsigned N_bits(N_t a, unsigned bits)
{
    int size = (bits - 1) / N_RADIX_SHIFT + 1;
    bits = (unsigned)size * N_RADIX_SHIFT;
    for (int i = size-1; i >= 0; i--)
    {
        N ai = a[i];
        if (ai == 0)
        {
            bits -= N_RADIX_SHIFT;
            continue;
        }
        unsigned j = 0;
        for (; ai != 0; j++)
        {
            ai >>= 1;
        }
        return bits - (N_RADIX_SHIFT - j);
    }
    return 0;
}

#if 0
/*
 * Printing function for debugging purposes.
 */
static void N_print(N_t a, size_t size)
{
    fputs("0x", stdout);
    bool start = true;
    for (int i = size-1; i >= 0; i--)
    {
        if (a[i] == 0 && start)
        {
            continue;
        }
        start = false;
        printf(N_RADIX_FORMAT, (uint64_t)a[i]);
    }
    if (start)
    {
        putchar('0');
    }
}
#endif

