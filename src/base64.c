/*
 * base64.c
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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"

/*
 * Read 8-bits.
 */
static uint8_t read_bits(const uint8_t *data, size_t idx)
{
    size_t idx_base = idx / 8;
    size_t idx_off  = idx % 8;
    return 0x3F & 
        ((data[idx_base] >> idx_off) | (data[idx_base+1] << (8 - idx_off)));
}

/*
 * Write 8-bits.
 */
static void write_bits(uint8_t *data, size_t idx, uint8_t val)
{
    size_t idx_base = idx / 8;
    size_t idx_off  = idx % 8;
    data[idx_base] = (data[idx_base] & (0xFF >> (8 - idx_off))) |
        (val << idx_off);
    data[idx_base+1] = val >> (8 - idx_off);
}

/*
 * Convert a 6-bit number to a base64 digit.
 */
static char base64_todigit(uint8_t val)
{
    val &= 0x3F;
    if (val < 10)
    {
        return val + '0';
    }
    val -= 10;
    if (val < 26)
    {
        return val + 'a';
    }
    val -= 26;
    if (val < 26)
    {
        return val + 'A';
    }
    val -= 26;
    if (val == 0)
    {
        return '-';
    }
    if (val == 1)
    {
        return '=';
    }
    return EOF;
}

/*
 * Convert a base64 digit to a 6-bit integer.
 */
static uint8_t base64_fromdigit(char dig)
{
    if (dig >= '0' && dig <= '9')
    {
        return dig - '0';
    }
    if (dig >= 'a' && dig <= 'z')
    {
        return dig - 'a' + 10;
    }
    if (dig >= 'A' && dig <= 'Z')
    {
        return dig - 'A' + 10 + 26;
    }
    if (dig == '-')
    {
        return 0x3E;
    }
    if (dig == '=')
    {
        return 0x3F;
    }
    return (uint8_t)EOF;
}

/*
 * Encode data as base64.
 */
size_t base64_encode(const uint8_t *in, size_t insize, char *out)
{
    size_t outsize = (insize*8 - 1) / 6 + 1;
    for (size_t i = 0; i < outsize; i++)
    {
        uint8_t val = read_bits(in, 6 * i);
        out[i] = base64_todigit(val);
    }
    return outsize;
}

/*
 * Decode base64 data.
 */
size_t base64_decode(const char *in, size_t insize, uint8_t *out)
{
    for (size_t i = 0; i < insize; i++)
    {
        uint8_t val = base64_fromdigit(in[i]);
        if (val == (uint8_t)EOF)
        {
            return (size_t)-1;
        }
        write_bits(out, i*6, val);
    }
    return (6*insize - 1) / 8 + 1;
}

