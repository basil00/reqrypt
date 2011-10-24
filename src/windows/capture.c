/*
 * capture.c
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

#include <windows.h>

#include "capture.h"
#include "cfg.h"
#include "log.h"

#define UINT8   unsigned char
#define UINT16  unsigned short
#include "divert.h"

/*
 * Divert device handle.
 */
HANDLE handle = INVALID_HANDLE_VALUE;

/*
 * Initialises the packet capture device.
 */
void init_capture(void)
{
    handle = DivertOpen(
        "outbound and "
        "ip and "
        "(tcp.DstPort == 80 or udp.DstPort == 53) and "
        "ip.DstAddr != 127.0.0.1"
    );
    if (handle == INVALID_HANDLE_VALUE)
    {
        error("unable to open divert packet capture handle");
    }
}

/*
 * Get a captured packet.
 */
size_t get_packet(uint8_t *buff, size_t len)
{
    UINT read_len;
    if (!DivertRecv(handle, (PVOID)buff, (UINT)len, NULL, &read_len))
    {
        warning("unable to read packet from divert packet capture handle");
        return 0;
    }
    return (size_t)read_len;
}

/*
 * Re-inject a captured packet.
 */
void inject_packet(uint8_t *buff, size_t len)
{
    DIVERT_ADDRESS addr = {0};
    UINT write_len;
    if (!DivertSend(handle, (PVOID)buff, (UINT)len, &write_len, NULL) ||
        (UINT)len != write_len)
    {
        warning("unable to inject packet of size " SIZE_T_FMT " to "
            "divert packet capture handle", len);
    }
}

