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

/*
 * The name of the packet capture device I/O interface.
 */
#define CAPTURE_DEV_NAME    "\\\\.\\\\" PROGRAM_NAME_LONG "Device"

/*
 * Packet capture device handle.
 */
HANDLE handle = INVALID_HANDLE_VALUE;

/*
 * Initialises the packet capture device.
 */
void init_capture(void)
{
    handle = CreateFile(CAPTURE_DEV_NAME, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, INVALID_HANDLE_VALUE);

    if (handle == INVALID_HANDLE_VALUE)
    {
        error("failed to open packet capture driver \"%s\"",
            CAPTURE_DEV_NAME);
    }
}

/*
 * Get a captured packet.
 */
size_t get_packet(uint8_t *buff, size_t len)
{
    DWORD read_len;
    if (!ReadFile(handle, buff, len, &read_len, NULL))
    {
        warning("failed to read packet from packet capture device");
        return 0;
    }
    return (unsigned)read_len;
}

/*
 * Re-inject a captured packet.
 */
void inject_packet(uint8_t *buff, size_t len)
{
    DWORD write_len;
    if (!WriteFile(handle, buff, len, &write_len, NULL) ||
        len != write_len)
    {
        warning("failed to inject packet of size " SIZE_T_FMT, len);
    }
}

