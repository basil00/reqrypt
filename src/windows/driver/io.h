/*
 * io.h
 * (C) 2009, all rights reserved,
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

#ifndef __IO_H
#define __IO_H

#include "queue.h"

/*
 * Presentation of a queued packet.
 */
struct packet_s
{
    uint16_t length;
    /*
     * Packet data immediately follows this structure.
     */
};

/*
 * The device states.
 */
#define DEVICE_INIT         0
#define DEVICE_CLOSED       1
#define DEVICE_OPEN         2
#define DEVICE_CLOSING      3
typedef uint8_t dev_state_t;

/*
 * The context structure for I/O operations.
 */
struct context_s
{
    NDIS_SPIN_LOCK lock;

    /*
     * This device's state.
     */
    dev_state_t state;

    /*
     * The packet queue.
     */
    struct queue_s packet_queue;

    /*
     * I/O requests.
     */
    struct queue_s pending_reads;

    /*
     * Pools.
     */
    NDIS_HANDLE buffer_pool;
    NDIS_HANDLE packet_pool;

    /*
     * Device object handle.
     */
    NDIS_HANDLE dev_handle;
};

/*
 * The global context object.
 */
extern struct context_s context;

/*
 * Helper macros.
 */
#define get_handle()        (&context)
#define is_handle(handle)   ((struct context_s *)(handle) == get_handle())

/*
 * Declare dispatch routines.
 */
__drv_dispatchType(IRP_MJ_READ)    DRIVER_DISPATCH read_packet;
__drv_dispatchType(IRP_MJ_WRITE)   DRIVER_DISPATCH write_packet;
__drv_dispatchType(IRP_MJ_CREATE)  DRIVER_DISPATCH open_packets;
__drv_dispatchType(IRP_MJ_CLOSE)   DRIVER_DISPATCH close_packets;
__drv_dispatchType(IRP_MJ_CLEANUP) DRIVER_DISPATCH cleanup_packets;

/*
 * Prototypes.
 */
NTSTATUS create_packets_dev(IN NDIS_HANDLE wrapper_handle);
void cleanup_packets_dev(void);
NTSTATUS read_packet(IN PDEVICE_OBJECT p_dev, IN PIRP p_irp);
NTSTATUS write_packet(IN PDEVICE_OBJECT dev, IN PIRP p_irp);
void write_packet_complete(IN PNDIS_PACKET packet, IN NDIS_STATUS status);
void queue_packet(IN PNDIS_PACKET packet);
NTSTATUS open_packets(IN PDEVICE_OBJECT dev, IN PIRP p_irp);
NTSTATUS close_packets(IN PDEVICE_OBJECT dev, IN PIRP p_irp);
NTSTATUS cleanup_packets(IN PDEVICE_OBJECT dev, IN PIRP p_irp);
PNDIS_PACKET copy_packet(IN PNDIS_PACKET packet);
void free_packet(IN PNDIS_PACKET packet);
bool should_capture_packet(IN PNDIS_PACKET packet);
void get_adapter_address(IN PNDIS_PACKET packet, uint8_t *address);

#endif      /* __IO_H */
