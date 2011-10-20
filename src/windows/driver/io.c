/*
 * io.c
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

/*
 * This module implements our "packets" device.  In a nutshell:
 * - The IM driver captures packets of interest, e.g. outbound HTTP (port 80)
 *   data packets, and queues a copy of the packet here.
 * - The user application can read queued packets from the device implemented
 *   by this module.
 * - The user application can write new packets from the device implemented 
 *   by this module.  The written packets are sent straight to the
 *   corresponding adapter.  This is so the user application can re-inject
 *   (potentially modified versions) of the captured packets.
 * - For simplicity, the "packets" driver is a singleton -- it can only be
 *   opened once.
 */

#include "precomp.h"

#include "queue.c"

#define BUFFER_POOL_MAX     512
#define PACKET_POOL_MIN     32
#define PACKET_POOL_MAX     512

/*
 * The global context object.
 */
struct context_s context = {0};

/*
 * Prototypes.
 */
DRIVER_CANCEL read_packet_cancel;
DRIVER_CANCEL write_packet_cancel;
void read_packet_cancel(IN PDEVICE_OBJECT dev, IN PIRP p_irp);
void read_packet_service(void);
void write_packet_cancel(IN PDEVICE_OBJECT dev, IN PIRP p_irp);
void get_packet_data(IN PNDIS_PACKET packet, uint8_t *ptr, unsigned size,
    unsigned offset);

/*
 * Dispatch routine to handle IRP_MJ_READ.
 */
NTSTATUS read_packet(IN PDEVICE_OBJECT dev, IN PIRP p_irp)
{
    PIO_STACK_LOCATION p_irp_sp;
    NTSTATUS status = STATUS_PENDING;

    UNREFERENCED_PARAMETER(dev);

    p_irp_sp = IoGetCurrentIrpStackLocation(p_irp);

    /*
     * Sanity checking.
     */
    if (!is_handle(p_irp_sp->FileObject->FsContext))
    {
        status = STATUS_INVALID_HANDLE;
        goto read_packet_exit;
    }
    if (p_irp->MdlAddress == NULL)
    {
        status = STATUS_INVALID_PARAMETER;
        goto read_packet_exit;
    }

    /*
     * Get the virtual address of the MDL.
     */
    if (MmGetSystemAddressForMdlSafe(p_irp->MdlAddress, NormalPagePriority)
        == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto read_packet_exit;
    }

    /*
     * Check if the context is open.
     */
    NdisAcquireSpinLock(&context.lock);
    if (context.state != DEVICE_OPEN)
    {
        NdisReleaseSpinLock(&context.lock);
        status = STATUS_INVALID_HANDLE;
        goto read_packet_exit;
    }

    /*
     * Check if the read queue is full.
     */
    if (queue_full(&context.pending_reads))
    {
        NdisReleaseSpinLock(&context.lock);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto read_packet_exit;
    }

    /*
     * Record the pending read.
     */
    queue_push(&context.pending_reads, p_irp);
    
    /*
     * Set up the read cancel.
     * Note: this must be done when we hold context.lock.
     */
    IoMarkIrpPending(p_irp);
    IoSetCancelRoutine(p_irp, read_packet_cancel);

    NdisReleaseSpinLock(&context.lock);
    
    /*
     * Service the read requests.
     */
    read_packet_service();

read_packet_exit:
    
    if (status != STATUS_PENDING)
    {
        /*
         * An error -- complete the request.
         */
        p_irp->IoStatus.Information = 0;
        p_irp->IoStatus.Status = status;
        IoCompleteRequest(p_irp, IO_NO_INCREMENT);
    }

    return status;
}

/*
 * Cancel a pending read packet IRP.
 */
void read_packet_cancel(IN PDEVICE_OBJECT dev, IN PIRP p_irp)
{
    uint16_t i;

    UNREFERENCED_PARAMETER(dev);

    IoReleaseCancelSpinLock(p_irp->CancelIrql);

    /*
     * Find and remove the pending request from 'context'
     */
    NdisAcquireSpinLock(&context.lock);
    if (context.state != DEVICE_CLOSED)
    {
        for (i = 0; i < queue_length(&context.pending_reads); i++)
        {
            if (queue_get(&context.pending_reads, i) == p_irp)
            {
                queue_del(&context.pending_reads, i);
                break;
            }
        }
    }
    NdisReleaseSpinLock(&context.lock);

    /*
     * Complete the IRP.
     */
    p_irp->IoStatus.Information = 0;
    p_irp->IoStatus.Status = STATUS_CANCELLED;
    IoCompleteRequest(p_irp, IO_NO_INCREMENT);
}

/*
 * Service any outstanding read packet requests.
 */
void read_packet_service(void)
{
    NdisAcquireSpinLock(&context.lock);
    while (context.state == DEVICE_OPEN &&
           !queue_empty(&context.pending_reads) &&
           !queue_empty(&context.packet_queue))
    {
        /*
         * Find an IRP that is not being canceled.
         */
        bool found = false;
        PIRP p_irp = NULL;
        while (!queue_empty(&context.pending_reads))
        {
            p_irp = queue_pop(&context.pending_reads);
            if (p_irp != NULL &&
                IoSetCancelRoutine(p_irp, NULL) != NULL)
            {
                found = true;
                break;
            }
        }
        
        if (!found)
        {
            /*
             * All IRPs are being cancelled.
             */
            break;
        }

        /*
         * Get the first queued packet and copy it to the destination.
         */
        {
            struct packet_s *packet;
            PVOID src, dst;
            ULONG src_size, dst_size, move_size;

            packet = (struct packet_s *)queue_pop(&context.packet_queue);
            NdisReleaseSpinLock(&context.lock);
            src = (PVOID)(packet + 1);
            src_size = packet->length;
            dst = MmGetSystemAddressForMdlSafe(p_irp->MdlAddress,
                NormalPagePriority);
            dst_size = MmGetMdlByteCount(p_irp->MdlAddress);

            /*
             * Copy the packet contents to the destination.
             */
            move_size = (dst_size < src_size? dst_size: src_size);
            NdisMoveMemory(dst, src, move_size);
            NdisFreeMemory((PVOID)packet, 0, 0);

            /*
             * Complete the IRP.
             */
            p_irp->IoStatus.Status = STATUS_SUCCESS;
            p_irp->IoStatus.Information = move_size;
            IoCompleteRequest(p_irp, IO_NO_INCREMENT);
        }

        NdisAcquireSpinLock(&context.lock);
    }
    NdisReleaseSpinLock(&context.lock);
}

/*
 * Queue a packet.
 * Note: assumes the packet has been allocated by copy_packet.
 */
void queue_packet(IN PNDIS_PACKET packet)
{
    NDIS_STATUS alloc_status;
    struct packet_s *new_packet;
    uint8_t *new_packet_data;
    UINT new_packet_size;

    /*
     * Check if the device is still open.  If not, then simply ignore the queue
     * request.
     */
    NdisAcquireSpinLock(&context.lock);
    if (context.state != DEVICE_OPEN)
    {
        NdisReleaseSpinLock(&context.lock);
        return;
    }

    /*
     * Check if the packet queue is full.  If so, then drop the oldest packet.
     */
    if (queue_full(&context.packet_queue))
    {
        PVOID old_packet = queue_pop(&context.packet_queue);
        NdisFreeMemory(old_packet, 0, 0);
    }
    NdisReleaseSpinLock(&context.lock);

    /*
     * Create the packet_s structure for the (copy of) the new packet.
     */
    NdisQueryPacketLength(packet, &new_packet_size);
    alloc_status = NdisAllocateMemoryWithTag(&new_packet,
        new_packet_size + sizeof(struct packet_s), 0);
    if (alloc_status != NDIS_STATUS_SUCCESS)
    {
        NdisReleaseSpinLock(&context.lock);
        return;
    }
    new_packet->length = (uint16_t)new_packet_size;
    new_packet_data = (uint8_t *)(new_packet + 1);
    get_packet_data(packet, new_packet_data, new_packet_size, 0);

    /*
     * Add the packet to the queue.
     */
    NdisAcquireSpinLock(&context.lock);
    if (context.state != DEVICE_OPEN)
    {
        NdisReleaseSpinLock(&context.lock);
        NdisFreeMemory((PVOID)new_packet, 0, 0);
        return;
    }
    queue_push(&context.packet_queue, new_packet);
    NdisReleaseSpinLock(&context.lock);

    /*
     * Service any pending reads now that we have the new packet.
     */
    read_packet_service();
}

/*
 * Dispatch routine to handle IRP_MJ_WRITE.
 */
NTSTATUS write_packet(IN PDEVICE_OBJECT dev, IN PIRP p_irp)
{
    PIO_STACK_LOCATION p_irp_sp;
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    unsigned packet_len;
    PADAPT adapter;
    NTSTATUS status;
    size_t i;

    UNREFERENCED_PARAMETER(dev);

    p_irp_sp = IoGetCurrentIrpStackLocation(p_irp);

    /*
     * Sanity checking.
     */
    status = STATUS_SUCCESS;
    if (!is_handle(p_irp_sp->FileObject->FsContext))
    {
        status = STATUS_INVALID_HANDLE;
        goto write_packet_exit;
    }
    if (p_irp->MdlAddress == NULL)
    {
        status = STATUS_INVALID_PARAMETER;
        goto write_packet_exit;
    }
    eth_header = 
        (struct ethhdr *)MmGetSystemAddressForMdlSafe(p_irp->MdlAddress,
            NormalPagePriority);
    if (eth_header == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto write_packet_exit;
    }
    packet_len = MmGetMdlByteCount(p_irp->MdlAddress);
    if (packet_len < sizeof(struct ethhdr) + sizeof(struct iphdr))
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto write_packet_exit;
    }
    if (ntohs(eth_header->h_proto) != ETH_P_IP)
    {
        status = STATUS_INVALID_PARAMETER;
        goto write_packet_exit;
    }
    ip_header = (struct iphdr *)(eth_header + 1);
    if (ip_header->version != 4)
    {
        status = STATUS_INVALID_PARAMETER;
        goto write_packet_exit;
    }
    
    /*
     * Find the adapter to send the packet based on address.
     */
    NdisAcquireSpinLock(&driver_lock);
    adapter = NULL;
    for (i = 0; i < adapters_size && adapters[i] != NULL; i++)
    {
        if (adapters[i]->address_valid &&
            eth_header->h_source[0] == adapters[i]->address[0] &&
            eth_header->h_source[1] == adapters[i]->address[1] &&
            eth_header->h_source[2] == adapters[i]->address[2] &&
            eth_header->h_source[3] == adapters[i]->address[3] &&
            eth_header->h_source[4] == adapters[i]->address[4] &&
            eth_header->h_source[5] == adapters[i]->address[5])
        {
            adapter = adapters[i];
            break;
        }
    }
    NdisReleaseSpinLock(&driver_lock);
    if (adapter == NULL)
    {
        /*
         * Could not find the apater to send the packet.
         */
        status = STATUS_INVALID_PARAMETER;
        goto write_packet_exit;
    }

    /*
     * Check that we are in an open state.  We do this here (instead of above)
     * so that we don't lock context twice.
     */
    NdisAcquireSpinLock(&context.lock);
    if (context.state != DEVICE_OPEN)
    {
        NdisReleaseSpinLock(&context.lock);
        status = STATUS_INVALID_HANDLE;
        goto write_packet_exit;
    }

    /*
     * Create a NDIS packet and copy the data to it.
     */
    {
        uint8_t *src = MmGetSystemAddressForMdlSafe(p_irp->MdlAddress,
            NormalPagePriority);
        size_t src_size = MmGetMdlByteCount(p_irp->MdlAddress);
        uint8_t *data;
        PNDIS_BUFFER buffer;
        PNDIS_PACKET packet;
        NDIS_STATUS alloc_status;

        alloc_status = NdisAllocateMemoryWithTag(&data, src_size, 0);
        if (alloc_status != NDIS_STATUS_SUCCESS)
        {
            NdisReleaseSpinLock(&context.lock);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto write_packet_exit;
        }
        NdisMoveMemory(data, src, src_size);

        NdisAllocateBuffer(&alloc_status, &buffer, context.buffer_pool, data,
            src_size);
        if (alloc_status != NDIS_STATUS_SUCCESS)
        {
            NdisReleaseSpinLock(&context.lock);
            NdisFreeMemory(data, 0, 0);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto write_packet_exit;
        }

        NdisAllocatePacket(&alloc_status, &packet, context.packet_pool);
        NdisReleaseSpinLock(&context.lock);
        if (status != NDIS_STATUS_SUCCESS)
        {
            NdisFreeBuffer(buffer);
            NdisFreeMemory(data, 0, 0);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto write_packet_exit;
        }

        NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
        NdisChainBufferAtFront(packet, buffer);

        /*
         * Send the packet:
         */
        NdisInterlockedIncrement(&adapter->pending_sends);
        NdisSend(&status, adapter->binding_handle, packet);
        if (status != NDIS_STATUS_PENDING)
        {
            free_packet(packet);
            NdisInterlockedDecrement(&adapter->pending_sends);
        }
        else
        {
            status = STATUS_SUCCESS;
        }
    }

write_packet_exit:

    if (status == STATUS_SUCCESS)
    {
        p_irp->IoStatus.Information = MmGetMdlByteCount(p_irp->MdlAddress);
    }
    else
    {
        p_irp->IoStatus.Information = 0;
    }
    p_irp->IoStatus.Status = status;
    IoCompleteRequest(p_irp, IO_NO_INCREMENT);

    return status;
}

/*
 * Called when the sending of a I/O packet has finished.
 */
void write_packet_complete(IN PNDIS_PACKET packet, IN NDIS_STATUS status)
{
    UNREFERENCED_PARAMETER(status);
    free_packet(packet);
}

/*
 * Dispatch routine for IRP_MJ_CREATE.
 */
NTSTATUS open_packets(IN PDEVICE_OBJECT dev, IN PIRP p_irp)
{
    PIO_STACK_LOCATION p_irp_sp = IoGetCurrentIrpStackLocation(p_irp);
    NTSTATUS status = STATUS_SUCCESS;
    NDIS_STATUS alloc_status;

    UNREFERENCED_PARAMETER(dev);

    NdisAcquireSpinLock(&context.lock);

    /*
     * Check if the device is closed.  Only one instance of the device can
     * exist at any given time.
     */
    if (context.state != DEVICE_CLOSED)
    {
        NdisReleaseSpinLock(&context.lock);
        status = STATUS_DEVICE_BUSY;
        goto open_packets_exit;
    }

    context.state = DEVICE_OPEN;
    queue_init(&context.packet_queue);
    queue_init(&context.pending_reads);
    NdisAllocateBufferPool(&alloc_status, &context.buffer_pool,
        BUFFER_POOL_MAX);
    /*
     * Allocate the packet pool.
     * Note: since this is only used for packets sent to lower adapters, and
     *       not protocol drivers, then ProtocolReservedLength can be 0.
     */
    NdisAllocatePacketPoolEx(&alloc_status, &context.packet_pool,
        PACKET_POOL_MIN, PACKET_POOL_MAX - PACKET_POOL_MIN, 0);

    NdisReleaseSpinLock(&context.lock);
    p_irp_sp->FileObject->FsContext = get_handle();

open_packets_exit:

    p_irp->IoStatus.Information = 0;
    p_irp->IoStatus.Status = status;
    IoCompleteRequest(p_irp, IO_NO_INCREMENT);

    return status;
}

/*
 * Dispatch routine for IRP_MJ_CLOSE.
 */
NTSTATUS close_packets(IN PDEVICE_OBJECT dev, IN PIRP p_irp)
{
    PIO_STACK_LOCATION p_irp_sp = IoGetCurrentIrpStackLocation(p_irp);
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(dev);
    
    if (!is_handle(p_irp_sp->FileObject->FsContext))
    {
        status = STATUS_INVALID_HANDLE;
        goto close_packets_exit;
    }

    /*
     * Complete the closing and free any resources used.
     */
    NdisAcquireSpinLock(&context.lock);
    if (context.state != DEVICE_CLOSING)
    {
        NdisReleaseSpinLock(&context.lock);
        status = STATUS_INVALID_HANDLE;
        goto close_packets_exit;
    }
    NdisFreeBufferPool(context.buffer_pool);
    NdisFreePacketPool(context.packet_pool);
    context.state = DEVICE_CLOSED;
    NdisReleaseSpinLock(&context.lock);

close_packets_exit:
    
    p_irp->IoStatus.Information = 0;
    p_irp->IoStatus.Status = status;
    IoCompleteRequest(p_irp, IO_NO_INCREMENT);

    return status;
}

/*
 * Dispatch routine for IRP_MJ_CLEANUP.
 */
NTSTATUS cleanup_packets(IN PDEVICE_OBJECT dev, IN PIRP p_irp)
{
    PIO_STACK_LOCATION p_irp_sp = IoGetCurrentIrpStackLocation(p_irp);
    NTSTATUS status = STATUS_SUCCESS;
 
    UNREFERENCED_PARAMETER(dev);

    if (!is_handle(p_irp_sp->FileObject->FsContext))
    {
        status = STATUS_INVALID_HANDLE;
        goto cleanup_packets_exit;
    }

    NdisAcquireSpinLock(&context.lock);

    /*
     * Check and update the device's state.
     */
    if (context.state != DEVICE_OPEN)
    {
        NdisReleaseSpinLock(&context.lock);
        status = STATUS_INVALID_HANDLE;
        goto cleanup_packets_exit;
    }
    context.state = DEVICE_CLOSING;

    /*
     * Cancel all pending reads.
     */
    while (!queue_empty(&context.pending_reads))
    {
        PIRP p_irp = queue_pop(&context.pending_reads);
        /*
         * If the read is not already being canceled, then cancel it now.
         */
        if (IoSetCancelRoutine(p_irp, NULL) != NULL)
        {
            NdisReleaseSpinLock(&context.lock);
            p_irp->IoStatus.Information = 0;
            p_irp->IoStatus.Status = STATUS_CANCELLED;
            IoCompleteRequest(p_irp, IO_NO_INCREMENT);
            NdisAcquireSpinLock(&context.lock);
        }
    }

    /*
     * Free all packets in the queue.
     * Note: a better approach may be to send the packets to their respective
     *       adapters rather than essentially dropping them.
     */
    while (!queue_empty(&context.packet_queue))
    {
        PVOID packet = queue_pop(&context.packet_queue);
        NdisFreeMemory(packet, 0, 0);
    }

    NdisReleaseSpinLock(&context.lock);

cleanup_packets_exit:

    p_irp->IoStatus.Information = 0;
    p_irp->IoStatus.Status = status;
    IoCompleteRequest(p_irp, IO_NO_INCREMENT);

    return status;
}

/*
 * Initialise the packets device.
 */
NTSTATUS create_packets_dev(IN NDIS_HANDLE wrapper_handle)
{
    PDEVICE_OBJECT dev;
    UNICODE_STRING dev_name, dos_dev_name;
    NTSTATUS status;
//    NDIS_STATUS alloc_status;
    PDRIVER_DISPATCH dispatch[IRP_MJ_MAXIMUM_FUNCTION+1];

    /*
     * Check if the device has already been created.  If so, do nothing.
     */
    if (context.state != DEVICE_INIT)
    {
        return NDIS_STATUS_SUCCESS;
    }

    NdisInitUnicodeString(&dev_name, DRIVER_DEVICE);
    NdisInitUnicodeString(&dos_dev_name, DRIVER_DOS_DEVICE);

    NdisZeroMemory(dispatch,
        (IRP_MJ_MAXIMUM_FUNCTION+1)*sizeof(PDRIVER_DISPATCH));

    dispatch[IRP_MJ_CREATE]  = open_packets;
    dispatch[IRP_MJ_CLOSE]   = close_packets;
    dispatch[IRP_MJ_CLEANUP] = cleanup_packets;
    dispatch[IRP_MJ_READ]    = read_packet;
    dispatch[IRP_MJ_WRITE]   = write_packet;

    status = NdisMRegisterDevice(wrapper_handle, &dev_name, &dos_dev_name,
        &dispatch[0], &dev, &context.dev_handle);
    
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    dev->Flags |= DO_DIRECT_IO;

    /*
     * Initialise the global context structure.
     */
    NdisAllocateSpinLock(&context.lock);
    context.state = DEVICE_CLOSED;

    return STATUS_SUCCESS;
}

/*
 * Cleanup the packets device object.
 */
void cleanup_packets_dev(void)
{
    if (context.dev_handle != NULL)
    {
        NdisMDeregisterDevice(context.dev_handle);
        context.dev_handle = NULL;
    }
}

/*
 * Free a packet allocated by copy_packet.
 */
void free_packet(IN PNDIS_PACKET packet)
{
    PNDIS_BUFFER buffer;
    unsigned total_len, buffer_len;
    uint8_t *data;
    
    NdisGetFirstBufferFromPacketSafe(packet, &buffer, &data, &buffer_len,
        &total_len, NormalPagePriority);
    NdisFreeMemory(data, 0, 0);
    NdisFreeBuffer(buffer);
    NdisFreePacket(packet);
}

/*
 * Decides whether or not the packet should be captured.
 */
bool should_capture_packet(IN PNDIS_PACKET packet)
{
    unsigned total_len;
    struct ethhdr eth_header;
    struct iphdr ip_header;
    unsigned ip_header_size;
    uint8_t b;

    /*
     * Note: we don't bother locking context because the worst that will
     * happen is that packets will be incorrectly queued and/or not queued.
     */
    if (context.state != DEVICE_OPEN)
    {
        return false;
    }

    NdisQueryPacketLength(packet, &total_len);

    if (total_len < sizeof(struct ethhdr) + sizeof(struct iphdr))
    {
        return false;
    }

    get_packet_data(packet, (uint8_t *)&eth_header, sizeof(struct ethhdr), 0);
    if (ntohs(eth_header.h_proto) != ETH_P_IP)
    {
        return false;
    }

    get_packet_data(packet, (uint8_t *)&ip_header, sizeof(struct iphdr),
        sizeof(struct ethhdr));
    if (ip_header.version != 4)
    {
        return false;
    }

    ip_header_size = sizeof(struct ethhdr) + ip_header.ihl*sizeof(uint32_t);
    switch (ip_header.protocol)
    {
        case IPPROTO_TCP:
        {
            struct tcphdr tcp_header;
            if (total_len < ip_header_size + sizeof(struct tcphdr))
            {
                return false;
            }

            get_packet_data(packet, (uint8_t *)&tcp_header,
                sizeof(struct tcphdr), ip_header_size);
            if (tcp_header.dest != htons(80))
            {
                return false;
            }
            break;
        }
        case IPPROTO_UDP:
        {
            struct udphdr udp_header;
            if (total_len < ip_header_size + sizeof(struct udphdr) +
                sizeof(struct dnshdr))
            {
                return false;
            }

            get_packet_data(packet, (uint8_t *)&udp_header,
                sizeof(struct udphdr), ip_header_size);
            if (udp_header.dest != htons(53))
            {
                return false;
            }
            break;
        }
        default:
            return false;
    }

    /*
     * Check for special IP addresses.
     */
    b = (uint8_t)ip_header.daddr;
    switch (b)
    {
        case 0:
            /*
             * Current Network: RFC 1700
             */
            return false;
        case 10:
            /*
             * Private Network: RFC 1918
             */
            return false;
        case 127:
            /*
             * Loopback: RFC 3330
             */
            return false;
        case 172:
            b = (uint8_t)(ip_header.daddr >> 8);
            if ((b >= 16) && (b <= 31))
            {
                /*
                 * Private Network: RFC 1918
                 */
                return false;
            }
            break;
        case 192:
            b = (uint8_t)(ip_header.daddr >> 8);
            if (b == 168)
            {
                /*
                 * Private Network: RFC 1918
                 */
                return false;
            }
            break;
    }

    /*
     * All passed!
     */
    return true;
}

/*
 * Get the adapter ethernet address.
 */
void get_adapter_address(IN PNDIS_PACKET packet, uint8_t *address)
{
    struct ethhdr eth_header;
    get_packet_data(packet, (uint8_t *)&eth_header, sizeof(struct ethhdr), 0);
    NdisMoveMemory((PVOID)address, eth_header.h_source, 6);
}

/*
 * Reads data from an NDIS packet structure.
 */
void get_packet_data(IN PNDIS_PACKET packet, uint8_t *ptr, unsigned size,
    unsigned offset)
{
    PNDIS_BUFFER buffer;
    PVOID data;
    UINT data_len, remain_len, copy_len;

    NdisQueryPacket(packet, NULL, NULL, &buffer, NULL);

    while (true)
    {
        NdisQueryBuffer(buffer, &data, &data_len);

        buffer = buffer->Next;
        if (offset < data_len)
        {
            break;
        }
        offset -= data_len;
    }

    while (true)
    {
        remain_len = data_len - offset;
        copy_len = (size > remain_len? remain_len: size);
        NdisMoveMemory((PVOID)ptr, (PVOID)((uint8_t *)data + offset),
            copy_len);
        size -= copy_len;
        ptr += copy_len;
        offset = 0;
        if (size == 0)
        {
            break;
        }
        if (buffer == NULL)
        {
            break;
        }
        NdisQueryBuffer(buffer, &data, &data_len);
        buffer = buffer->Next;
    }
}

