/*
 * miniport.c
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

#include "precomp.h"
#pragma hdrstop

/*
 * Current set of open adapters.
 */
PADAPT adapters[MAX_ADAPTERS] = {NULL};
size_t adapters_size = 0;

/*
 * Miniport initialisation handler.
 */
NDIS_STATUS miniport_initialize(OUT PNDIS_STATUS status,
    OUT PUINT idx, IN PNDIS_MEDIUM mediums, IN UINT mediums_size,
    IN NDIS_HANDLE miniport_handle, IN NDIS_HANDLE config_context)
{
    PADAPT adapter = NdisIMGetDeviceContext(miniport_handle);
    UNREFERENCED_PARAMETER(config_context);
    
    adapter->halted = false;

    {
        // As per the MS samples, export NdisMediumWan as NdisMedium802_3.
        NDIS_MEDIUM medium = (adapter->medium == NdisMediumWan?
            NdisMedium802_3: adapter->medium);
        UINT i;
        for (i = 0; i < mediums_size && medium != mediums[i]; i++)
            ;
        if (i >= mediums_size)
        {
            *status = NDIS_STATUS_UNSUPPORTED_MEDIA;
            goto initialise_exit;
        }
        *idx = i;
    }

    // Set up attributes as per MS driver sample.
    NdisMSetAttributesEx(miniport_handle, adapter, 0,
        NDIS_ATTRIBUTE_IGNORE_PACKET_TIMEOUT |
        NDIS_ATTRIBUTE_IGNORE_REQUEST_TIMEOUT |
        NDIS_ATTRIBUTE_INTERMEDIATE_DRIVER |
        NDIS_ATTRIBUTE_DESERIALIZE |
        NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND, 0);
    adapter->miniport_handle = miniport_handle;
    adapter->last_indicated_status = NDIS_STATUS_MEDIA_CONNECT;
    adapter->miniport_state = NdisDeviceStateD0;
    adapter->protocol_state = NdisDeviceStateD0;
    
    NdisAcquireSpinLock(&driver_lock);
    if (adapters_size < MAX_ADAPTERS)
    {
        adapters[adapters_size++] = adapter;
    }
    NdisReleaseSpinLock(&driver_lock);
    
    *status = NDIS_STATUS_SUCCESS;

initialise_exit:

    adapter->init = false;
    NdisSetEvent(&adapter->init_event);
    if (*status == NDIS_STATUS_SUCCESS)
    {
        reference_adapter(adapter);
    }

    return *status;
}

/*
 * Send packets handler.
 */
VOID miniport_send_packets(IN NDIS_HANDLE adapter_context,
    IN PPNDIS_PACKET packets, IN UINT packets_size)
{
    PADAPT adapter = (PADAPT)adapter_context;
    NDIS_STATUS status;
    UINT i;
   
    NdisAcquireSpinLock(&adapter->lock); 
    if (adapter->miniport_state > NdisDeviceStateD0 ||
        adapter->protocol_state > NdisDeviceStateD0)
    {
        NdisReleaseSpinLock(&adapter->lock);
        // Low power state; fail all send requests.
        for (i = 0; i < packets_size; i++)
        {
            NdisMSendComplete(adapter->miniport_handle, packets[i],
                NDIS_STATUS_FAILURE);
        }
        return;
    }
    NdisReleaseSpinLock(&adapter->lock);

    for (i = 0; i < packets_size; i++)
    {
        BOOLEAN stacks_remain;

        // Capture the packet if need be.
        if (should_capture_packet(packets[i]))
        {
            if (!adapter->address_valid)
            {
                NdisAcquireSpinLock(&adapter->lock);
                adapter->address_valid = true;
                get_adapter_address(packets[i], adapter->address);
                NdisReleaseSpinLock(&adapter->lock);
            }
            queue_packet(packets[i]);
            NdisMSendComplete(adapter->miniport_handle, packets[i],
                NDIS_STATUS_SUCCESS);
            continue;
        }

        NdisIMGetCurrentPacketStack(packets[i], &stacks_remain);
        if (stacks_remain == TRUE)
        {
            // NDIS 5.1 packet stacking:
            NdisInterlockedIncrement(&adapter->pending_sends);
            NdisSend(&status, adapter->binding_handle, packets[i]);
            if (status != NDIS_STATUS_PENDING)
            {
                NdisInterlockedDecrement(&adapter->pending_sends);
            }
        }
        else
        {
            // NDIS 5.0 packet repackaging:
            PNDIS_PACKET new_packet;
            PSEND_RSVD send_info;
            
            NdisAllocatePacket(&status, &new_packet, adapter->send_handle);
            if (status != NDIS_STATUS_SUCCESS)
            {
                goto send_packet_finish;
            }
            send_info = (PSEND_RSVD)(new_packet->ProtocolReserved);
            send_info->original_packet = packets[i];

            // repackage the original packet.
            NDIS_PACKET_FIRST_NDIS_BUFFER(new_packet) =
                NDIS_PACKET_FIRST_NDIS_BUFFER(packets[i]);
            NDIS_PACKET_LAST_NDIS_BUFFER(new_packet) =
                NDIS_PACKET_LAST_NDIS_BUFFER(packets[i]);
            NDIS_SET_ORIGINAL_PACKET(new_packet,
                NDIS_GET_ORIGINAL_PACKET(packets[i]));
            NdisGetPacketFlags(new_packet) =
                NdisGetPacketFlags(packets[i]);
            NDIS_SET_PACKET_STATUS(new_packet,
                NDIS_GET_PACKET_STATUS(packets[i]));
            NDIS_SET_PACKET_HEADER_SIZE(new_packet,
                NDIS_GET_PACKET_HEADER_SIZE(packets[i]));
            NdisIMCopySendPerPacketInfo(new_packet, packets[i]);
            
            {
                PVOID media_info;
                UINT media_info_size;
                NDIS_GET_PACKET_MEDIA_SPECIFIC_INFO(packets[i],
                    &media_info, &media_info_size);
                if (media_info != NULL)
                {
                    NDIS_SET_PACKET_MEDIA_SPECIFIC_INFO(new_packet,
                        media_info, media_info_size);
                }
            }

            NdisInterlockedIncrement(&adapter->pending_sends);
            NdisSend(&status, adapter->binding_handle, new_packet);
            if (status != NDIS_STATUS_PENDING)
            {
                NdisIMCopySendCompletePerPacketInfo(packets[i], new_packet);
                NdisFreePacket(new_packet);
                NdisInterlockedDecrement(&adapter->pending_sends);
            }
        }

send_packet_finish:
        if (status != NDIS_STATUS_PENDING)
        {
            NdisMSendComplete(adapter->miniport_handle, packets[i], status);
        }
    }
}

/*
 * Query information handler.
 */
NDIS_STATUS miniport_query_information(IN NDIS_HANDLE adapter_context,
    IN NDIS_OID oid, IN PVOID buffer, IN ULONG buffer_size,
    OUT PULONG bytes_written, OUT PULONG bytes_needed)
{
    PADAPT adapter = (PADAPT)adapter_context;
    NDIS_STATUS status;

    if (oid == OID_PNP_QUERY_POWER)
    {
        *bytes_needed = 0;
        *bytes_written = 0;
        return NDIS_STATUS_SUCCESS;
    }

    NdisAcquireSpinLock(&adapter->lock);
    if (adapter->unbinding == true || adapter->standing_by == true)
    {
        NdisReleaseSpinLock(&adapter->lock);
        return NDIS_STATUS_FAILURE;
    }
    NdisReleaseSpinLock(&adapter->lock);

    if (adapter->miniport_state > NdisDeviceStateD0) 
    {
        return NDIS_STATUS_FAILURE;
    }

    switch (oid)
    {
        case OID_GEN_SUPPORTED_GUIDS:
            return NDIS_STATUS_NOT_SUPPORTED;
        case OID_TCP_TASK_OFFLOAD:
            // Disable TCP/UDP checksum offloads for "bad checksum" NAT
            // traversal method.
            return NDIS_STATUS_NOT_SUPPORTED;
        default:
            // Forward the request:
            break;
    }

    // All other queries are forwarded.
    adapter->request.RequestType = NdisRequestQueryInformation;
    adapter->request.DATA.QUERY_INFORMATION.Oid = oid;
    adapter->request.DATA.QUERY_INFORMATION.InformationBuffer = buffer;
    adapter->request.DATA.QUERY_INFORMATION.InformationBufferLength =
        buffer_size;

    NdisAcquireSpinLock(&adapter->lock);
    if (adapter->protocol_state > NdisDeviceStateD0 &&
        adapter->standing_by == false)
    {
        adapter->queued_request = true;
        NdisReleaseSpinLock(&adapter->lock);
        return NDIS_STATUS_PENDING;
    }
    adapter->pending_request = true;
    NdisReleaseSpinLock(&adapter->lock);

    NdisRequest(&status, adapter->binding_handle, &adapter->request);

    if (status != NDIS_STATUS_PENDING)
    {
        protocol_request_complete(adapter, &adapter->request, status);
        return NDIS_STATUS_PENDING;
    }

    return status;
}

/*
 * Set information handler.
 */
NDIS_STATUS miniport_set_information(IN NDIS_HANDLE adapter_context,
    IN NDIS_OID oid, IN PVOID buffer, IN ULONG buffer_size,
    OUT PULONG bytes_read, OUT PULONG bytes_needed)
{
    PADAPT adapter = (PADAPT)adapter_context;
    NDIS_STATUS status;
    
    if (oid == OID_PNP_SET_POWER)
    {
        // Special case: set power state
        NDIS_DEVICE_POWER_STATE new_state;

        if (buffer_size < sizeof(NDIS_DEVICE_POWER_STATE))
        {
            *bytes_read = 0;
            *bytes_needed = sizeof(NDIS_DEVICE_POWER_STATE);
            return NDIS_STATUS_INVALID_LENGTH;
        }

        new_state = *(PNDIS_DEVICE_POWER_STATE)buffer;
        if (adapter->miniport_state > NdisDeviceStateD0)
        {
            if (new_state == NdisDeviceStateD0)
            {
                adapter->miniport_state = new_state;
                adapter->standing_by = false;
            }
            else
            {
                return NDIS_STATUS_FAILURE;
            }
        }
        else
        {
            if (new_state > NdisDeviceStateD0)
            {
                adapter->miniport_state = new_state;
                adapter->standing_by = true;
            }
            else
            {
                return NDIS_STATUS_FAILURE;
            }
        }

        if (adapter->standing_by == false)
        {
            if (adapter->last_indicated_status !=
                    adapter->latest_unindicate_status &&
                adapter->miniport_handle != NULL)
            {
                NdisMIndicateStatus(adapter->miniport_handle,
                    adapter->latest_unindicate_status, (PVOID)NULL, 0);
                NdisMIndicateStatusComplete(adapter->miniport_handle);
                adapter->last_indicated_status =
                    adapter->latest_unindicate_status;
            }
        }
        else
        {
            adapter->latest_unindicate_status = adapter->last_indicated_status;
        }
        *bytes_read = sizeof(NDIS_DEVICE_POWER_STATE);
        *bytes_needed = 0;
        return NDIS_STATUS_SUCCESS;
    }

    NdisAcquireSpinLock(&adapter->lock);     
    if (adapter->unbinding == true || adapter->standing_by == true)
    {
        NdisReleaseSpinLock(&adapter->lock);
        return NDIS_STATUS_FAILURE;
    }
    NdisReleaseSpinLock(&adapter->lock);

    if (adapter->miniport_state > NdisDeviceStateD0)
    {
        return NDIS_STATUS_FAILURE;
    }

    adapter->request.RequestType = NdisRequestSetInformation;
    adapter->request.DATA.SET_INFORMATION.Oid = oid;
    adapter->request.DATA.SET_INFORMATION.InformationBuffer =
        buffer;
    adapter->request.DATA.SET_INFORMATION.InformationBufferLength =
        buffer_size;

    NdisAcquireSpinLock(&adapter->lock);
    if (adapter->protocol_state > NdisDeviceStateD0 &&
        adapter->standing_by == false)
    {
        adapter->queued_request = true;
        NdisReleaseSpinLock(&adapter->lock);
        return NDIS_STATUS_PENDING;
    }
    adapter->pending_request = true;
    NdisReleaseSpinLock(&adapter->lock);

    NdisRequest(&status, adapter->binding_handle, &adapter->request);
    if (status != NDIS_STATUS_PENDING)
    {
        protocol_request_complete(adapter, &adapter->request, status);
        return NDIS_STATUS_PENDING;
    }

    return status;
}

/*
 * Return packet handler.
 */
VOID miniport_return_packet(IN NDIS_HANDLE adapter_context,
    IN PNDIS_PACKET packet)
{
    PADAPT adapter = (PADAPT)adapter_context;

    if (NdisGetPoolFromPacket(packet) == adapter->recv_handle)
    {
        // NDIS 5.0 packet repackaging:
        PRECV_RSVD recv_info = (PRECV_RSVD)(packet->MiniportReserved);
        PNDIS_PACKET original_packet = recv_info->original_packet;
        NdisFreePacket(packet);
        packet = original_packet;
    }
    
    // NDIS 5.1 packet stacking
    NdisReturnPackets(&packet, 1);
}

/*
 * Transfer data handler.
 */
NDIS_STATUS miniport_transfer_data(OUT PNDIS_PACKET packet,
    OUT PUINT transferred_size, IN NDIS_HANDLE adapter_context,
    IN NDIS_HANDLE receive_context, IN UINT offset, IN UINT transfer_size)
{
    PADAPT adapter = (PADAPT)adapter_context;
    NDIS_STATUS status;

    if (adapter->miniport_state != NdisDeviceStateD0 ||
        adapter->protocol_state != NdisDeviceStateD0)
    {
        return NDIS_STATUS_FAILURE;
    }

    NdisTransferData(&status, adapter->binding_handle, receive_context, offset,
        transfer_size, packet, transferred_size);
    return status;
}

/*
 * Halt handler.
 */
VOID miniport_halt(IN NDIS_HANDLE adapter_context)
{
    PADAPT adapter = (PADAPT)adapter_context;
    NDIS_STATUS status;

    adapter->miniport_handle = NULL;
    adapter->halted = true;

    NdisAcquireSpinLock(&driver_lock);
    {
        size_t i;
        for (i = 0; i < MAX_ADAPTERS && adapters[i] != adapter; i++)
            ;
        if (i < MAX_ADAPTERS)
        {
            for (; i < MAX_ADAPTERS && adapters[i] != NULL; i++)
            {
                adapters[i] = (i+1 == MAX_ADAPTERS? NULL: adapters[i]);
            }
        }
    }
    NdisReleaseSpinLock(&driver_lock);

    if (adapter->binding_handle != NULL)
    {
        protocol_close_adapter_binding(&status, adapter);
        dereference_adapter(adapter);
    }
    dereference_adapter(adapter);
}

/*
 * Cancel send packet handler.
 */
VOID miniport_cancel_send_packets(IN NDIS_HANDLE adapter_context,
    IN PVOID cancel_id)
{
    PADAPT adapter = (PADAPT)adapter_context;
    NdisCancelSendPackets(adapter->binding_handle, cancel_id);
}

/* 
 * System shutdown handler. 
 */ 
VOID miniport_adapter_shutdown(IN NDIS_HANDLE adapter_context) 
{ 
    UNREFERENCED_PARAMETER(adapter_context); 
}

/*
 * PnP event notify handler.
 */
VOID miniport_PnP_event_notify(IN NDIS_HANDLE adapter_context,
    IN NDIS_DEVICE_PNP_EVENT pnp_event, IN PVOID buffer, IN ULONG buffer_size)
{
    UNREFERENCED_PARAMETER(adapter_context);
    UNREFERENCED_PARAMETER(pnp_event);
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(buffer_size);
}

