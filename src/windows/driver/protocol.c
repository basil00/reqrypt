/*
 * protocol.c
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

#define MAX_PACKET_POOL_SIZE 0x0000FFFF
#define MIN_PACKET_POOL_SIZE 0x000000FF

/*
 * Completion routine for NdisOpenAdapter.
 */
VOID protocol_open_adapter_complete(IN NDIS_HANDLE binding_context,
    IN NDIS_STATUS status, IN NDIS_STATUS err_status)
{
    PADAPT adapter = (PADAPT)binding_context;
    UNREFERENCED_PARAMETER(err_status);
    adapter->status = status;
    NdisSetEvent(&adapter->event);
}

/*
 * Close adapter complete handler.
 */
VOID protocol_close_adapter_complete(IN NDIS_HANDLE binding_context,
    IN NDIS_STATUS status)
{
    PADAPT adapter = (PADAPT)binding_context;
    adapter->status = status;
    NdisSetEvent(&adapter->event);
}

/*
 * Reset complete handler (should never be called).
 */
VOID protocol_reset_complete(IN NDIS_HANDLE binding_context,
    IN NDIS_STATUS status)
{
    UNREFERENCED_PARAMETER(binding_context);
    UNREFERENCED_PARAMETER(status);
    ASSERT(0);
}

/*
 * Request complete handler.
 */
VOID protocol_request_complete(IN NDIS_HANDLE binding_context,
    IN PNDIS_REQUEST request, IN NDIS_STATUS status)
{
    PADAPT adapter = (PADAPT)binding_context;
    NDIS_OID oid = adapter->request.DATA.SET_INFORMATION.Oid;

    adapter->pending_request = false;
    switch (request->RequestType)
    {
        case NdisRequestQueryInformation:
            if (oid == OID_PNP_CAPABILITIES && status == NDIS_STATUS_SUCCESS)
            {
                if (adapter->request.DATA.QUERY_INFORMATION.
                    InformationBufferLength >= sizeof(NDIS_PNP_CAPABILITIES))
                {
                    PNDIS_PNP_CAPABILITIES pnp_caps = (PNDIS_PNP_CAPABILITIES)
                        adapter->request.DATA.QUERY_INFORMATION.
                        InformationBuffer;
                    PNDIS_PM_WAKE_UP_CAPABILITIES pnp_wake_caps =
                        &pnp_caps->WakeUpCapabilities;
                    pnp_wake_caps->MinMagicPacketWakeUp =
                        NdisDeviceStateUnspecified;
                    pnp_wake_caps->MinPatternWakeUp =
                        NdisDeviceStateUnspecified;
                    pnp_wake_caps->MinLinkChangeWakeUp =
                        NdisDeviceStateUnspecified;
                }
                else
                {
                    request->DATA.QUERY_INFORMATION.BytesNeeded =
                        sizeof(NDIS_PNP_CAPABILITIES);
                    status = NDIS_STATUS_RESOURCES;
                }
            }

            if (oid == OID_GEN_MAC_OPTIONS && status == NDIS_STATUS_SUCCESS)
            {
                // As per the MS passthru example: clear the NO_LOOPBACK
                // bit
                *(PULONG)request->DATA.QUERY_INFORMATION.InformationBuffer &=
                    ~NDIS_MAC_OPTION_NO_LOOPBACK;
            }

            NdisMQueryInformationComplete(adapter->miniport_handle, status);
            break;
        case NdisRequestSetInformation:
            NdisMSetInformationComplete(adapter->miniport_handle, status);
            break;
        default:
            ASSERT(0);
            break;
    }
}

/*
 * Status handler.
 */
VOID protocol_status(IN NDIS_HANDLE binding_context, IN NDIS_STATUS status,
    IN PVOID buffer, IN UINT buffer_size)
{
    PADAPT adapter = (PADAPT)binding_context;

    if (adapter->miniport_handle != NULL)
    {
        if (adapter->miniport_state == NdisDeviceStateD0 &&
            adapter->protocol_state == NdisDeviceStateD0)   
        {
            if (status == NDIS_STATUS_MEDIA_CONNECT || 
                status == NDIS_STATUS_MEDIA_DISCONNECT)
            {
                adapter->last_indicated_status = status;
            }
            // Only indicate when initialised and powered on.
            NdisMIndicateStatus(adapter->miniport_handle, status, buffer,
                buffer_size);
        }
        else
        {
            if (status == NDIS_STATUS_MEDIA_CONNECT || 
                status == NDIS_STATUS_MEDIA_DISCONNECT)
            {
                adapter->latest_unindicate_status = status;
            }
        }
    }
}

/*
 * Status complete handler.
 */
VOID protocol_status_complete(IN NDIS_HANDLE binding_context)
{
    PADAPT adapter = (PADAPT)binding_context;

    // Only indicate when initialised and powered on.
    if (adapter->miniport_handle != NULL &&
        adapter->miniport_state == NdisDeviceStateD0 &&
        adapter->protocol_state == NdisDeviceStateD0) 
    {
        NdisMIndicateStatusComplete(adapter->miniport_handle);
    }
}

/*
 * Send complete handler.
 */
VOID protocol_send_complete(IN NDIS_HANDLE binding_context,
    IN PNDIS_PACKET packet, IN NDIS_STATUS status)
{
    PADAPT adapter = (PADAPT)binding_context;
    NDIS_HANDLE pool_handle = NdisGetPoolFromPacket(packet);

    // EXTENSION:
    // Determine if the packet was the result from a packet injection?
    if (pool_handle == context.packet_pool)
    {
        write_packet_complete(packet, status);
    }
    else if (pool_handle != adapter->send_handle)
    {
        // Packet belongs to the protocol above us.
        NdisMSendComplete(adapter->miniport_handle, packet, status);
    }
    else
    {
        PSEND_RSVD send_info = (PSEND_RSVD)(packet->ProtocolReserved);
        PNDIS_PACKET original_packet = send_info->original_packet;
        NdisIMCopySendCompletePerPacketInfo(original_packet, packet);
        NdisDprFreePacket(packet);
        NdisMSendComplete(adapter->miniport_handle, original_packet, status);
    }
    NdisInterlockedDecrement(&adapter->pending_sends);
}

/*
 * Transfer data handler.
 */
VOID protocol_transfer_data_complete(IN NDIS_HANDLE binding_context,
    IN PNDIS_PACKET packet, IN NDIS_STATUS status, IN UINT transfer_size)
{
    PADAPT adapter = (PADAPT)binding_context;
    if(adapter->miniport_handle != NULL)
    {
        NdisMTransferDataComplete(adapter->miniport_handle, packet, status,
            transfer_size);
    }
}

/*
 * Receive handler.
 */
NDIS_STATUS protocol_receive(IN NDIS_HANDLE binding_context,
    IN NDIS_HANDLE receive_context, IN PVOID header_buffer,
    IN UINT header_buffer_size, IN PVOID lookahead_buffer,
    IN UINT lookahead_buffer_size, IN UINT packet_size)
{
    PADAPT adapter = (PADAPT)binding_context;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    
    if (adapter->miniport_handle == NULL ||
        adapter->miniport_state > NdisDeviceStateD0)
    {
        status = NDIS_STATUS_FAILURE;
    }
    else
    {
        // The MS passthru example goes to the effort of building a packet
        // if one exists, etc.  We don't bother -- let the protocol above
        // us decide what to do.

        if (adapter->miniport_handle != NULL)
        {
            switch (adapter->medium)
            {
                case NdisMedium802_3: case NdisMediumWan:
                    NdisMEthIndicateReceive(adapter->miniport_handle,
                        receive_context, header_buffer, header_buffer_size,
                        lookahead_buffer, lookahead_buffer_size, packet_size);
                    break;
                case NdisMedium802_5:
                    NdisMTrIndicateReceive(adapter->miniport_handle,
                        receive_context, header_buffer, header_buffer_size,
                        lookahead_buffer, lookahead_buffer_size, packet_size);
                    break;
#if FDDI    
                case NdisMediumFddi:
                    NdisMFddiIndicateReceive(adapter->miniport_handle,
                        receive_context, header_buffer, header_buffer_size,
                        lookahead_buffer, lookahead_buffer_size, packet_size);
                    break;
#endif
                default:
                    ASSERT(FALSE);
                    break;
            }
        }
    };

    return status;
}

/*
 * Receive complete handler.
 */
VOID protocol_receive_complete(IN NDIS_HANDLE binding_context)
{
    PADAPT adapter = (PADAPT)binding_context;

    if (adapter->miniport_handle != NULL &&
        adapter->miniport_state == NdisDeviceStateD0)
    {
        switch (adapter->medium)
        {
            case NdisMedium802_3: case NdisMediumWan:
                NdisMEthIndicateReceiveComplete(adapter->miniport_handle);
                break;
            case NdisMedium802_5:
                NdisMTrIndicateReceiveComplete(adapter->miniport_handle);
                break;
#if FDDI
            case NdisMediumFddi:
                NdisMFddiIndicateReceiveComplete(adapter->miniport_handle);
                break;
#endif
            default:
                ASSERT(0);
                break;
        }
    }
}

/*
 * Receive packet handler.
 */
INT protocol_receive_packet(IN NDIS_HANDLE binding_context,
    IN PNDIS_PACKET packet)
{
    PADAPT adapter = (PADAPT)binding_context;
    NDIS_STATUS status;

    if (adapter->miniport_handle == NULL ||
        adapter->miniport_state > NdisDeviceStateD0)
    {
          return 0;
    }

    // NDIS 5.1 packet stacking.
    {
        BOOLEAN stacks_remaining;
        NdisIMGetCurrentPacketStack(packet, &stacks_remaining);
        if (stacks_remaining)
        {
            status = NDIS_GET_PACKET_STATUS(packet);
            NdisMIndicateReceivePacket(adapter->miniport_handle, &packet, 1);
            return (status != NDIS_STATUS_RESOURCES);
        }
    }

    // Fallback: <= NDIS 5.0 packet repackaging.
    { 
        PNDIS_PACKET new_packet;
        NdisDprAllocatePacket(&status, &new_packet, adapter->recv_handle);
        if (status == NDIS_STATUS_SUCCESS)
        {
            PRECV_RSVD recv_info = (PRECV_RSVD)(new_packet->MiniportReserved);
            recv_info->original_packet = packet;

            // repackage the original packet.
            NDIS_PACKET_FIRST_NDIS_BUFFER(new_packet) =
                NDIS_PACKET_FIRST_NDIS_BUFFER(packet);
            NDIS_PACKET_LAST_NDIS_BUFFER(new_packet) =
                NDIS_PACKET_LAST_NDIS_BUFFER(packet);
            NDIS_SET_ORIGINAL_PACKET(new_packet,
                NDIS_GET_ORIGINAL_PACKET(packet));
            NdisGetPacketFlags(new_packet) = NdisGetPacketFlags(packet);
            NDIS_SET_PACKET_STATUS(new_packet, NDIS_GET_PACKET_STATUS(packet));
            NDIS_SET_PACKET_HEADER_SIZE(new_packet,
                NDIS_GET_PACKET_HEADER_SIZE(packet));
            status = NDIS_GET_PACKET_STATUS(new_packet);
            NdisMIndicateReceivePacket(adapter->miniport_handle, &new_packet,
                1);

            if (status == NDIS_STATUS_RESOURCES)
            {
                NdisDprFreePacket(new_packet);
                return 0;
            }

            return 1;
        }
        else
        {
            // Out of resources -- drop the packet.
            return 0;
        }
    }
}

/*
 * Bind to a miniport below.
 */
VOID protocol_bind_adapter(OUT PNDIS_STATUS status,
    IN NDIS_HANDLE bind_context, IN PNDIS_STRING dev_name,
    IN PVOID protocol_section, IN PVOID __unused)
{
    NDIS_HANDLE config_handle = NULL;
    PNDIS_CONFIGURATION_PARAMETER param;
    NDIS_STRING upper_bindings_str = NDIS_STRING_CONST("UpperBindings");
    PVOID device_name_buffer;
    PNDIS_STRING device_name;
    PADAPT adapter = NULL;
    NDIS_STATUS __unused_status;
    UINT idx;
    bool cleanup = true;

    UNREFERENCED_PARAMETER(bind_context);
    UNREFERENCED_PARAMETER(__unused);
    
    // Open handle to protocol config.
    NdisOpenProtocolConfiguration(status, &config_handle, protocol_section);
    if (*status != NDIS_STATUS_SUCCESS)
    {
        goto bind_adapter_exit;
    }

    // Read the device_name
    NdisReadConfiguration(status, &param, config_handle, &upper_bindings_str,
        NdisParameterString);
    if (*status != NDIS_STATUS_SUCCESS)
    {
        NdisCloseConfiguration(config_handle);
        goto bind_adapter_exit;
    }
    device_name = &param->ParameterData.StringData;

    // Allocate memory for the adapter structure and device name.
    NdisAllocateMemoryWithTag(&adapter, sizeof(ADAPT), 0);
    NdisAllocateMemoryWithTag(&device_name_buffer, device_name->MaximumLength,
        0);
    if (adapter == NULL || device_name_buffer == NULL) 
    {
        NdisCloseConfiguration(config_handle);
        if (adapter != NULL)
        {
            NdisFreeMemory(adapter, 0, 0);
        }
        if (device_name_buffer != NULL)
        {
            NdisFreeMemory(device_name_buffer, 0, 0);
        }
        *status = NDIS_STATUS_RESOURCES;
        goto bind_adapter_exit;
    }

    // Initialise the adapter structure.
    NdisZeroMemory(adapter, sizeof(ADAPT));
    adapter->address_valid = false;
    adapter->name.MaximumLength = device_name->MaximumLength;
    adapter->name.Length        = device_name->Length;
    adapter->name.Buffer        = device_name_buffer;
    NdisMoveMemory(adapter->name.Buffer, device_name->Buffer,
        device_name->MaximumLength);

    // Now that device_name has been copied, close the config_handle.
    NdisCloseConfiguration(config_handle);

    NdisInitializeEvent(&adapter->event);
    NdisAllocateSpinLock(&adapter->lock);

    // Allocate packet pools:
    NdisAllocatePacketPoolEx(status, &adapter->send_handle,
        MIN_PACKET_POOL_SIZE, MAX_PACKET_POOL_SIZE - MIN_PACKET_POOL_SIZE,
        sizeof(SEND_RSVD));
    if (*status != NDIS_STATUS_SUCCESS)
    {
        goto bind_adapter_exit;
    }
    NdisAllocatePacketPoolEx(status, &adapter->recv_handle,
        MIN_PACKET_POOL_SIZE, MAX_PACKET_POOL_SIZE - MIN_PACKET_POOL_SIZE,
        PROTOCOL_RESERVED_SIZE_IN_PACKET);
    if (*status != NDIS_STATUS_SUCCESS)
    {
        goto bind_adapter_exit;
    }

    // Open adapter below.
    NdisOpenAdapter(status, &__unused_status, &adapter->binding_handle,
        &idx, mediums, sizeof(mediums) / sizeof(NDIS_MEDIUM), proto_handle,
        adapter, dev_name, 0, NULL);

    if (*status == NDIS_STATUS_PENDING)
    {
        NdisWaitEvent(&adapter->event, 0);
        *status = adapter->status;
    }
    if (*status != NDIS_STATUS_SUCCESS)
    {
        goto bind_adapter_exit;
    }
    reference_adapter(adapter);

    adapter->medium = mediums[idx];
    adapter->init = true;
    NdisInitializeEvent(&adapter->init_event);

    reference_adapter(adapter);
    *status = NdisIMInitializeDeviceInstanceEx(driver_handle, &adapter->name,
        adapter);

    if (*status != NDIS_STATUS_SUCCESS)
    {
        if (adapter->halted == true)
        {
            cleanup = false;
        }
        if (dereference_adapter(adapter))
        {
            adapter = NULL;
        }
        goto bind_adapter_exit;  
    }
    dereference_adapter(adapter);

bind_adapter_exit:

    if (*status != NDIS_STATUS_SUCCESS && cleanup && adapter != NULL &&
        adapter->binding_handle != NULL)
    {
        NDIS_STATUS close_status;
        NdisResetEvent(&adapter->event);
        NdisCloseAdapter(&close_status, adapter->binding_handle);
        adapter->binding_handle = NULL;
        if (close_status == NDIS_STATUS_PENDING)
        {
             NdisWaitEvent(&adapter->event, 0);
        }
        dereference_adapter(adapter);
    }
}

/*
 * Unbind from a miniport below.
 */
VOID protocol_unbind_adapter(OUT PNDIS_STATUS status,
    IN NDIS_HANDLE binding_context, IN NDIS_HANDLE unbind_context)
{
    PADAPT adapter = (PADAPT)binding_context;
    UNREFERENCED_PARAMETER(unbind_context);

    NdisAcquireSpinLock(&adapter->lock);
    adapter->unbinding = true;
    if (adapter->queued_request == true)
    {
        adapter->queued_request = false;
        NdisReleaseSpinLock(&adapter->lock);
        protocol_request_complete(adapter, &adapter->request,
            NDIS_STATUS_FAILURE);
    }
    else
    {
        NdisReleaseSpinLock(&adapter->lock);
    }

    if (adapter->init == true)
    {
        NDIS_STATUS cancel_status =
            NdisIMCancelInitializeDeviceInstance(driver_handle,
                &adapter->name);
        if (cancel_status == NDIS_STATUS_SUCCESS)
        {
            adapter->init = false;
        }
        else
        {
            NdisWaitEvent(&adapter->init_event, 0);
        }

    }

    if (adapter->miniport_handle != NULL)
    {
        *status = NdisIMDeInitializeDeviceInstance(adapter->miniport_handle);
        *status = (*status == NDIS_STATUS_SUCCESS? NDIS_STATUS_SUCCESS:
            NDIS_STATUS_FAILURE);
    }
    else
    {
        protocol_close_adapter_binding(status, adapter);
        NdisFreePacketPool(adapter->recv_handle);
        NdisFreePacketPool(adapter->send_handle);
        NdisFreeSpinLock(&adapter->lock);
        NdisFreeMemory(adapter->name.Buffer, 0, 0);
        NdisFreeMemory(adapter, 0, 0);
    }
}

/*
 * Protocol unload handler.
 */
VOID protocol_unload_protocol(VOID)
{
    if (proto_handle != NULL)
    {
        NDIS_STATUS status;
        NdisDeregisterProtocol(&status, proto_handle);
        proto_handle = NULL;
    }
}

/*
 * PnP or power event handler.
 */
#define MAX_WAIT_TRIES  1000
NDIS_STATUS protocol_PnP_event(IN NDIS_HANDLE binding_context,
    IN PNET_PNP_EVENT pnp_event)
{
    PADAPT adapter = (PADAPT)binding_context;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
 
    switch (pnp_event->NetEvent)
    {
        case NetEventReconfigure:
            if (adapter != NULL)
            {
                if (adapter->miniport_handle != NULL)
                {
                    status = NdisIMNotifyPnPEvent(adapter->miniport_handle,
                        pnp_event);
                }
            }
            else
            {
                NdisReEnumerateProtocolBindings(proto_handle);
            }
            break;
        case NetEventSetPower:
        {
            NDIS_DEVICE_POWER_STATE prev_state;
            
            NdisAcquireSpinLock(&adapter->lock);
            prev_state = adapter->protocol_state;
            adapter->protocol_state =
                *(PNDIS_DEVICE_POWER_STATE)(pnp_event->Buffer);
            if (adapter->protocol_state > NdisDeviceStateD0)
            {
                // Entering low power state:
                int i;
                if (prev_state == NdisDeviceStateD0)
                {
                    adapter->standing_by = true;
                }
                NdisReleaseSpinLock(&adapter->lock);
                if (adapter->miniport_handle != NULL)
                {
                    status = NdisIMNotifyPnPEvent(adapter->miniport_handle,
                        pnp_event);
                }

                NdisAcquireSpinLock(&adapter->lock);
                if (adapter->queued_request == true)
                {
                    adapter->queued_request = false;
                    NdisReleaseSpinLock(&adapter->lock);
                    protocol_request_complete(adapter, &adapter->request,
                        NDIS_STATUS_FAILURE);
                }
                else
                {
                    NdisReleaseSpinLock(&adapter->lock);
                }

                for (i = 0; i < MAX_WAIT_TRIES &&
                     (adapter->pending_sends != 0 ||
                      adapter->pending_request == true); i++)
                {
                    NdisMSleep(1000);
                }
                ASSERT(i < MAX_WAIT_TRIES);
            }
            else
            {
                // Returning from a lower power state.
                if (prev_state > NdisDeviceStateD0)
                {
                    adapter->standing_by = false;
                }
                if (adapter->queued_request == true)
                {
                    NDIS_STATUS request_status;
                    adapter->queued_request = false;
                    adapter->pending_request = true;
                    NdisReleaseSpinLock(&adapter->lock);
                    NdisRequest(&request_status, adapter->binding_handle,
                        &adapter->request);
                    if (request_status != NDIS_STATUS_PENDING)
                    {
                        protocol_request_complete(adapter, &adapter->request,
                            request_status);
                    }
                }
                else
                {
                    NdisReleaseSpinLock(&adapter->lock);
                }

                if (adapter->miniport_handle != NULL)
                {
                    status = NdisIMNotifyPnPEvent(adapter->miniport_handle,
                        pnp_event);
                }
            }
            break;
        }
        default:
            if (adapter != NULL && adapter->miniport_handle != NULL)
            {
                status = NdisIMNotifyPnPEvent(adapter->miniport_handle,
                    pnp_event);
            }
            break;
    }

    return status;
}

/*
 * Close the binding below.
 */
VOID protocol_close_adapter_binding(OUT PNDIS_STATUS status, IN PADAPT adapter)
{
    if (adapter->binding_handle != NULL)
    {
        NdisResetEvent(&adapter->event);
        NdisCloseAdapter(status, adapter->binding_handle);
        if (*status == NDIS_STATUS_PENDING)
        {
            NdisWaitEvent(&adapter->event, 0);
            *status = adapter->status;
        }
        adapter->binding_handle = NULL;
    }
}

