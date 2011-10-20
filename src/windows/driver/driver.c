/*
 * driver.c
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

#pragma NDIS_INIT_FUNCTION(DriverEntry)

NDIS_SPIN_LOCK driver_lock;

NDIS_HANDLE proto_handle = NULL;
NDIS_HANDLE driver_handle = NULL;
NDIS_HANDLE wrapper_handle = NULL;

NDIS_MEDIUM mediums[4] =
{
    NdisMedium802_3,
    NdisMedium802_5,
    NdisMediumFddi,
    NdisMediumWan
};

PADAPT pAdaptList = NULL;

/*
 * Prototypes.
 */
DRIVER_UNLOAD driverUnload;
VOID driverUnload(IN PDRIVER_OBJECT driver);

/*
 * The driver entry point.
 */
NTSTATUS DriverEntry(IN PDRIVER_OBJECT driver, IN PUNICODE_STRING reg_path)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_PROTOCOL_CHARACTERISTICS proto_chars;
    NDIS_MINIPORT_CHARACTERISTICS minip_chars;

    NdisAllocateSpinLock(&driver_lock);
    NdisMInitializeWrapper(&wrapper_handle, driver, reg_path, NULL);

    // Register the miniport.
    NdisZeroMemory(&minip_chars, sizeof(NDIS_MINIPORT_CHARACTERISTICS));

    // NDIS 5.1 miniport.
    minip_chars.MajorNdisVersion         = 5;
    minip_chars.MinorNdisVersion         = 1;
    minip_chars.InitializeHandler        = miniport_initialize;
    minip_chars.SendPacketsHandler       = miniport_send_packets;
    minip_chars.QueryInformationHandler  = miniport_query_information;
    minip_chars.SetInformationHandler    = miniport_set_information;
    minip_chars.ReturnPacketHandler      = miniport_return_packet;
    minip_chars.ResetHandler             = NULL;
    minip_chars.TransferDataHandler      = miniport_transfer_data;
    minip_chars.HaltHandler              = miniport_halt;
    minip_chars.CancelSendPacketsHandler = miniport_cancel_send_packets;
    minip_chars.AdapterShutdownHandler   = miniport_adapter_shutdown;
    minip_chars.PnPEventNotifyHandler    = miniport_PnP_event_notify;
    minip_chars.CheckForHangHandler      = NULL;
    minip_chars.SendHandler              = NULL;

    status = NdisIMRegisterLayeredMiniport(wrapper_handle, &minip_chars,
        sizeof(minip_chars), &driver_handle);
    if (status != NDIS_STATUS_SUCCESS)
    {
        goto driver_entry_exit;
    }

   NdisMRegisterUnloadHandler(wrapper_handle, driverUnload);

    // Register the protocol.
    NdisZeroMemory(&proto_chars, sizeof(proto_chars));

    // NDIS 5.0 protocol
    proto_chars.MajorNdisVersion = 5;
    proto_chars.MinorNdisVersion = 0;

    // Note: must match the .inf file.
    NdisInitUnicodeString(&proto_chars.Name, DRIVER_NAME);
    proto_chars.OpenAdapterCompleteHandler  = protocol_open_adapter_complete;
    proto_chars.CloseAdapterCompleteHandler = protocol_close_adapter_complete;
    proto_chars.ResetCompleteHandler        = protocol_reset_complete;
    proto_chars.RequestCompleteHandler      = protocol_request_complete;
    proto_chars.StatusHandler               = protocol_status;
    proto_chars.StatusCompleteHandler       = protocol_status_complete;
    proto_chars.SendCompleteHandler         = protocol_send_complete;
    proto_chars.TransferDataCompleteHandler = protocol_transfer_data_complete;
    proto_chars.ReceiveHandler              = protocol_receive;
    proto_chars.ReceiveCompleteHandler      = protocol_receive_complete;
    proto_chars.ReceivePacketHandler        = protocol_receive_packet;
    proto_chars.BindAdapterHandler          = protocol_bind_adapter;
    proto_chars.UnbindAdapterHandler        = protocol_unbind_adapter;
    proto_chars.UnloadHandler               = protocol_unload_protocol;
    proto_chars.PnPEventHandler             = protocol_PnP_event;

    NdisRegisterProtocol(&status, &proto_handle, &proto_chars,
        sizeof(proto_chars));

    if (status != NDIS_STATUS_SUCCESS)
    {
        NdisIMDeregisterLayeredMiniport(driver_handle);
        goto driver_entry_exit;
    }

    NdisIMAssociateMiniport(driver_handle, proto_handle);

    /*
     * Create the I/O device.
     */
    status = create_packets_dev(wrapper_handle);

driver_entry_exit:

    if (status != NDIS_STATUS_SUCCESS)
    {
        NdisTerminateWrapper(wrapper_handle, NULL);
    }

    return status;
}

/*
 * Unload this driver.
 */
VOID driverUnload(IN PDRIVER_OBJECT driver)
{
    UNREFERENCED_PARAMETER(driver);
    protocol_unload_protocol();
    NdisIMDeregisterLayeredMiniport(driver_handle);
    NdisFreeSpinLock(&driver_lock);
}

/*
 * Reference an adapter.
 */
VOID reference_adapter(IN PADAPT adapter)
{
    NdisInterlockedIncrement(&adapter->ref_count);
}

/*
 * Dereference an adapter.
 */
BOOLEAN dereference_adapter(IN PADAPT adapter)
{
    LONG ref_count = NdisInterlockedDecrement(&adapter->ref_count);
    if (ref_count != 0)
    {
        return FALSE;
    }

    NdisFreePacketPool(adapter->recv_handle);
    NdisFreePacketPool(adapter->send_handle);
    NdisFreeSpinLock(&adapter->lock);
    NdisFreeMemory(adapter->name.Buffer, 0, 0);
    NdisFreeMemory(adapter, 0, 0);
    return TRUE;
}

