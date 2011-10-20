/*
 * driver.h
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

#ifndef __DRIVER_H
#define __DRIVER_H

#include "common.h"

/*
 * Enable debug messages or not.
 */
#define debug(format)       DbgPrint format
/* #define debug(format) */

/*
 * Representation of an adapter.
 */
struct adapter_s
{
    NDIS_SPIN_LOCK lock;                // Spin lock
    LONG ref_count;                     // Reference count

    NDIS_STRING name;                   // Device name
    
    bool address_valid;                 // Is 'address' valid?
    uint8_t address[6];                 // MAC address

    NDIS_HANDLE binding_handle;         // Handle to the lower miniport
    NDIS_HANDLE miniport_handle;        // Handle for miniport up-calls
    NDIS_HANDLE send_handle;            // Send packet pool handle
    NDIS_HANDLE recv_handle;            // Receive packet pool handle
    NDIS_STATUS status;                 // Status
    NDIS_EVENT event;                   // Event for open/close sync.
    NDIS_EVENT init_event;              // Event for unbinding during init
    NDIS_MEDIUM medium;                 // Medium
    NDIS_REQUEST request;               // Request wrapper

    LONG pending_sends;                 // Pending send packets.    
    bool pending_request;               // Pending request at miniport below?
    bool queued_request;                // Request is queued?
    bool standing_by;                   // D0 -> (>D0) transition?
    bool init;                          // Init in progress?
    bool unbinding;                     // Adapter unbinding?
    bool halted;                        // Miniport halted?
    
    NDIS_DEVICE_POWER_STATE miniport_state;
                                        // Miniport's power state
    NDIS_DEVICE_POWER_STATE protocol_state;
                                        // Protocol's power state
    
    /*
     * As per the driver examples:
     */
    NDIS_STATUS last_indicated_status;  // The last indicated media status
    NDIS_STATUS latest_unindicate_status;
                                        // The latest suppressed media status
};

typedef struct adapter_s ADAPT;
typedef struct adapter_s *PADAPT;

/*
 * Global set of open adapters.
 */
#define MAX_ADAPTERS    32
extern PADAPT adapters[MAX_ADAPTERS];
extern size_t adapters_size;

/*
 * Global locks and handles.
 */
extern NDIS_HANDLE proto_handle;
extern NDIS_HANDLE driver_handle;
extern NDIS_MEDIUM mediums[4];
extern NDIS_SPIN_LOCK driver_lock;

/*
 * Prototypes.
 */
DRIVER_INITIALIZE DriverEntry;
extern NTSTATUS DriverEntry(IN PDRIVER_OBJECT driver,
    IN PUNICODE_STRING reg_path);
DRIVER_UNLOAD PtUnload;
VOID PtUnloadProtocol(VOID);

// Protocol:
extern VOID protocol_open_adapter_complete(IN NDIS_HANDLE binding_context,
    IN NDIS_STATUS status, IN NDIS_STATUS err_status);
extern VOID protocol_close_adapter_complete(IN NDIS_HANDLE binding_context,
    IN NDIS_STATUS status);
extern VOID protocol_reset_complete(IN NDIS_HANDLE binding_context,
    IN NDIS_STATUS status);
extern VOID protocol_request_complete(IN NDIS_HANDLE binding_context,
    IN PNDIS_REQUEST request, IN NDIS_STATUS status);
extern VOID protocol_status(IN NDIS_HANDLE binding_context,
    IN NDIS_STATUS status, IN PVOID buffer, IN UINT buffer_size);
extern VOID protocol_status_complete(IN NDIS_HANDLE binding_context);
extern VOID protocol_send_complete(IN NDIS_HANDLE binding_context,
    IN PNDIS_PACKET packet, IN NDIS_STATUS status);
extern VOID protocol_transfer_data_complete(IN NDIS_HANDLE binding_context,
    IN PNDIS_PACKET packet, IN NDIS_STATUS status, IN UINT transfer_size);
extern NDIS_STATUS protocol_receive(IN NDIS_HANDLE binding_context,
    IN NDIS_HANDLE receive_context, IN PVOID header_buffer,
    IN UINT header_buffer_size, IN PVOID lookahead_buffer,
    IN UINT lookahead_buffer_size, IN UINT packet_size);
extern VOID protocol_receive_complete(IN NDIS_HANDLE binding_context);
extern INT protocol_receive_packet(IN NDIS_HANDLE binding_context,
    IN PNDIS_PACKET packet);
extern VOID protocol_bind_adapter(OUT PNDIS_STATUS status,
    IN NDIS_HANDLE bind_context, IN PNDIS_STRING dev_name,
    IN PVOID protocol_section, IN PVOID __unused);
extern VOID protocol_unbind_adapter(OUT PNDIS_STATUS status,
    IN NDIS_HANDLE binding_context, IN NDIS_HANDLE unbind_context);
extern VOID protocol_unload_protocol(VOID);
extern NDIS_STATUS protocol_PnP_event(IN NDIS_HANDLE binding_context,
    IN PNET_PNP_EVENT pnp_event);
extern VOID protocol_close_adapter_binding(OUT PNDIS_STATUS status,
    IN PADAPT adapter);

// Miniport:
extern NDIS_STATUS miniport_initialize(OUT PNDIS_STATUS status,
    OUT PUINT idx, IN PNDIS_MEDIUM mediums, IN UINT mediums_size,
    IN NDIS_HANDLE miniport_handle, IN NDIS_HANDLE config_context);
extern VOID miniport_send_packets(IN NDIS_HANDLE adapter_context,
    IN PPNDIS_PACKET packets, IN UINT packets_size);
extern NDIS_STATUS miniport_query_information(IN NDIS_HANDLE adapter_context,
    IN NDIS_OID oid, IN PVOID buffer, IN ULONG buffer_size,
    OUT PULONG bytes_written, OUT PULONG bytes_needed);
extern NDIS_STATUS miniport_set_information(IN NDIS_HANDLE adapter_context,
    IN NDIS_OID oid, IN PVOID buffer, IN ULONG buffer_size,
    OUT PULONG bytes_read, OUT PULONG bytes_needed);
extern VOID miniport_return_packet(IN NDIS_HANDLE adapter_context,
    IN PNDIS_PACKET packet);
extern NDIS_STATUS miniport_transfer_data(OUT PNDIS_PACKET packet,
    OUT PUINT transferred_size, IN NDIS_HANDLE adapter_context,
    IN NDIS_HANDLE receive_context, IN UINT offset, IN UINT transfer_size);
extern VOID miniport_halt(IN NDIS_HANDLE adapter_context);
extern VOID miniport_cancel_send_packets(IN NDIS_HANDLE adapter_context,
    IN PVOID cancel_id);
extern VOID miniport_adapter_shutdown(IN NDIS_HANDLE adapter_context);
extern VOID miniport_PnP_event_notify(IN NDIS_HANDLE adapter_context,
    IN NDIS_DEVICE_PNP_EVENT pnp_event, IN PVOID buffer, IN ULONG buffer_size);

extern VOID reference_adapter(IN PADAPT adapter);
extern BOOLEAN dereference_adapter(IN PADAPT adapter);

struct send_info_s
{
    PNDIS_PACKET original_packet;
};
typedef struct send_info_s SEND_RSVD;
typedef struct send_info_s *PSEND_RSVD;

struct recv_info_s
{
    PNDIS_PACKET original_packet;
};
typedef struct recv_info_s RECV_RSVD;
typedef struct recv_info_s *PRECV_RSVD;

#endif          /* __DRIVER_H */
