#include "quic_connection.h"
#include "log.h"
#include <msquic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Globals
static const QUIC_API_TABLE* MsQuic = NULL;
static HQUIC Registration = NULL;
static HQUIC Configuration = NULL;
static QUIC_BUFFER Alpn = { sizeof("p2p-quic-app-v1") - 1, (uint8_t*)"p2p-quic-app-v1" };
static quic_callbacks_t AppCallbacks;

// Forward declarations
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS QUIC_API ServerListenerCallback(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event);

_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS QUIC_API ServerConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event);

_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS QUIC_API ServerStreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event);

int quic_init(const char *cert_path, const char *key_path, quic_callbacks_t callbacks) {
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;

    if (QUIC_FAILED(status = MsQuicOpen2(&MsQuic))) {
        log_error("MsQuicOpen2 failed, 0x%x", status);
        return -1;
    }

    QUIC_REGISTRATION_CONFIG RegConfig = { "p2p-app", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    if (QUIC_FAILED(status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        log_error("RegistrationOpen failed, 0x%x", status);
        goto error;
    }

    QUIC_SETTINGS Settings = {0};
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    
    // Use a single, unified, insecure configuration for both client and server
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    if (QUIC_FAILED(status = MsQuic->ConfigurationOpen(
            Registration, &Alpn, 1, &Settings, sizeof(Settings), &CredConfig, &Configuration))) {
        log_error("ConfigurationOpen failed, 0x%x", status);
        goto error;
    }

    AppCallbacks = callbacks;
    log_info("QUIC initialized successfully.");
    return 0;

error:
    if (Configuration != NULL) MsQuic->ConfigurationClose(Configuration);
    if (Registration != NULL) MsQuic->RegistrationClose(Registration);
    return -1;
}

void quic_cleanup(void) {
    if (MsQuic != NULL) {
        if (Configuration != NULL) MsQuic->ConfigurationClose(Configuration);
        if (Registration != NULL) MsQuic->RegistrationClose(Registration);
    }
}

quic_listener_t* quic_listen(const char *address, int port) {
    QUIC_STATUS status;
    HQUIC listener = NULL;
    QUIC_ADDR addr;

    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&addr, (uint16_t)port);

    if (QUIC_FAILED(status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, NULL, &listener))) {
        log_error("ListenerOpen failed, 0x%x", status);
        return NULL;
    }

    if (QUIC_FAILED(status = MsQuic->ListenerStart(listener, &Alpn, 1, &addr))) {
        log_error("ListenerStart failed, 0x%x", status);
        MsQuic->ListenerClose(listener);
        return NULL;
    }

    log_info("QUIC listener started on port %d.", port);
    return (quic_listener_t*)listener;
}

quic_conn_t* quic_connect(const char *address, int port) {
    QUIC_STATUS status;
    HQUIC connection = NULL;

    if (QUIC_FAILED(status = MsQuic->ConnectionOpen(Registration, ServerConnectionCallback, NULL, &connection))) {
        log_error("ConnectionOpen failed, 0x%x", status);
        return NULL;
    }

    log_info("Attempting to connect to %s:%d...", address, port);

    if (QUIC_FAILED(status = MsQuic->ConnectionStart(
            connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, address, (uint16_t)port))) {
        log_error("ConnectionStart failed, 0x%x", status);
        MsQuic->ConnectionClose(connection);
        return NULL;
    }

    return (quic_conn_t*)connection;
}

void quic_conn_get_remote_address(quic_conn_t* conn, char* ip_buffer, size_t buffer_size, uint16_t* port) {
    QUIC_ADDR remote_addr;
    uint32_t addr_size = sizeof(remote_addr);
    if (conn && MsQuic && QUIC_SUCCEEDED(MsQuic->GetParam(
            (HQUIC)conn, QUIC_PARAM_CONN_REMOTE_ADDRESS, &addr_size, &remote_addr))) {
        
        QUIC_ADDR_STR addr_str;
        QuicAddrToString(&remote_addr, &addr_str);
        strncpy(ip_buffer, addr_str.Address, buffer_size);
        ip_buffer[buffer_size - 1] = '\0';
        *port = QuicAddrGetPort(&remote_addr);
    } else {
        strncpy(ip_buffer, "?.?.?.?", buffer_size);
        ip_buffer[buffer_size - 1] = '\0';
        *port = 0;
    }
}

int quic_stream_send(void *stream, const uint8_t *data, uint32_t len, int fin) {
    QUIC_STATUS status;
    uint8_t* send_buffer = (uint8_t*)malloc(len);
    if (send_buffer == NULL) {
        log_error("Failed to allocate send buffer.");
        return -1;
    }
    memcpy(send_buffer, data, len);

    QUIC_BUFFER buffer;
    buffer.Buffer = send_buffer;
    buffer.Length = len;

    status = MsQuic->StreamSend((HQUIC)stream, &buffer, 1, (QUIC_SEND_FLAGS)fin, send_buffer);

    if (QUIC_FAILED(status)) {
        log_error("StreamSend failed, 0x%x", status);
        free(send_buffer);
        return -1;
    }
    return 0;
}

void quic_listener_close(quic_listener_t *listener) {
    if (listener) MsQuic->ListenerClose((HQUIC)listener);
}

void quic_conn_close(quic_conn_t *conn) {
    if (conn) MsQuic->ConnectionShutdown((HQUIC)conn, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
}

_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS QUIC_API ServerListenerCallback(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) {
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
            MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
            if (AppCallbacks.on_new_connection) {
                AppCallbacks.on_new_connection((quic_conn_t*)Event->NEW_CONNECTION.Connection);
            }
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS QUIC_API ServerConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            log_info("Peer connected.");
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            if (AppCallbacks.on_connection_closed) {
                AppCallbacks.on_connection_closed((quic_conn_t*)Connection);
            }
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            MsQuic->ConnectionClose(Connection);
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            log_info("Peer opened a new stream.");
            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, (void*)Connection);
            if (AppCallbacks.on_new_stream) {
                AppCallbacks.on_new_stream((quic_conn_t*)Connection, Event->PEER_STREAM_STARTED.Stream);
            }
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS QUIC_API ServerStreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {
    quic_conn_t* conn = (quic_conn_t*)Context;
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            if (AppCallbacks.on_stream_data) {
                for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                    AppCallbacks.on_stream_data(conn, Stream, Event->RECEIVE.Buffers[i].Buffer, Event->RECEIVE.Buffers[i].Length);
                }
            }
            break;
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            free(Event->SEND_COMPLETE.ClientContext);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            if (AppCallbacks.on_stream_closed) {
                AppCallbacks.on_stream_closed(conn, Stream);
            }
            MsQuic->StreamClose(Stream);
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}