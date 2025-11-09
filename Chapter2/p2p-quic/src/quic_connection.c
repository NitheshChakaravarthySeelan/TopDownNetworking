#include "quic_connection.h"
#include "log.h"
#include <msquic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Globals
static QUIC_API_TABLE* MsQuic = NULL;
static HQUIC Registration = NULL;
static HQUIC Configuration = NULL;
static QUIC_BUFFER Alpn = { sizeof("p2p-quic") - 1, (uint8_t*)"p2p-quic" };
static quic_callbacks_t AppCallbacks;

// Forward declarations for our callback handlers
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS QUIC_API ServerListenerCallback(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event);

_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS QUIC_API ServerConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event);


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

    if (QUIC_FAILED(status = MsQuic->ConfigurationOpen(
            Registration, &Alpn, 1, NULL, 0, NULL, &Configuration))) {
        log_error("ConfigurationOpen failed, 0x%x", status);
        goto error;
    }

    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_SERVER; // We need to be a server
    CredConfig.CertificateFile.CertificateFile = (char*)cert_path;
    CredConfig.CertificateFile.PrivateKeyFile = (char*)key_path;

    if (QUIC_FAILED(status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        log_error("ConfigurationLoadCredential failed, 0x%x", status);
        goto error;
    }

    AppCallbacks = callbacks; // Store the application callbacks
    log_info("QUIC initialized successfully.");
    return 0;

error:
    if (Registration != NULL) {
        MsQuic->RegistrationClose(Registration);
    }
    MsQuicClose(MsQuic);
    return -1;
}

void quic_cleanup(void) {
    if (MsQuic != NULL) {
        if (Configuration != NULL) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Registration != NULL) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }
}

quic_listener_t* quic_listen(const char *address, int port) {
    QUIC_STATUS status;
    HQUIC listener = NULL;
    QUIC_ADDR addr;

    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&addr, (uint16_t)port);
    // Note: We are not setting the IP address, so it will listen on all interfaces (0.0.0.0 or ::)

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

_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS QUIC_API ServerListenerCallback(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) {
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            // A new connection is trying to connect.
            // Set the callback handler for the connection and associate our app context.
            MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
            
            // Set the configuration for the connection.
            MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
            
            log_info("New peer connection received.");
            if (AppCallbacks.on_new_connection) {
                AppCallbacks.on_new_connection((quic_conn_t*)Event->NEW_CONNECTION.Connection);
            }
            break;
        default:
            break;
    }
    return status;
}

_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS QUIC_API ServerConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            log_info("Peer connected.");
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            log_warn("Peer initiated shutdown with transport error 0x%x.", Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
            if (AppCallbacks.on_connection_closed) {
                AppCallbacks.on_connection_closed((quic_conn_t*)Connection);
            }
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            log_info("Peer initiated shutdown with app error 0x%llx.", Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
            if (AppCallbacks.on_connection_closed) {
                AppCallbacks.on_connection_closed((quic_conn_t*)Connection);
            }
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            log_info("Shutdown complete for connection.");
            MsQuic->ConnectionClose(Connection);
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            log_info("Peer opened a new stream.");
            // Set the callback handler for the new stream.
            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerConnectionCallback, NULL);
            if (AppCallbacks.on_new_stream) {
                AppCallbacks.on_new_stream((quic_conn_t*)Connection, Event->PEER_STREAM_STARTED.Stream);
            }
            break;
        case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
            // This event is not used in this implementation.
            break;
	case QUIC_STREAM_EVENT_SEND_COMPLETE:
		free(Event->SEND_COMPLETE.ClientContext);
		log_info("Send Complete.");
		break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

void quic_listener_close(quic_listener_t *listener) {
    if (listener) MsQuic->ListenerClose((HQUIC)listener);
}

quic_conn_t* quic_connect(const char *address, int port) {
	QUIC_STATUS status;
	HQUIC Connection = NULL;

	if (QUIC_FAILED(status = MsQuic->ConnectionOpen(Registration, ServerConnectionCallback, NULL, &Connection)) {
		log_error("quic_connection is not established");
		return NULL;
	}
	
	// Start the Handshake
	status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, address, (uint16_t)port);

	if (QUIC_FAILED(status)) {
		log_error("quic_connection is not starting");
		MsQuic->ConnectionClose();
		return NULL;
	}
	return (quic_conn_t*)Connection;
}

void quic_conn_close(quic_conn_t *conn) {
    if (conn) MsQuic->ConnectionShutdown((HQUIC)conn, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
}

int quic_stream_send(void *stream, const uint8_t *data, uint32_t len, int fin) {
	QUIC_STATUS status;

	// Allocate a new buffer on the heap
	memcpy(send_buffer, data, len);

	// Prepare the QUIC_BUFFER struct
	QUIC_BUFFER buffer;
	buffer.Buffer = data;
	buffer.length = len;

	status = MsQuic->StreamSend((HQUIC)stream, &buffer, 1, (QUIC_SEND_FLAGS)fin, data);

	if (QUIC_FAILED(status)) {
		log_error("StreamSend failed, 0x%x", status);
		free(send_buffer);
		return -1;
	}

	return 0;
}

