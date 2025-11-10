#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h> // For sleep

#include "log.h"
#include "config.h"
#include "quic_connection.h"
#include "peer.h"
#include "message.h" // For message deserialization
#include "utils.h"   // For get_current_time_ms

// --- Global State for Signal Handling ---
static volatile bool running = true;

void sigint_handler(int signum) {
    log_info("SIGINT received. Initiating graceful shutdown...");
    running = false;
}

void on_new_connection(quic_conn_t* conn) {
    char remote_ip_str[46];
    uint16_t remote_port;
    quic_conn_get_remote_address(conn, remote_ip_str, sizeof(remote_ip_str), &remote_port);
    log_info("main.c: New connection established from %s:%d.", remote_ip_str, remote_port);

    peer_t* peer = find_peer(remote_ip_str, remote_port);
    if (peer == NULL) {
        peer = add_peer(remote_ip_str, remote_port);
        if (peer == NULL) {
            log_error("Failed to add new peer %s:%d to list.", remote_ip_str, remote_port);
            quic_conn_close(conn);
            return;
        }
    }

    peer->state = PEER_STATE_CONNECTED;
    peer->conn = conn;
    peer->last_seen = get_current_time_ms();
    log_info("Peer %s:%d is now connected.", peer->address, peer->port);
}

void on_connection_closed(quic_conn_t* conn) {
    peer_t* current = get_peer_list();
    while (current != NULL) {
        if (current->conn == conn) {
            log_info("Peer %s:%d has disconnected.", current->address, current->port);
            current->state = PEER_STATE_DISCONNECTED;
            current->conn = NULL;
            return;
        }
        current = current->next;
    }
}

void on_new_stream(quic_conn_t* conn, void* stream) {
    log_info("main.c: New stream opened.");
}

void on_stream_data(quic_conn_t* conn, void* stream, const uint8_t *data, uint32_t len) {
    log_info("main.c: Data received on stream (length: %u).", len);
    message_header_t header;
    void* payload = NULL;
    int bytes_read = deserialize_message(data, len, &header, &payload);
    if (bytes_read < 0) {
        log_error("Failed to deserialize message from peer.");
        return;
    }
    // TODO: Handle messages
    free_message_payload(&header, payload);
}

void on_stream_closed(quic_conn_t* conn, void *stream) {
    log_info("main.c: Stream closed.");
}

int main(int argc, char *argv[]) {
    log_info("Application starting up...");
    signal(SIGINT, sigint_handler);

    app_config my_config;
    if (load_config(&my_config) != 0) {
        log_error("Failed to load configuration.");
        return 1;
    }

    peer_list_init();

    quic_callbacks_t app_quic_callbacks = {
        .on_new_connection = on_new_connection,
        .on_connection_closed = on_connection_closed,
        .on_new_stream = on_new_stream,
        .on_stream_data = on_stream_data,
        .on_stream_closed = on_stream_closed
    };

    if (quic_init(NULL, NULL, app_quic_callbacks) != 0) {
        log_error("Failed to initialize QUIC.");
        return 1;
    }

    quic_listener_t* listener = NULL;
    if (argc == 1) {
        log_info("Starting in server mode...");
        listener = quic_listen(my_config.listen_address, my_config.listen_port);
        if (listener == NULL) {
            log_error("Failed to start QUIC listener.");
            quic_cleanup();
            return 1;
        }
    } else if (argc == 3) {
        log_info("Starting in client mode...");
        const char* target_address = argv[1];
        int target_port = atoi(argv[2]);
        quic_conn_t* conn = quic_connect(target_address, target_port);
        if (conn == NULL) {
            log_error("Failed to connect to peer %s:%d", target_address, target_port);
            quic_cleanup();
            return 1;
        }
    } else {
        log_error("Usage: %s [address port]", argv[0]);
        quic_cleanup();
        return 1;
    }

    log_info("Application running. Press Ctrl+C to exit.");
    while (running) {
        sleep(1);
    }

    log_info("Initiating application shutdown...");
    if (listener != NULL) {
        quic_listener_close(listener);
    }
    peer_t* current_peer = get_peer_list();
    while (current_peer != NULL) {
        if (current_peer->conn != NULL) {
            quic_conn_close(current_peer->conn);
        }
        current_peer = current_peer->next;
    }
    quic_cleanup();
    peer_list_destroy();
    free_config(&my_config);
    log_info("Application shut down gracefully.");
    return 0;
}