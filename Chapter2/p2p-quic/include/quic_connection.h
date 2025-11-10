#ifndef QUIC_CONNECTION_H
#define QUIC_CONNECTION_H

#include <stdint.h>
#include <stddef.h>

// Opaque QUIC connection handle.
typedef struct quic_conn_t quic_conn_t;

// Opaque QUIC listener handle.
typedef struct quic_listener_t quic_listener_t;

// Callbacks for QUIC events.
typedef struct {
    // Called when a new connection is established.
    void (*on_new_connection)(quic_conn_t *conn);
    // Called when a connection is closed.
    void (*on_connection_closed)(quic_conn_t *conn);
    // Called when a new stream is opened by the peer.
    void (*on_new_stream)(quic_conn_t *conn, void *stream);
    // Called when data is received on a stream.
    void (*on_stream_data)(quic_conn_t *conn, void *stream, const uint8_t *data, uint32_t len);
    // Called when a stream is closed.
    void (*on_stream_closed)(quic_conn_t *conn, void *stream);
} quic_callbacks_t;

// Initializes the QUIC library.
int quic_init(const char *cert_path, const char *key_path, quic_callbacks_t callbacks);

// Cleans up the QUIC library.
void quic_cleanup(void);

// Starts a QUIC listener.
quic_listener_t* quic_listen(const char *address, int port);

// Closes a QUIC listener.
void quic_listener_close(quic_listener_t *listener);

// Connects to a QUIC peer.
quic_conn_t* quic_connect(const char *address, int port);

// Closes a QUIC connection.
void quic_conn_close(quic_conn_t *conn);

// Gets the remote address of a QUIC connection.
void quic_conn_get_remote_address(quic_conn_t* conn, char* ip_buffer, size_t buffer_size, uint16_t* port);

// Sends data on a QUIC stream.
int quic_stream_send(void *stream, const uint8_t *data, uint32_t len, int fin);

#endif // QUIC_CONNECTION_H
