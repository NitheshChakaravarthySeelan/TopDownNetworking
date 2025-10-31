#ifndef PEER_H
#define PEER_H

#include <stdint.h>
#include "quic_eonnection.h"

typedef enum {
    PEER_STATE_DISCONNECTED,
    PEER_STATE_CONNECTING,
    PEER_STATE_CONNECTED,
} peer_state_t;

typedef struct peer_t {
    char *address;
    int port;
    peer_state_t state;
    quic_conn_t *conn;
    uint64_t last_seen;
    struct peer_t *next;
} peer_t;

// Initializes the peer list.
void peer_list_init(void);

// Frees the peer list.
void peer_list_destroy(void);

// Adds a peer to the list.
peer_t* add_peer(const char *address, int port);

// Removes a peer from the list.
void remove_peer(peer_t *peer);

// Finds a peer by address and port.
peer_t* find_peer(const char *address, int port);

// Gets the head of the peer list.
peer_t* get_peer_list(void);

// Loads peers from the database.
int load_peers_from_db(const char *db_path);

// Saves peers to the database.
int save_peers_to_db(const char *db_path);

#endif // PEER_H
