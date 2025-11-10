#include "peer.h"
#include "utils.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

// The head of our peer list. Static makes it private to this file.
static peer_t* peer_list_head = NULL;

void peer_list_init(void) {
    peer_list_head = NULL;
    log_info("Peer list initialized.");
}

void peer_list_destroy(void) {
    peer_t *current = peer_list_head;
    peer_t *next;

    while (current != NULL) {
        next = current->next; // Save the next pointer

        // Free the memory owned by the struct
        if (current->address) {
            free(current->address);
        }
        free(current); // Free the struct itself

        current = next; // Move to the next node
    }

    peer_list_head = NULL;
    log_info("Peer list destroyed.");
}

peer_t* add_peer(const char *address, int port) {
    // First, check if the peer already exists.
    if (find_peer(address, port) != NULL) {
        log_warn("Peer %s:%d already in the list.", address, port);
        return NULL;
    }

    // Allocate memory for the new peer struct
    peer_t* new_peer = (peer_t*)malloc(sizeof(peer_t));
    if (new_peer == NULL) {
        log_error("Failed to allocate memory for new peer.");
        return NULL;
    }

    // Populate the new peer's data
    new_peer->address = strdup(address); // Use strdup for ownership
    if (new_peer->address == NULL) {
        log_error("Failed to duplicate address string for new peer.");
        free(new_peer);
        return NULL;
    }
    new_peer->port = port;
    new_peer->state = PEER_STATE_DISCONNECTED;
    new_peer->conn = NULL;
    new_peer->last_seen = get_current_time_ms();

    // Add the new peer to the beginning of the list
    new_peer->next = peer_list_head;
    peer_list_head = new_peer;

    log_info("Added new peer: %s:%d", address, port);
    return new_peer;
}

void remove_peer(peer_t* peer_to_remove) {
    if (peer_to_remove == NULL) {
        return;
    }

    // Case 1: The peer to remove is the head of the list
    if (peer_list_head == peer_to_remove) {
        peer_list_head = peer_to_remove->next; // Update the head
    } else {
        // Case 2: The peer is somewhere else in the list
        peer_t* current = peer_list_head;
        while (current != NULL && current->next != peer_to_remove) {
            current = current->next;
        }

        // If current is NULL, the peer wasn't in the list (shouldn't happen if used correctly)
        if (current == NULL) {
            log_warn("Attempted to remove a peer that is not in the list.");
            return;
        }

        // Unlink the peer
        current->next = peer_to_remove->next;
    }

    log_info("Removed peer: %s:%d", peer_to_remove->address, peer_to_remove->port);

    // Free the memory owned by the removed peer
    if (peer_to_remove->address) {
        free(peer_to_remove->address);
    }
    free(peer_to_remove);
}

peer_t* find_peer(const char *address, int port) {
    peer_t* current = peer_list_head;

    while (current != NULL) {
        // Correctly check for string equality (strcmp == 0)
        if (strcmp(current->address, address) == 0 && current->port == port) {
            return current; // Found it
        }
        current = current->next;
    }

    return NULL; // Not found
}

peer_t* get_peer_list(void) {
    return peer_list_head;
}

// --- Stub Functions for Database Integration ---

int load_peers_from_db(const char *db_path) {
    log_info("Database loading is not yet implemented.");
    // Here you would open the SQLite database and call add_peer() for each entry.
    return 0;
}

int save_peers_to_db(const char *db_path) {
    log_info("Database saving is not yet implemented.");
    // Here you would iterate through the list and write each peer to the database.
    return 0;
}
