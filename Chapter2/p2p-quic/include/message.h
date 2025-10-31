#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdint.h>
#include <stddef.h>

#define FILE_HASH_SIZE 32
#define CHUNK_HASH_SIZE 32

typedef enum {
    MSG_TYPE_HANDSHAKE,
    MSG_TYPE_FILE_INFO_REQUEST,
    MSG_TYPE_FILE_INFO_RESPONSE,
    MSG_TYPE_CHUNK_REQUEST,
    MSG_TYPE_CHUNK_RESPONSE,
    MSG_TYPE_PEER_LIST_REQUEST,
    MSG_TYPE_PEER_LIST_RESPONSE,
} message_type_t;

typedef struct {
    message_type_t type;
    uint32_t length; // Length of the payload
} message_header_t;

// Payload for MSG_TYPE_FILE_INFO_REQUEST
typedef struct {
    uint8_t file_hash[FILE_HASH_SIZE];
} msg_file_info_request_t;

// Payload for MSG_TYPE_FILE_INFO_RESPONSE
typedef struct {
    uint8_t file_hash[FILE_HASH_SIZE];
    uint64_t file_size;
    uint32_t chunk_size;
    uint32_t chunk_count;
} msg_file_info_response_t;

// Payload for MSG_TYPE_CHUNK_REQUEST
typedef struct {
    uint8_t file_hash[FILE_HASH_SIZE];
    uint32_t chunk_index;
} msg_chunk_request_t;

// Payload for MSG_TYPE_CHUNK_RESPONSE
typedef struct {
    uint8_t file_hash[FILE_HASH_SIZE];
    uint32_t chunk_index;
    uint32_t chunk_size;
    uint8_t *chunk_data; // Variable length
} msg_chunk_response_t;

// Serializes a message into a buffer.
// Returns the number of bytes written to the buffer, or -1 on error.
int serialize_message(const message_header_t *header, const void *payload, uint8_t *buffer, size_t buffer_size);

// Deserializes a message from a buffer.
// The caller is responsible for freeing the payload if it contains dynamically allocated memory.
// Returns the number of bytes read from the buffer, or -1 on error.
int deserialize_message(const uint8_t *buffer, size_t buffer_size, message_header_t *header, void **payload);

void free_message_payload(message_header_t *header, void *payload);

#endif // MESSAGE_H
