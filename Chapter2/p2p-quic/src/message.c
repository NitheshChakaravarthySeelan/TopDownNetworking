#include "message.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

// Helper to safely copy data into a buffer and advance the pointer
static void encode_buffer(uint8_t** buffer, const void* data, size_t size) {
    memcpy(*buffer, data, size);
    *buffer += size;
}

// Helper to safely read data from a buffer and advance the pointer
static void decode_buffer(uint8_t** buffer, void* data, size_t size) {
    memcpy(data, *buffer, size);
    *buffer += size;
}

int serialize_message(const message_header_t *header, const void *payload, uint8_t *buffer, size_t buffer_size) {
    size_t total_size = sizeof(message_header_t) + header->length;
    if (buffer_size < total_size) {
        return -1; // Buffer too small
    }

    uint8_t* p = buffer;
    encode_buffer(&p, header, sizeof(message_header_t));

    switch (header->type) {
        case MSG_TYPE_FILE_INFO_REQUEST:
        case MSG_TYPE_FILE_INFO_RESPONSE:
        case MSG_TYPE_CHUNK_REQUEST:
            // These have fixed-size payloads
            encode_buffer(&p, payload, header->length);
            break;
        case MSG_TYPE_CHUNK_RESPONSE: {
            const msg_chunk_response_t* msg = (const msg_chunk_response_t*)payload;
            // Manually serialize variable-length message
            encode_buffer(&p, &msg->file_hash, FILE_HASH_SIZE);
            encode_buffer(&p, &msg->chunk_index, sizeof(msg->chunk_index));
            encode_buffer(&p, &msg->chunk_size, sizeof(msg->chunk_size));
            encode_buffer(&p, msg->chunk_data, msg->chunk_size);
            break;
        }
        // Handshake, Peer List Request/Response are not implemented yet
        default:
            // For messages with no payload, do nothing
            break;
    }

    return total_size;
}

int deserialize_message(const uint8_t *buffer, size_t buffer_size, message_header_t *header, void **payload) {
    if (buffer_size < sizeof(message_header_t)) {
        return -1; // Not enough data for a header
    }

    uint8_t* p = (uint8_t*)buffer;
    decode_buffer(&p, header, sizeof(message_header_t));

    if (buffer_size < sizeof(message_header_t) + header->length) {
        return -1; // Not enough data for the full payload
    }

    if (header->length == 0) {
        *payload = NULL;
        return sizeof(message_header_t);
    }

    *payload = malloc(header->length);
    if (*payload == NULL) {
        return -1; // Out of memory
    }

    switch (header->type) {
        case MSG_TYPE_FILE_INFO_REQUEST:
        case MSG_TYPE_FILE_INFO_RESPONSE:
        case MSG_TYPE_CHUNK_REQUEST:
            decode_buffer(&p, *payload, header->length);
            break;
        case MSG_TYPE_CHUNK_RESPONSE: {
            msg_chunk_response_t* msg = (msg_chunk_response_t*)malloc(sizeof(msg_chunk_response_t));
            if (msg == NULL) { free(*payload); *payload = NULL; return -1; }
            
            decode_buffer(&p, &msg->file_hash, FILE_HASH_SIZE);
            decode_buffer(&p, &msg->chunk_index, sizeof(msg->chunk_index));
            decode_buffer(&p, &msg->chunk_size, sizeof(msg->chunk_size));
            
            // The actual chunk data is the rest of the payload
            size_t data_size = header->length - (FILE_HASH_SIZE + sizeof(uint32_t) + sizeof(uint32_t));
            msg->chunk_data = (uint8_t*)malloc(data_size);
            if (msg->chunk_data == NULL) { free(msg); free(*payload); *payload = NULL; return -1; }
            
            decode_buffer(&p, msg->chunk_data, data_size);
            
            free(*payload); // Free the initial generic payload
            *payload = msg; // Point to the structured payload
            break;
        }
        default:
            // For unknown types with a payload, just copy the raw payload
            decode_buffer(&p, *payload, header->length);
            break;
    }

    return sizeof(message_header_t) + header->length;
}

void free_message_payload(message_header_t *header, void *payload) {
    if (payload == NULL) {
        return;
    }

    if (header->type == MSG_TYPE_CHUNK_RESPONSE) {
        msg_chunk_response_t* msg = (msg_chunk_response_t*)payload;
        if (msg->chunk_data) {
            free(msg->chunk_data);
        }
    }

    free(payload);
}