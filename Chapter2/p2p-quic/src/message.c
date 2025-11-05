#include "include/message.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int serialize_message(const message_header_t *header, const void *payload, uint8_t *buffer, size_t buffer_size) {
	// Boundary Checking 
	// total_size_msg = sizeof(message_header_t) + header->length
	
	size_t total_size_msg = sizeof(message_header_t) + header->length;

	if (total_size_msg > buffer_size) {
		printf("The total size is greater than the buffer.\n");
		return -1;
	}

	// Copy the header to the buffer
	memcpy(buffer, header, sizeof(message_header_t));

	// Copy the payload returns *void so it could be one of many types by casting the payload to the required type
	switch (header->type) {
		case MSG_TYPE_FILE_INFO_REQUEST: {
							 msg_file_info_request_t *req = (msg_file_info_request_t *)payload;
							 memcpy(buffer + sizeof(message_header_t), req, sizeof(msg_file_info_request_t));
							 break;
						 }
		case MSG_TYPE_FILE_INFO_RESPONSE: {
							  msg_file_info_response_t *res = (msg_file_info_response_t *) payload;
							  memcpy(buffer + sizeof(message_header_t), res, sizeof(msg_file_info_response_t));
							  break;
						  }
		case MSG_TYPE_CHUNK_REQUEST: {
						     msg_chunk_request_t *req = (msg_chunk_request *) payload;
						     memcpy(buffer + sizeof(message_header_t), req, sizeof(msg_chunk_request));
						     break;
					     }
		case MST_TYPE_CHUNK_RESPONSE: {
						      msg_chunk_response_t *res = (msg_chunk_response *) payload;
						      uint8_t *dest = buffer + sizeof(message_header_t);

						      // First lets copy the fixed fields
						      memcpy(dest, &payload.file_hash, FILE_HASH_SIZE);
						      memcpy(dest + FILE_HASH_SIZE, &payload.chunk_index, sizeof(payload.chunk_index));
						      memcpy(dest + FILE_HASH_SIZE + sizeof(payload.chunk_index), &payload.chunk_size, sizeof(payload.chunk_size));

						      // Now copy the ptr value
						      memcpy(dest + FILE_HASH_SIZE + sizeof(payload.chunk_index) + sizeof(payload.chunk_size), payload.chunk_data, payload.chunk_size);
						      break;
					      }
		default:
					      return -1;
	}

	// Return total bytes written
	return sizeof(message_header_t) + header->length;
}

/**
 * *buffer -> The raw data
 * buffer_size -> Total bytes available 
 * *header -> We fill in with the message header
 * **payload -> We allocate and return a pointer to the message *payload
 */
int deserialize_message(const uint8_t *buffer, size_t buffer_size, message_header_t *header, void **payload) {

	if (buffer_size < sizeof(message_header_t)) {
			return -1;
	}

	memcpy(header, buffer, buffer_size);

	if (buffer_size < sizeof(message_header_t) + header->length) {
		return -1;
	}

	switch (header->type) {
		case MSG_TYPE_FILE_INFO_REQUEST: {
							 *payload = malloc(sizeof(msg_file_info_request_t));
							 if (*payload == NULL) {
								 return -1;
							 }

							 memcpy(*payload, buffer + sizeof(message_header_t), sizeof(msg_file_info_request_t));
							 break;
						 }
		case MSG_TYPE_FILE_INFO_RESPONSE: {
							  *payload = malloc(sizeof(msg_file_info_response_t));
							  if (*payload == NULL) {
								  return -1;
							  }

							  memcpy(*payload, buffer + sizeof(message_header_t), sizeof(msg_file_info_response_t));
							  break;
						  }
		case MSG_TYPE_CHUNK_REQUEST: {
						     *payload = malloc(sizeof(msg_chunk_request));
						     if (*payload == NULL) {
							     return -1;
						     }

						     memcpy(*payload, buffer + sizeof(message_header_t), sizeof(msg_chunk_request));
						     break;
					     }
		case MAS_TYPE_CHUNK_RESPONSE: {
						      const uint8_t *ptr = buffer + sizeof(message_header_t);

						      msg_chunk_response_t *msg = malloc(sizeof(*msg));
						      
						      if (!msg) return -1;

						      memcpy(&msg->file_hash, ptr, FILE_HASH_SIZE);
						      ptr += FILE_HASH_SIZE;
						      memcpy(&msg->chunk_index, ptr, sizeof(msg->chunk_index));
						      ptr += sizeof(msg->chunk_index);
            						memcpy(&msg->chunk_size, ptr, sizeof(msg->chunk_size));
            						ptr += sizeof(msg->chunk_size);

            						msg->chunk_data = malloc(msg->chunk_size);
            						if (!msg->chunk_data) { free(msg); return -1; }

            						memcpy(msg->chunk_data, ptr, msg->chunk_size);
            						*payload = msg;
            						break;
        }
		default:
					      return -1;
	}

	return sizeof(message_header_t) + header->length;
}

void free_message_payload(message_header_t *header, void *payload) {
	if (!payload || !header) {
		printf("Payload is null");
		return;
	}

	switch (header->type) {
		case MSG_TYPE_FILE_INFO_REQUEST: {
							 free(payload);
							 break;
						 }
		case MSG_TYPE_FILE_INFO_RESPONSE: {
							  free(payload);
							  break;
						  }
		case MSG_TYPE_CHUNK_REQUEST: {
						     free(payload);
						     break;
					     }
		case MSG_TYPE_CHUNK_RESPONSE: {
						      msg_chunk_response_t *msg = (msg_chunk_response_t *)payload;
						      if (msg->chunk_data != NULL) {
							      free(msg->chunk_data);
						      }
						      free(msg);
						      break;
					      }
		default:
					      free(payload);
					      break;
	}
}
