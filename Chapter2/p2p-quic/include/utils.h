#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

// Calculates the SHA-256 hash of a buffer.
void sha256(const uint8_t *data, size_t len, uint8_t hash[32]);

// Converts a binary hash to a hex string.
void hash_to_hex(const uint8_t hash[32], char hex_string[65]);

// Returns the current time in milliseconds since the epoch.
uint64_t get_current_time_ms(void);

// Reads the entire content of a file into a buffer.
// The caller is responsible for freeing the returned buffer.
uint8_t *read_file_content(const char *path, size_t *file_size);

// Writes a buffer to a file.
int write_file_content(const char *path, const uint8_t *data, size_t size);

#endif // UTILS_H
