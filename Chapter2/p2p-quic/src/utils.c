#include "utils.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

// Calculates the SHA-256 hash of a buffer.
void sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);
}

// Converts a binary hash to a hex string.
void hash_to_hex(const uint8_t hash[32], char hex_string[65]) {
    for (int i = 0; i < 32; i++) {
        sprintf(hex_string + (i * 2), "%02x", hash[i]);
    }
    hex_string[64] = 0;
}

// Returns the current time in milliseconds since the epoch.
uint64_t get_current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

// Reads the entire content of a file into a buffer.
// The caller is responsible for freeing the returned buffer.
uint8_t *read_file_content(const char *path, size_t *file_size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    *file_size = size;
    fseek(f, 0, SEEK_SET);

    uint8_t *buffer = (uint8_t *)malloc(*file_size);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    if (fread(buffer, 1, *file_size, f) != *file_size) {
        free(buffer);
        fclose(f);
        return NULL;
    }

    fclose(f);
    return buffer;
}

// Writes a buffer to a file.
int write_file_content(const char *path, const uint8_t *data, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }

    if (fwrite(data, 1, size, f) != size) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}