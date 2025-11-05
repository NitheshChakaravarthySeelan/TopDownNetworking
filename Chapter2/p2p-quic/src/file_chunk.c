#include "file_chunk.h"
#include "utils.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int calculate_file_hash(const char *file_path, uint8_t file_hash[SHA256_DIGEST_LENGTH]) {
    FILE *f = NULL;
    SHA256_CTX sha256_context;
    uint8_t buffer[8192];
    size_t bytes_read;
    int ret = -1;

    if (!SHA256_Init(&sha256_context)) {
        log_error("Failed to initialize SHA256 context");
        return -1;
    }

    f = fopen(file_path, "rb");
    if (!f) {
        log_error("Could not open file for hashing: %s", file_path);
        return -1;
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        if (!SHA256_Update(&sha256_context, buffer, bytes_read)) {
            log_error("SHA256_Update failed");
            goto cleanup;
        }
    }

    if (ferror(f)) {
        log_error("Error reading from file: %s", file_path);
        goto cleanup;
    }

    if (!SHA256_Final(file_hash, &sha256_context)) {
        log_error("SHA256_Final failed");
        goto cleanup;
    }

    ret = 0; // Success

cleanup:
    if (f) {
        fclose(f);
    }
    return ret;
}

int write_chunk(const char *chunks_dir, const file_chunk_t *chunk) {
    char file_hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    char dir_path[PATH_MAX];
    char chunk_path[PATH_MAX];

    hash_to_hex(chunk->file_hash, file_hash_hex);

    snprintf(dir_path, sizeof(dir_path), "%s/%s", chunks_dir, file_hash_hex);

    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
        log_error("Failed to create directory: %s", dir_path);
        return -1;
    }

    snprintf(chunk_path, sizeof(chunk_path), "%s/%u", dir_path, chunk->chunk_index);

    if (write_file_content(chunk_path, chunk->data, chunk->chunk_size) != 0) {
        log_error("Failed to write chunk to: %s", chunk_path);
        return -1;
    }

    return 0;
}

file_chunk_t* read_chunk(const char *chunks_dir, const uint8_t file_hash[FILE_HASH_SIZE], uint32_t chunk_index) {
    char file_hash_hex[FILE_HASH_SIZE * 2 + 1];
    char chunk_path[PATH_MAX];
    size_t chunk_size;

    hash_to_hex(file_hash, file_hash_hex);
    snprintf(chunk_path, sizeof(chunk_path), "%s/%s/%u", chunks_dir, file_hash_hex, chunk_index);

    uint8_t *chunk_data = read_file_content(chunk_path, &chunk_size);
    if (!chunk_data) {
        log_error("Failed to read chunk from: %s", chunk_path);
        return NULL;
    }

    file_chunk_t *chunk = (file_chunk_t*)malloc(sizeof(file_chunk_t));
    if (!chunk) {
        free(chunk_data);
        log_error("Failed to allocate memory for file_chunk_t");
        return NULL;
    }

    memcpy(chunk->file_hash, file_hash, FILE_HASH_SIZE);
    chunk->chunk_index = chunk_index;
    chunk->chunk_size = chunk_size;
    chunk->data = chunk_data;
    // Note: chunk->chunk_hash is not populated here, as it's not stored in the file.
    // Verification must be done by the caller who has the file's metadata.

    return chunk;
}

int chunk_file(const char *file_path, const char *chunks_dir) {
    uint8_t file_hash[FILE_HASH_SIZE];
    FILE *f = NULL;
    uint8_t buffer[DEFAULT_CHUNK_SIZE];
    size_t bytes_read;
    uint32_t chunk_index = 0;
    int ret = -1;

    if (calculate_file_hash(file_path, file_hash) != 0) {
        log_error("Failed to calculate file hash for %s", file_path);
        return -1;
    }

    f = fopen(file_path, "rb");
    if (!f) {
        log_error("Failed to open file for chunking: %s", file_path);
        return -1;
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        file_chunk_t chunk;
        memcpy(chunk.file_hash, file_hash, FILE_HASH_SIZE);
        chunk.chunk_index = chunk_index;
        chunk.data = buffer;
        chunk.chunk_size = bytes_read;

        // Here we use the simple sha256 wrapper because the chunk is fully in memory
        sha256(chunk.data, chunk.chunk_size, chunk.chunk_hash);

        if (write_chunk(chunks_dir, &chunk) != 0) {
            log_error("Failed to write chunk %u", chunk_index);
            goto cleanup;
        }
        chunk_index++;
    }

    if (ferror(f)) {
        log_error("Error reading from file during chunking: %s", file_path);
        goto cleanup;
    }

    log_info("Successfully split file %s into %u chunks.", file_path, chunk_index);
    ret = 0; // Success

cleanup:
    if (f) {
        fclose(f);
    }
    return ret;
}

int reassemble_file(const char *output_file_path, const char *chunks_dir, const uint8_t file_hash[FILE_HASH_SIZE], uint32_t chunk_count) {
    FILE *f_out = NULL;
    int ret = -1;

    f_out = fopen(output_file_path, "wb");
    if (!f_out) {
        log_error("Failed to open output file for reassembly: %s", output_file_path);
        return -1;
    }

    for (uint32_t i = 0; i < chunk_count; i++) {
        file_chunk_t *chunk = read_chunk(chunks_dir, file_hash, i);
        if (!chunk) {
            log_error("Failed to read chunk %u for reassembly.", i);
            goto cleanup;
        }

        // Optional: Verify chunk hash here if you have the list of expected hashes

        if (fwrite(chunk->data, 1, chunk->chunk_size, f_out) != chunk->chunk_size) {
            log_error("Failed to write chunk %u to output file.", i);
            free_chunk(chunk);
            goto cleanup;
        }

        free_chunk(chunk);
    }

    log_info("Successfully reassembled file %s from %u chunks.", output_file_path, chunk_count);
    ret = 0; // Success

cleanup:
    if (f_out) {
        fclose(f_out);
        if (ret != 0) {
            remove(output_file_path); // Clean up partial file on failure
        }
    }
    return ret;
}

void free_chunk(file_chunk_t *chunk) {
    if (!chunk) {
        return;
    }
    if (chunk->data) {
        free(chunk->data);
    }
    free(chunk);
}