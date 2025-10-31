#ifndef FILE_CHUNK_H
#define FILE_CHUNK_H

#include <stdint.h>
#include <stddef.h>

#define FILE_HASH_SIZE 32
#define CHUNK_HASH_SIZE 32
#define DEFAULT_CHUNK_SIZE (1024 * 256) // 256 KB

typedef struct {
    uint8_t file_hash[FILE_HASH_SIZE];
    uint32_t chunk_index;
    uint32_t chunk_size;
    uint8_t chunk_hash[CHUNK_HASH_SIZE];
    uint8_t *data;
} file_chunk_t;

// Calculates the hash of a file.
int calculate_file_hash(const char *file_path, uint8_t file_hash[FILE_HASH_SIZE]);

// Splits a file into chunks and stores them in the chunks directory.
int chunk_file(const char *file_path, const char *chunks_dir);

// Reassembles a file from its chunks.
int reassemble_file(const char *output_file_path, const char *chunks_dir, const uint8_t file_hash[FILE_HASH_SIZE], uint32_t chunk_count);

// Reads a chunk from the chunk store.
file_chunk_t* read_chunk(const char *chunks_dir, const uint8_t file_hash[FILE_HASH_SIZE], uint32_t chunk_index);

// Writes a chunk to the chunk store.
int write_chunk(const char *chunks_dir, const file_chunk_t *chunk);

// Frees a file_chunk_t struct.
void free_chunk(file_chunk_t *chunk);

#endif // FILE_CHUNK_H
