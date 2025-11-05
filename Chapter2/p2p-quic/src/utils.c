#include "utils.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

// This is a single buffer would be called multiple time in the main
void sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
	SHA256_CTX ctx;

	// Initialize the SHA256 content
	SHA256_Init(&ctx);

	// Update the hash with the input
	SHA256_Update(&ctx, data, len);

	// Finalize the hash computation
	SHA256_Final(hash[32], &ctx);
}

void hash_to_hex(const uint8_t hash[32], char hexstring[65]) {
	// Each byte will become two hexadecimal character, plus a null character
	// So the hexstring size is sizeof(hash) * 2 + 1 -> To store each and every character
	for (size_t i = 0; i < 32; i++) {
		sprintf(&hexstring[i*2], "%02x", hash[i]);
	}
	hexstring[64] = '\0';
}

uint64_t get_current_time_ms(void) {
	// Structure where the time will be stored
	struct timeval tv;
	int result = gettimeofday(&tv, NULL);

	int second = result.tv_sec * 1000;
	int milli_second = result.tv_usec / 1000;

	uint64_t current_time = second + milli_second;
	return current_time;
}

uint64_t *read_file_content(const char *path, size_t file_size) {
	FILE *fp = fopen(path, "rb");
	
	// Check if the file was opened successfully
	if (fp == NULL) {
		printf("Error opening file!\n");
		return 1;
	}

	// Move the file pointer to the end
	if (fseek(fp, 0, SEEK_END) != 0) {
		printf("Error seeking file!\n");
		fclose(fp);
		return 1;
	}
	
	// Get file size
	long size = ftell(fp);
	if (size == -1L) {
		printf("Error telling file position!\n");
		fclose(fp);
		return 1;
	}
	
	rewind(fp);

	int *buffer = malloc(size);

	size_t read_bytes = fread(buffer, 1, size, fp);

	if (read_bytes != size) {
		perror("Error reading file");
		free(buffer);
		fclose(fp);
		return NULL;
	}

	fclose(fp);
	*file_size = size;
	
	return buffer;
}

int write_file_content(const char *path, const uint8_t *data, size_t size) {
	FILE *fp; 

	fopen(path, "wb");
	if (fp == NULL) {
		printf("Error opening the file!\n");
		return 1;
	}

	size_t written = fwrite(data, 1, size, fp);

	if (written != size) {
		perror("Error writing file");
		fclose(fp);
		return 1;
	}
	
	fclose(fp);
	printf("Successfully wrote %zu bytes. \n", written);
	return 0;
}

 


