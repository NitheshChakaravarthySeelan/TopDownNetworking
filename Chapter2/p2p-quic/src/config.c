#include "include/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * It needs to 
 * 	Provide a reliable way to get the settings. (load_config)
 * 	Provide a way to clean up any memory used by those settings. (free_config)
 */
// Need to implement the robustness like if strdup fails due to system out of memory
int load_config(app_config *config) {
	config->listen_address 		= strdup(DEFAULT_LISTEN_ADDRESS);
	config->listen_port 		= DEFAULT_LISTEN_PORT;
	config->peer_db_path 		= strdup(DEFAULT_PEER_DB_PATH);
	config->chunks_dir_path 	= strdup(DEFAULT_CHUNKS_DIR_PATH);
	config->cert_path 		= strdup(DEFAULT_CERT_PATH);
	config->key_path 		= strdup(DEFAULT_KEY_PATH);
	return 0;
}

void free_config(app_config *config) {
	free(config->listen_address);
	free(config->peer_db_path);
	free(config->chunks_dir_path);
	free(config->cert_path);
	free(config->key_path);
}

