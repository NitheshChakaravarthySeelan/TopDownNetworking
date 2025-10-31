#ifndef CONFIG_H
#define CONFIG_H

#define DEFAULT_LISTEN_ADDRESS "0.0.0.0"
#define DEFAULT_LISTEN_PORT 1234
#define DEFAULT_PEER_DB_PATH "data/peers.db"
#define DEFAULT_CHUNKS_DIR_PATH "data/chunks"
#define DEFAULT_CERT_PATH "assets/certs/cert.pem"
#define DEFAULT_KEY_PATH "assets/certs/key.pem"

typedef struct {
    char *listen_address;
    int listen_port;
    char *peer_db_path;
    char *chunks_dir_path;
    char *cert_path;
    char *key_path;
} app_config;

int load_config(app_config *config);
void free_config(app_config *config);

#endif // CONFIG_H
