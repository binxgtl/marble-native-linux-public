/* M19 metadata unlock core. Reports status codes only and never prints key material. */
#ifndef M19_CORE_H
#define M19_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M19_KEY_MAX 4096
#define M19_SECDISCARDABLE_BYTES 16384
#define M19_NONCE_BYTES 12
#define M19_MAC_BYTES 16
#define M19_HASH_BYTES 64
#define M19_PARAMS_MAX (2 * M19_KEY_MAX + 256)

enum m19_status {
    M19_OK,
    M19_ARGUMENTS,
    M19_LAYOUT,
    M19_VERSION,
    M19_UPGRADE_PENDING,
    M19_SECDISCARDABLE,
    M19_CONNECT,
    M19_DECRYPT,
    M19_UPGRADE_REQUIRED,
    M19_EPHEMERAL,
    M19_SIZE,
    M19_TABLE,
};

enum m19_keystore_result { M19_KS_OK, M19_KS_ERROR, M19_KS_UPGRADE };

struct m19_decrypt_request {
    const uint8_t *blob;
    size_t blob_size;
    const uint8_t *app_id;
    size_t app_id_size;
    const uint8_t *nonce;
    size_t nonce_size;
    const uint8_t *body_and_mac;
    size_t body_and_mac_size;
};

struct m19_keystore_ops {
    int (*connect)(void *context, int *detail);
    int (*decrypt)(void *context, const struct m19_decrypt_request *request, uint8_t *output, size_t capacity,
                   size_t *size, int *detail);
    int (*ephemeral)(void *context, const uint8_t *storage_key, size_t storage_key_size, uint8_t *output,
                     size_t capacity, size_t *size, int *detail);
};

struct m19_dm_ops {
    int (*sectors)(void *context, const char *device, uint64_t *sectors);
    int (*create)(void *context, const char *name);
    int (*load)(void *context, const char *name, uint64_t sectors, const char *target, const char *parameters);
    int (*resume)(void *context, const char *name);
    int (*remove)(void *context, const char *name);
};

struct m19_target {
    const char *name;
    const char *device;
    uint64_t sectors;
};

struct m19_key_dir {
    uint8_t blob[M19_KEY_MAX];
    size_t blob_size;
    uint8_t encrypted[M19_KEY_MAX];
    size_t encrypted_size;
    uint8_t app_id[M19_HASH_BYTES];
};

const char *m19_status_name(enum m19_status status);
void m19_wipe(void *data, size_t size);
void m19_sha256(const void *data, size_t size, uint8_t digest[32]);
void m19_sha512_parts(const void *first, size_t first_size, const void *second, size_t second_size, uint8_t digest[64]);
void m19_app_id(const uint8_t *secdiscardable, size_t size, uint8_t digest[M19_HASH_BYTES]);
enum m19_status m19_read_key_dir(const char *directory, struct m19_key_dir *keys);
int m19_table_parameters(const uint8_t *key, size_t key_size, const char *device, char *output, size_t capacity);
enum m19_status m19_metadata_unlock(const char *directory, const struct m19_target *target,
                                    const struct m19_keystore_ops *keystore, void *keystore_context,
                                    const struct m19_dm_ops *dm, void *dm_context, int *detail);

#ifdef __cplusplus
}
#endif

#endif
