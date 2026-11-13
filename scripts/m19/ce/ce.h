/* M19 R7 CE unlock core: TWRP's PIN path (docs/m19-r7.md), read-only, every STOP explicit.
 * Reports status codes and counts only. No PIN, token, secret or key ever reaches output. */
#ifndef M19_CE_H
#define M19_CE_H

#include <stddef.h>
#include <stdint.h>

#include "../unlock/core.h"

#ifdef __cplusplus
extern "C" {
#endif

#define M19_CE_PIN_MIN 4
#define M19_CE_PIN_MAX 16
#define M19_CE_TOKEN_BYTES 32
#define M19_CE_HASH_BYTES 64
#define M19_CE_SECDIS_BYTES 16384
#define M19_CE_SPBLOB_MAX 512
#define M19_CE_PWD_MAX 512
#define M19_CE_AUTH_TOKEN_BYTES 69
#define M19_CE_FAKE_UID_BASE 100000u
#define M19_CE_KEYSTORE_NAMESPACE 103
#define M19_CE_ID_CHARS 16
#define M19_CE_GCM_NONCE 12
#define M19_CE_GCM_TAG 16

enum m19_ce_status {
    M19_CE_OK,
    M19_CE_ARGUMENTS,
    M19_CE_PROTECTOR,
    M19_CE_PASSWORD_DATA,
    M19_CE_SPBLOB,
    M19_CE_SECDIS,
    M19_CE_CRYPTO,
    M19_CE_GK_CONNECT,
    M19_CE_GK_REJECTED,
    M19_CE_GK_RETRY,
    M19_CE_AUTH_TOKEN,
    M19_CE_KS_CONNECT,
    M19_CE_SP_UNWRAP,
    M19_CE_SP_TAG,
    M19_CE_CE_LAYOUT,
    M19_CE_CE_TAG,
    M19_CE_EPHEMERAL,
    M19_CE_INSTALL,
    M19_CE_DE_LAYOUT,
    M19_CE_DE_DECRYPT,
    M19_CE_DB_COPY,
};

/* libcrypto, resolved from the island's BoringSSL at run time (OpenSSL in tests). */
struct m19_ce_crypto {
    int (*scrypt)(const uint8_t *password, size_t password_size, const uint8_t *salt, size_t salt_size, uint64_t n, uint64_t r,
                  uint64_t p, uint8_t *output, size_t output_size);
    /* AES-256-GCM open with a 12-byte nonce; `sealed` ends with the 16-byte tag. 0 only when the tag verifies. */
    int (*gcm_open)(const uint8_t key[32], const uint8_t nonce[M19_CE_GCM_NONCE], const uint8_t *sealed, size_t sealed_size,
                    uint8_t *output);
    int (*hmac_sha256)(const uint8_t *key, size_t key_size, const uint8_t *data, size_t data_size, uint8_t output[32]);
};

enum m19_gk_result { M19_GK_OK, M19_GK_REJECTED, M19_GK_RETRY, M19_GK_ERROR };

/* IGatekeeper/default, verify only. `token` receives the 69-byte hardware auth token on M19_GK_OK
 * (status OK or REENROLL); ERROR_RETRY_TIMEOUT is M19_GK_RETRY with its timeout. */
struct m19_ce_gatekeeper {
    int (*connect)(void *context, int *detail);
    int (*verify)(void *context, uint32_t uid, const uint8_t *handle, size_t handle_size, const uint8_t *provided,
                  size_t provided_size, uint8_t *token, size_t token_capacity, size_t *token_size, uint32_t *timeout_ms, int *detail);
};

/* The parsed hw_auth_token_t, as TWRP hands it to IKeystoreAuthorization. */
struct m19_ce_auth_token {
    int64_t challenge, user_id, authenticator_id;
    int32_t authenticator_type;
    int64_t timestamp_ms;
    uint8_t mac[32];
};

struct m19_ce_keystore {
    int (*connect)(void *context, int *detail); /* IKeystoreService and IKeystoreAuthorization */
    int (*add_auth_token)(void *context, const struct m19_ce_auth_token *token, int *detail);
    /* getKeyEntry {SELINUX, 103, alias}, then createOperation(AES, GCM, NONE, DECRYPT, nonce, 128, forced) and finish. */
    int (*sp_decrypt)(void *context, const char *alias, const uint8_t nonce[M19_CE_GCM_NONCE], const uint8_t *sealed,
                      size_t sealed_size, uint8_t *output, size_t capacity, size_t *size, int *detail);
};

/* FS_IOC_ADD_ENCRYPTION_KEY with the hardware-wrapped flag, on the read-only /data mount. */
struct m19_ce_fs {
    int (*add_key)(void *context, const uint8_t *raw, size_t raw_size, int *detail);
};

struct m19_ce_env {
    int spblob_dir;  /* system_de/<user>/spblob */
    int ce_dir;      /* misc/vold/user_keys/ce/<user>/current */
    uint32_t user;
    const struct m19_ce_crypto *crypto;
    const struct m19_ce_gatekeeper *gatekeeper;
    void *gatekeeper_context;
    const struct m19_ce_keystore *keystore;
    void *keystore_context;
    const struct m19_keystore_ops *storage; /* R1's connect and convertStorageKeyToEphemeral */
    void *storage_context;
    const struct m19_ce_fs *fs;
    void *fs_context;
};

struct m19_ce_pwd {
    uint32_t credential_type;
    uint8_t log_n, log_r, log_p;
    const uint8_t *salt;
    size_t salt_size;
    const uint8_t *handle;
    size_t handle_size;
};

struct m19_ce_report {
    int detail;
    int spblob_version;
    uint32_t gk_timeout_ms;
    int upgraded;
};

const char *m19_ce_status_name(enum m19_ce_status status);
void m19_ce_personalized(const char *label, const uint8_t *data, size_t size, uint8_t output[M19_CE_HASH_BYTES]);
int m19_ce_sp800(const struct m19_ce_crypto *crypto, const uint8_t *key, size_t key_size, const char *label, const char *context,
                 uint8_t output[32]);
int m19_ce_parse_pwd(const uint8_t *data, size_t size, struct m19_ce_pwd *pwd);
int m19_ce_parse_auth_token(const uint8_t *data, size_t size, struct m19_ce_auth_token *token);
int m19_ce_check_pin(const char *pin, size_t size);
/* Exactly one "<16 hex>.pwd" in the directory, with its .spblob and .secdis. */
int m19_ce_find_protector(int spblob_dir, char id[M19_CE_ID_CHARS + 1]);
enum m19_ce_status m19_ce_unlock(const struct m19_ce_env *env, const char *pin, size_t pin_size, struct m19_ce_report *report);
/* R1's keystore-bound key directory (DE system, DE user): decrypt, make ephemeral, add to the filesystem. */
enum m19_ce_status m19_ce_install_keystore_key(const char *directory, const struct m19_keystore_ops *storage, void *storage_context,
                                               const struct m19_ce_fs *fs, void *fs_context, int *detail, int *upgraded);
/* TWRP's copySqliteDb: the running Keystore2's own file is overwritten in place, the source only read. */
enum m19_ce_status m19_ce_copy_db(const char *source, const char *target);

#ifdef __cplusplus
}
#endif

#endif
