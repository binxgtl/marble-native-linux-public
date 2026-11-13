/* libcrypto for the CE core, opened at run time: the island's BoringSSL (TWRP's /system/lib64/libcrypto.so,
 * the library its own vold and Keystore2 use) on the phone, the runner's OpenSSL in tests. Both export these
 * symbols with the same meaning. Nothing proprietary is linked. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

typedef void *(*ctx_new_fn)(void);
typedef void (*ctx_free_fn)(void *);
typedef const void *(*cipher_fn)(void);
typedef int (*init_fn)(void *, const void *, void *, const uint8_t *, const uint8_t *);
typedef int (*ctrl_fn)(void *, int, int, void *);
typedef int (*update_fn)(void *, uint8_t *, int *, const uint8_t *, int);
typedef int (*final_fn)(void *, uint8_t *, int *);
typedef int (*scrypt_fn)(const char *, size_t, const uint8_t *, size_t, uint64_t, uint64_t, uint64_t, size_t, uint8_t *, size_t);
typedef uint8_t *(*hmac_fn)(const void *, const void *, size_t, const uint8_t *, size_t, uint8_t *, unsigned *);
typedef const void *(*md_fn)(void);

#define CTRL_GCM_SET_IVLEN 0x9
#define CTRL_GCM_SET_TAG 0x11
#define SCRYPT_MAX_MEMORY ((size_t)64 << 20)

static struct {
    ctx_new_fn ctx_new;
    ctx_free_fn ctx_free;
    cipher_fn aes_256_gcm;
    init_fn init;
    ctrl_fn ctrl;
    update_fn update;
    final_fn final;
    scrypt_fn scrypt;
    hmac_fn hmac;
    md_fn sha256;
} lib;

static int do_scrypt(const uint8_t *password, size_t password_size, const uint8_t *salt, size_t salt_size, uint64_t n, uint64_t r,
                     uint64_t p, uint8_t *output, size_t output_size)
{
    return lib.scrypt((const char *)password, password_size, salt, salt_size, n, r, p, SCRYPT_MAX_MEMORY, output, output_size) == 1 ? 0 : -1;
}

static int do_gcm_open(const uint8_t key[32], const uint8_t nonce[M19_CE_GCM_NONCE], const uint8_t *sealed, size_t sealed_size,
                       uint8_t *output)
{
    if (sealed_size < M19_CE_GCM_TAG || sealed_size - M19_CE_GCM_TAG > 0x7fffffff)
        return -1;
    int body = (int)(sealed_size - M19_CE_GCM_TAG), produced = 0, tail = 0, ok = 0;
    uint8_t tag[M19_CE_GCM_TAG];
    for (int i = 0; i < M19_CE_GCM_TAG; i++)
        tag[i] = sealed[body + i];
    void *ctx = lib.ctx_new();
    if (!ctx)
        return -1;
    ok = lib.init(ctx, lib.aes_256_gcm(), NULL, NULL, NULL) == 1 && lib.ctrl(ctx, CTRL_GCM_SET_IVLEN, M19_CE_GCM_NONCE, NULL) == 1 &&
         lib.init(ctx, NULL, NULL, key, nonce) == 1 && lib.update(ctx, output, &produced, sealed, body) == 1 && produced == body &&
         lib.ctrl(ctx, CTRL_GCM_SET_TAG, M19_CE_GCM_TAG, tag) == 1 && lib.final(ctx, output + produced, &tail) == 1 && tail == 0;
    lib.ctx_free(ctx);
    m19_wipe(tag, sizeof(tag));
    if (!ok)
        m19_wipe(output, (size_t)body);
    return ok ? 0 : -1;
}

static int do_hmac(const uint8_t *key, size_t key_size, const uint8_t *data, size_t data_size, uint8_t output[32])
{
    unsigned size = 0;
    return lib.hmac(lib.sha256(), key, key_size, data, data_size, output, &size) && size == 32 ? 0 : -1;
}

static const struct m19_ce_crypto kCrypto = {do_scrypt, do_gcm_open, do_hmac};

const struct m19_ce_crypto *m19_ce_crypto_open(const char *path)
{
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return NULL;
#define LOAD(field, name)                                                                                                              \
    do {                                                                                                                               \
        *(void **)&lib.field = dlsym(handle, name);                                                                                    \
        if (!lib.field)                                                                                                                \
            return NULL;                                                                                                               \
    } while (0)
    LOAD(ctx_new, "EVP_CIPHER_CTX_new");
    LOAD(ctx_free, "EVP_CIPHER_CTX_free");
    LOAD(aes_256_gcm, "EVP_aes_256_gcm");
    LOAD(init, "EVP_DecryptInit_ex");
    LOAD(ctrl, "EVP_CIPHER_CTX_ctrl");
    LOAD(update, "EVP_DecryptUpdate");
    LOAD(final, "EVP_DecryptFinal_ex");
    LOAD(scrypt, "EVP_PBE_scrypt");
    LOAD(hmac, "HMAC");
    LOAD(sha256, "EVP_sha256");
#undef LOAD
    return &kCrypto;
}
