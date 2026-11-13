/* The real ce.c, crypto.c and fscrypt.c layout on synthetic fixtures from model.py. Fakes stand in for
 * Gatekeeper, Keystore2 and the filesystem; each checks what TWRP's own path would hand it. Never staged. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ce.h"
#include "crypto.h"
#include "fscrypt.h"

size_t m19_ce_test_residue(void); /* ce.c built with M19_CE_TEST */

static const struct m19_ce_crypto *crypto;
static const char *fault = "none";
static uint8_t fx_handle[256], fx_provided[64], fx_auth[69], fx_key[32], fx_ephemeral[64], fx_alias[64];
static size_t fx_handle_size, fx_ephemeral_size, fx_alias_size;
static int gk_calls, gk_connects, auth_added, sp_calls, installed, matched, storage_connected, order_ok = 1;

static int faulted(const char *name)
{
    return !strcmp(fault, name);
}

static size_t unhex(const char *text, uint8_t *out, size_t capacity)
{
    size_t length = strlen(text), size = length / 2;
    if (length % 2 || size > capacity)
        exit(90);
    for (size_t i = 0; i < size; i++) {
        unsigned value;
        if (sscanf(text + 2 * i, "%2x", &value) != 1)
            exit(91);
        out[i] = (uint8_t)value;
    }
    return size;
}

static void load_fixture(const char *root)
{
    char path[4096], line[40000];
    snprintf(path, sizeof(path), "%s/fixture.txt", root);
    FILE *file = fopen(path, "r");
    if (!file)
        exit(92);
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;
        char *value = strchr(line, '=');
        if (!value)
            continue;
        *value++ = 0;
        if (!strcmp(line, "handle"))
            fx_handle_size = unhex(value, fx_handle, sizeof(fx_handle));
        else if (!strcmp(line, "provided"))
            unhex(value, fx_provided, sizeof(fx_provided));
        else if (!strcmp(line, "auth"))
            unhex(value, fx_auth, sizeof(fx_auth));
        else if (!strcmp(line, "keystore_key"))
            unhex(value, fx_key, sizeof(fx_key));
        else if (!strcmp(line, "ephemeral"))
            fx_ephemeral_size = unhex(value, fx_ephemeral, sizeof(fx_ephemeral));
        else if (!strcmp(line, "alias"))
            fx_alias_size = unhex(value, fx_alias, sizeof(fx_alias) - 1);
    }
    fclose(file);
}

/* Gatekeeper: what the TA checks, the enrolled handle and the provided password, for the SP's fake uid. */
static int gk_connect(void *context, int *detail)
{
    (void)context;
    gk_connects++;
    if (faulted("gk-connect")) {
        *detail = -2;
        return -1;
    }
    return 0;
}

static int gk_verify(void *context, uint32_t uid, const uint8_t *handle, size_t handle_size, const uint8_t *provided, size_t provided_size,
                     uint8_t *token, size_t capacity, size_t *token_size, uint32_t *timeout, int *detail)
{
    (void)context;
    gk_calls++;
    order_ok &= storage_connected && gk_connects == 1;
    if (faulted("gk-error"))
        return M19_GK_ERROR;
    if (faulted("gk-retry")) {
        *timeout = 30000;
        return M19_GK_RETRY;
    }
    if (uid != 100000 || handle_size != fx_handle_size || memcmp(handle, fx_handle, handle_size) || provided_size != 64 ||
        memcmp(provided, fx_provided, 64)) {
        *detail = -1;
        return M19_GK_REJECTED;
    }
    if (capacity < sizeof(fx_auth))
        return M19_GK_ERROR;
    memcpy(token, fx_auth, sizeof(fx_auth));
    *token_size = faulted("gk-short-token") ? 68 : sizeof(fx_auth);
    return M19_GK_OK;
}

static const struct m19_ce_gatekeeper gatekeeper = {gk_connect, gk_verify};

static uint64_t be64(const uint8_t *at)
{
    uint64_t value = 0;
    for (int i = 0; i < 8; i++)
        value = value << 8 | at[i];
    return value;
}

static int ks_connect(void *context, int *detail)
{
    (void)context;
    if (faulted("ks-connect")) {
        *detail = -3;
        return -1;
    }
    return 0;
}

/* Keystore2 accepts a token only when Gatekeeper's MAC and timestamp arrive unchanged. */
static int ks_add_auth_token(void *context, const struct m19_ce_auth_token *token, int *detail)
{
    (void)context;
    if (faulted("auth-reject") || memcmp(token->mac, fx_auth + 37, 32) || (uint64_t)token->timestamp_ms != be64(fx_auth + 29) ||
        token->authenticator_type != 2) {
        *detail = -4;
        return -1;
    }
    auth_added++;
    return 0;
}

/* The SP key is auth-bound: Keystore2 refuses it until an auth token was added. */
static int ks_sp_decrypt(void *context, const char *alias, const uint8_t nonce[12], const uint8_t *sealed, size_t sealed_size,
                         uint8_t *output, size_t capacity, size_t *size, int *detail)
{
    (void)context;
    sp_calls++;
    if (!auth_added || strlen(alias) != fx_alias_size || memcmp(alias, fx_alias, fx_alias_size) || sealed_size < 16 ||
        sealed_size - 16 > capacity) {
        *detail = -5;
        return -1;
    }
    if (crypto->gcm_open(fx_key, nonce, sealed, sealed_size, output)) {
        *detail = -6;
        return -1;
    }
    *size = sealed_size - 16;
    return 0;
}

static const struct m19_ce_keystore keystore = {ks_connect, ks_add_auth_token, ks_sp_decrypt};

static int st_connect(void *context, int *detail)
{
    (void)context;
    (void)detail;
    storage_connected = 1;
    return faulted("storage-connect") ? M19_KS_ERROR : M19_KS_OK;
}

/* The fake KeyMint binds a DE key to its blob and application id, as TAG_APPLICATION_ID does. */
static int st_decrypt(void *context, const struct m19_decrypt_request *request, uint8_t *output, size_t capacity, size_t *size,
                      int *detail)
{
    (void)context;
    static uint8_t joined[16 + 4096 + 64];
    static const char tag[] = "m19-fake-keymint";
    uint8_t key[32];
    if (request->blob_size > 4096 || request->app_id_size != 64 || request->nonce_size != 12 || request->body_and_mac_size < 16 ||
        request->body_and_mac_size - 16 > capacity)
        return M19_KS_ERROR;
    memcpy(joined, tag, 16);
    memcpy(joined + 16, request->blob, request->blob_size);
    memcpy(joined + 16 + request->blob_size, request->app_id, 64);
    m19_sha256(joined, 16 + request->blob_size + 64, key);
    if (crypto->gcm_open(key, request->nonce, request->body_and_mac, request->body_and_mac_size, output)) {
        *detail = -7;
        return M19_KS_ERROR;
    }
    *size = request->body_and_mac_size - 16;
    return faulted("upgrade") ? M19_KS_UPGRADE : M19_KS_OK;
}

static int st_ephemeral(void *context, const uint8_t *storage, size_t storage_size, uint8_t *output, size_t capacity, size_t *size,
                        int *detail)
{
    (void)context;
    if (faulted("eph-fail")) {
        *detail = -8;
        return M19_KS_ERROR;
    }
    if (capacity < 35)
        return M19_KS_ERROR;
    memcpy(output, "EPH", 3);
    m19_sha256(storage, storage_size, output + 3);
    *size = 35;
    return M19_KS_OK;
}

static const struct m19_keystore_ops storage = {st_connect, st_decrypt, st_ephemeral};

static int fs_add(void *context, const uint8_t *raw, size_t raw_size, int *detail)
{
    (void)context;
    uint8_t arg[0x50 + 64];
    if (faulted("install-fail")) {
        *detail = -9;
        return -1;
    }
    /* The real layout must accept it, and the key must be the one the model expects. */
    if (m19_ce_fs_layout(raw, raw_size, arg, sizeof(arg)) != (int)(0x50 + raw_size))
        return -1;
    installed++;
    matched = raw_size == fx_ephemeral_size && !memcmp(raw, fx_ephemeral, raw_size) && !memcmp(arg + 0x50, raw, raw_size);
    return 0;
}

static const struct m19_ce_fs fs = {fs_add};

static int open_dir(const char *root, const char *sub)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", root, sub);
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static int unlock_mode(int argc, char **argv)
{
    if (argc < 5)
        return 64;
    const char *root = argv[3], *pin = argv[4];
    if (argc > 5)
        fault = argv[5];
    load_fixture(root);
    struct m19_ce_env env = {open_dir(root, "spblob"), open_dir(root, "ce/current"), 0, crypto, &gatekeeper, NULL, &keystore, NULL,
                             &storage, NULL, &fs, NULL};
    struct m19_ce_report report;
    enum m19_ce_status status = m19_ce_unlock(&env, pin, strlen(pin), &report);
    printf("CE status=%s gk_calls=%d auth_added=%d sp_calls=%d installed=%d match=%d order=%d version=%d timeout=%u residue=%zu\n",
           m19_ce_status_name(status), gk_calls, auth_added, sp_calls, installed, matched, order_ok, report.spblob_version,
           report.gk_timeout_ms, m19_ce_test_residue());
    return status == M19_CE_OK ? 0 : 1;
}

static int de_mode(int argc, char **argv)
{
    if (argc < 5)
        return 64;
    if (argc > 5)
        fault = argv[5];
    fx_ephemeral_size = unhex(argv[4], fx_ephemeral, sizeof(fx_ephemeral));
    int detail = 0, upgraded = 0;
    enum m19_ce_status status = m19_ce_install_keystore_key(argv[3], &storage, NULL, &fs, NULL, &detail, &upgraded);
    printf("DE status=%s installed=%d match=%d upgraded=%d residue=%zu\n", m19_ce_status_name(status), installed, matched, upgraded,
           m19_ce_test_residue());
    return status == M19_CE_OK ? 0 : 1;
}

static int copy_mode(int argc, char **argv)
{
    struct stat before, after;
    if (argc != 5)
        return 64;
    int had = !stat(argv[4], &before);
    enum m19_ce_status status = m19_ce_copy_db(argv[3], argv[4]);
    int same = had && !stat(argv[4], &after) && after.st_ino == before.st_ino;
    printf("COPY status=%s same_inode=%d\n", m19_ce_status_name(status), same);
    return status == M19_CE_OK ? 0 : 1;
}

static int auth_mode(int argc, char **argv)
{
    uint8_t data[80];
    struct m19_ce_auth_token token;
    if (argc != 4)
        return 64;
    size_t size = unhex(argv[3], data, sizeof(data));
    if (m19_ce_parse_auth_token(data, size, &token)) {
        printf("AUTH bad\n");
        return 1;
    }
    printf("AUTH %lld %lld %lld %d %lld ", (long long)token.challenge, (long long)token.user_id, (long long)token.authenticator_id,
           token.authenticator_type, (long long)token.timestamp_ms);
    for (int i = 0; i < 32; i++)
        printf("%02x", token.mac[i]);
    printf("\n");
    return 0;
}

static int pin_mode(int argc, char **argv)
{
    if (argc != 4)
        return 64;
    printf("PIN %d\n", m19_ce_check_pin(argv[3], strlen(argv[3])));
    return 0;
}

static int layout_mode(void)
{
    uint8_t raw[3] = {0xa1, 0xa2, 0xa3}, arg[0x60];
    int length = m19_ce_fs_layout(raw, sizeof(raw), arg, sizeof(arg));
    printf("LAYOUT %d", length);
    for (int i = 0; i < length; i++)
        printf("%s%02x", i ? "" : " ", arg[i]);
    printf("\n");
    return length == 0x53 ? 0 : 1;
}

static int sp800_mode(int argc, char **argv)
{
    uint8_t key[64], out[32];
    if (argc != 6)
        return 64;
    size_t size = unhex(argv[3], key, sizeof(key));
    if (m19_ce_sp800(crypto, key, size, argv[4], argv[5], out))
        return 1;
    printf("SP800 ");
    for (int i = 0; i < 32; i++)
        printf("%02x", out[i]);
    printf("\n");
    return 0;
}

static int personalized_mode(int argc, char **argv)
{
    uint8_t data[512], out[64];
    if (argc != 5)
        return 64;
    size_t size = unhex(argv[4], data, sizeof(data));
    m19_ce_personalized(argv[3], data, size, out);
    printf("HASH ");
    for (int i = 0; i < 64; i++)
        printf("%02x", out[i]);
    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3)
        return 64;
    crypto = m19_ce_crypto_open(argv[1]);
    if (!crypto) {
        printf("CRYPTO unavailable\n");
        return 65;
    }
    if (!strcmp(argv[2], "unlock"))
        return unlock_mode(argc, argv);
    if (!strcmp(argv[2], "de"))
        return de_mode(argc, argv);
    if (!strcmp(argv[2], "copy"))
        return copy_mode(argc, argv);
    if (!strcmp(argv[2], "auth"))
        return auth_mode(argc, argv);
    if (!strcmp(argv[2], "pin"))
        return pin_mode(argc, argv);
    if (!strcmp(argv[2], "layout"))
        return layout_mode();
    if (!strcmp(argv[2], "sp800"))
        return sp800_mode(argc, argv);
    if (!strcmp(argv[2], "hash"))
        return personalized_mode(argc, argv);
    return 64;
}
