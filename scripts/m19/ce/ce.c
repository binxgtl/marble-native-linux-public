/* M19 R7 CE unlock core. Every step is TWRP's (docs/m19-r7.md): the same files, hashes, labels and calls,
 * read-only. Every secret buffer is static or on this stack and wiped on every return. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ce.h"

#define PREFIX_BLOCK 128
#define READ_FLAGS (O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)

static const char LABEL_GK[] = "user-gk-authentication";
static const char LABEL_SECDIS[] = "secdiscardable-transform";
static const char LABEL_APP_ID[] = "application-id";
static const char LABEL_FBE[] = "fbe-key";
static const char SP800_CONTEXT[] = "android-synthetic-password-personalization-context";
static const char PREFIX_KEYGEN[] = "Android key wrapping key generation SHA512";
static const char ALIAS_PREFIX[] = "synthetic_password_";

const char *m19_ce_status_name(enum m19_ce_status status)
{
    static const char *const names[] = {"OK", "ARGUMENTS", "PROTECTOR", "PASSWORD_DATA", "SPBLOB", "SECDIS", "CRYPTO", "GK_CONNECT",
                                        "GK_REJECTED", "GK_RETRY", "AUTH_TOKEN", "KS_CONNECT", "SP_UNWRAP", "SP_TAG", "CE_LAYOUT",
                                        "CE_TAG", "EPHEMERAL", "INSTALL", "DE_LAYOUT", "DE_DECRYPT", "DB_COPY"};
    return (size_t)status < sizeof(names) / sizeof(names[0]) ? names[status] : "UNKNOWN";
}

void m19_ce_personalized(const char *label, const uint8_t *data, size_t size, uint8_t output[M19_CE_HASH_BYTES])
{
    uint8_t prefix[PREFIX_BLOCK] = {0};
    size_t length = strlen(label);
    memcpy(prefix, label, length < sizeof(prefix) ? length : sizeof(prefix));
    m19_sha512_parts(prefix, sizeof(prefix), data, size, output);
}

static void put32(uint8_t *at, uint32_t value)
{
    at[0] = (uint8_t)(value >> 24);
    at[1] = (uint8_t)(value >> 16);
    at[2] = (uint8_t)(value >> 8);
    at[3] = (uint8_t)value;
}

static uint32_t get32(const uint8_t *at)
{
    return (uint32_t)at[0] << 24 | (uint32_t)at[1] << 16 | (uint32_t)at[2] << 8 | at[3];
}

static uint64_t get64(const uint8_t *at)
{
    return (uint64_t)get32(at) << 32 | get32(at + 4);
}

static uint64_t get64le(const uint8_t *at)
{
    uint64_t value = 0;
    for (int i = 7; i >= 0; i--)
        value = value << 8 | at[i];
    return value;
}

/* SP800-108 counter mode, one block, as AOSP's SP800Derive.withContext and TWRP's PersonalizedHashSP800. */
int m19_ce_sp800(const struct m19_ce_crypto *crypto, const uint8_t *key, size_t key_size, const char *label, const char *context,
                 uint8_t output[32])
{
    uint8_t message[256];
    size_t label_size = strlen(label), context_size = strlen(context), used = 0;
    if (4 + label_size + 1 + context_size + 8 > sizeof(message))
        return -1;
    put32(message, 1);
    used = 4;
    memcpy(message + used, label, label_size);
    used += label_size;
    message[used++] = 0;
    memcpy(message + used, context, context_size);
    used += context_size;
    put32(message + used, (uint32_t)(context_size * 8));
    put32(message + used + 4, 256);
    used += 8;
    int result = crypto->hmac_sha256(key, key_size, message, used, output);
    m19_wipe(message, sizeof(message));
    return result;
}

int m19_ce_parse_pwd(const uint8_t *data, size_t size, struct m19_ce_pwd *pwd)
{
    memset(pwd, 0, sizeof(*pwd));
    if (size < 11)
        return -1;
    pwd->credential_type = get32(data);
    pwd->log_n = data[4];
    pwd->log_r = data[5];
    pwd->log_p = data[6];
    uint32_t salt = get32(data + 7);
    if (!salt || salt > 64 || 11 + (size_t)salt + 4 > size)
        return -1;
    pwd->salt = data + 11;
    pwd->salt_size = salt;
    uint32_t handle = get32(data + 11 + salt);
    if (!handle || handle > 256 || 15 + (size_t)salt + handle > size)
        return -1;
    pwd->handle = data + 15 + salt;
    pwd->handle_size = handle;
    /* Android uses 11/3/1. The bound keeps scrypt's memory under 16 MiB. */
    if (!pwd->log_n || pwd->log_n > 15 || pwd->log_r > 4 || pwd->log_p > 2)
        return -1;
    return 0;
}

/* hw_auth_token_t: version, challenge, user_id, authenticator_id (host order), type and timestamp (network order), mac. */
int m19_ce_parse_auth_token(const uint8_t *data, size_t size, struct m19_ce_auth_token *token)
{
    if (size != M19_CE_AUTH_TOKEN_BYTES || data[0] != 0)
        return -1;
    token->challenge = (int64_t)get64le(data + 1);
    token->user_id = (int64_t)get64le(data + 9);
    token->authenticator_id = (int64_t)get64le(data + 17);
    token->authenticator_type = (int32_t)get32(data + 25);
    token->timestamp_ms = (int64_t)get64(data + 29);
    memcpy(token->mac, data + 37, sizeof(token->mac));
    return 0;
}

int m19_ce_check_pin(const char *pin, size_t size)
{
    if (size < M19_CE_PIN_MIN || size > M19_CE_PIN_MAX)
        return -1;
    for (size_t i = 0; i < size; i++)
        if (pin[i] < '0' || pin[i] > '9')
            return -1;
    return 0;
}

static int is_hex_id(const char *name, size_t size)
{
    if (size != M19_CE_ID_CHARS)
        return 0;
    for (size_t i = 0; i < size; i++)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f')))
            return 0;
    return 1;
}

static int present(int directory, const char *id, const char *suffix)
{
    char name[64];
    struct stat st;
    snprintf(name, sizeof(name), "%s%s", id, suffix);
    return !fstatat(directory, name, &st, AT_SYMLINK_NOFOLLOW) && S_ISREG(st.st_mode);
}

int m19_ce_find_protector(int spblob_dir, char id[M19_CE_ID_CHARS + 1])
{
    int copy = dup(spblob_dir), found = 0;
    if (copy < 0)
        return -1;
    DIR *directory = fdopendir(copy);
    if (!directory) {
        close(copy);
        return -1;
    }
    errno = 0;
    for (struct dirent *entry; (entry = readdir(directory));) {
        size_t length = strlen(entry->d_name);
        if (length != M19_CE_ID_CHARS + 4 || strcmp(entry->d_name + M19_CE_ID_CHARS, ".pwd"))
            continue;
        if (!is_hex_id(entry->d_name, M19_CE_ID_CHARS) || found++) {
            found = 2;
            break;
        }
        memcpy(id, entry->d_name, M19_CE_ID_CHARS);
        id[M19_CE_ID_CHARS] = 0;
    }
    int error = errno;
    closedir(directory);
    if (error || found != 1)
        return -1;
    return present(spblob_dir, id, ".pwd") && present(spblob_dir, id, ".spblob") && present(spblob_dir, id, ".secdis") ? 0 : -1;
}

static int read_at(int directory, const char *name, uint8_t *output, size_t capacity, size_t *size)
{
    int fd = openat(directory, name, READ_FLAGS);
    size_t used = 0;
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 || (uint64_t)st.st_size > capacity) {
        close(fd);
        return -1;
    }
    for (;;) {
        ssize_t got = read(fd, output + used, capacity - used);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            close(fd);
            return -1;
        }
        if (got == 0)
            break;
        used += (size_t)got;
        if (used == capacity) {
            uint8_t extra;
            ssize_t more = read(fd, &extra, 1);
            if (more != 0) {
                close(fd);
                return -1;
            }
            break;
        }
    }
    close(fd);
    *size = used;
    return 0;
}

static int read_named(int directory, const char *id, const char *suffix, uint8_t *output, size_t capacity, size_t *size)
{
    char name[64];
    snprintf(name, sizeof(name), "%s%s", id, suffix);
    return read_at(directory, name, output, capacity, size);
}

/* AOSP's alias is "%x" of the protector id: no leading zeros, unlike the file names. */
static void alias_for(const char id[M19_CE_ID_CHARS + 1], char *alias, size_t capacity)
{
    const char *digits = id;
    while (digits[0] == '0' && digits[1])
        digits++;
    snprintf(alias, capacity, "%s%s", ALIAS_PREFIX, digits);
}

/* The CE key directory holds exactly encrypted_key and version: the secret, not Keystore, protects it. */
static enum m19_ce_status check_ce_names(int ce_dir)
{
    int copy = dup(ce_dir), seen = 0, other = 0;
    if (copy < 0)
        return M19_CE_CE_LAYOUT;
    DIR *directory = fdopendir(copy);
    if (!directory) {
        close(copy);
        return M19_CE_CE_LAYOUT;
    }
    errno = 0;
    for (struct dirent *entry; (entry = readdir(directory));) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (!strcmp(entry->d_name, "encrypted_key") || !strcmp(entry->d_name, "version"))
            seen++;
        else
            other++;
    }
    int error = errno;
    closedir(directory);
    return !error && seen == 2 && !other ? M19_CE_OK : M19_CE_CE_LAYOUT;
}

/* Every secret this file holds lives here, so one wipe covers all of them and tests can prove it. */
static struct {
    uint8_t pwd_data[M19_CE_PWD_MAX], spblob[M19_CE_SPBLOB_MAX], secdis[M19_CE_SECDIS_BYTES + 1];
    uint8_t token[M19_CE_TOKEN_BYTES], provided[M19_CE_HASH_BYTES], auth[M19_CE_AUTH_TOKEN_BYTES + 1];
    uint8_t protector[M19_CE_TOKEN_BYTES + M19_CE_HASH_BYTES], app_id[M19_CE_HASH_BYTES], intermediate[M19_CE_SPBLOB_MAX];
    uint8_t sp[M19_CE_SPBLOB_MAX], secret[M19_CE_HASH_BYTES], keygen[PREFIX_BLOCK + M19_CE_HASH_BYTES], wrap[M19_CE_HASH_BYTES];
    uint8_t encrypted[M19_KEY_MAX], storage[M19_KEY_MAX], ephemeral[M19_KEY_MAX], plain[M19_KEY_MAX];
    struct m19_key_dir keys;
    struct m19_ce_auth_token parsed;
    struct m19_ce_pwd pwd;
} S;

#ifdef M19_CE_TEST
size_t m19_ce_test_residue(void)
{
    const uint8_t *bytes = (const uint8_t *)&S;
    size_t left = 0;
    for (size_t i = 0; i < sizeof(S); i++)
        left += bytes[i] != 0;
    return left;
}
#endif

enum m19_ce_status m19_ce_unlock(const struct m19_ce_env *env, const char *pin, size_t pin_size, struct m19_ce_report *report)
{
    char id[M19_CE_ID_CHARS + 1] = {0}, alias[64] = {0};
    size_t pwd_size = 0, spblob_size = 0, secdis_size = 0, auth_size = 0, intermediate_size = 0, encrypted_size = 0;
    size_t sp_size = 0, secret_size = 0, storage_size = 0, ephemeral_size = 0, version_size = 0;
    uint8_t version[2];
    uint32_t timeout = 0;
    enum m19_ce_status status = M19_CE_ARGUMENTS;
    int result;

    memset(report, 0, sizeof(*report));
    if (!env || !pin || m19_ce_check_pin(pin, pin_size))
        goto out;
    status = M19_CE_PROTECTOR;
    if (m19_ce_find_protector(env->spblob_dir, id))
        goto out;
    status = M19_CE_PASSWORD_DATA;
    if (read_named(env->spblob_dir, id, ".pwd", S.pwd_data, sizeof(S.pwd_data), &pwd_size) ||
        m19_ce_parse_pwd(S.pwd_data, pwd_size, &S.pwd))
        goto out;
    status = M19_CE_SPBLOB;
    if (read_named(env->spblob_dir, id, ".spblob", S.spblob, sizeof(S.spblob), &spblob_size))
        goto out;
    /* [0] version 2 or 3, [1] type 0 (password based), [2..14) nonce, then ciphertext and tag. */
    if (spblob_size < 2 + M19_CE_GCM_NONCE + M19_CE_GCM_TAG + 1 || (S.spblob[0] != 2 && S.spblob[0] != 3) || S.spblob[1] != 0)
        goto out;
    report->spblob_version = S.spblob[0];
    status = M19_CE_SECDIS;
    if (read_named(env->spblob_dir, id, ".secdis", S.secdis, sizeof(S.secdis), &secdis_size) || secdis_size != M19_CE_SECDIS_BYTES)
        goto out;
    status = M19_CE_CE_LAYOUT;
    if (check_ce_names(env->ce_dir) || read_at(env->ce_dir, "version", version, sizeof(version), &version_size) || version_size != 1 ||
        version[0] != '1' || read_at(env->ce_dir, "encrypted_key", S.encrypted, sizeof(S.encrypted), &encrypted_size) ||
        encrypted_size <= M19_CE_GCM_NONCE + M19_CE_GCM_TAG)
        goto out;

    /* Everything is read, checked and connected before the one Gatekeeper attempt. */
    status = M19_CE_KS_CONNECT;
    if (env->storage->connect(env->storage_context, &report->detail) != M19_KS_OK ||
        env->keystore->connect(env->keystore_context, &report->detail))
        goto out;
    status = M19_CE_GK_CONNECT;
    if (env->gatekeeper->connect(env->gatekeeper_context, &report->detail))
        goto out;
    status = M19_CE_CRYPTO;
    if (env->crypto->scrypt((const uint8_t *)pin, pin_size, S.pwd.salt, S.pwd.salt_size, (uint64_t)1 << S.pwd.log_n,
                            (uint64_t)1 << S.pwd.log_r, (uint64_t)1 << S.pwd.log_p, S.token, sizeof(S.token)))
        goto out;
    m19_ce_personalized(LABEL_GK, S.token, sizeof(S.token), S.provided);
    result = env->gatekeeper->verify(env->gatekeeper_context, M19_CE_FAKE_UID_BASE + env->user, S.pwd.handle, S.pwd.handle_size,
                                     S.provided, sizeof(S.provided), S.auth, sizeof(S.auth), &auth_size, &timeout, &report->detail);
    report->gk_timeout_ms = timeout;
    if (result != M19_GK_OK) {
        status = result == M19_GK_REJECTED ? M19_CE_GK_REJECTED : result == M19_GK_RETRY ? M19_CE_GK_RETRY : M19_CE_GK_CONNECT;
        goto out;
    }
    status = M19_CE_AUTH_TOKEN;
    if (m19_ce_parse_auth_token(S.auth, auth_size, &S.parsed) ||
        env->keystore->add_auth_token(env->keystore_context, &S.parsed, &report->detail))
        goto out;

    memcpy(S.protector, S.token, sizeof(S.token));
    m19_ce_personalized(LABEL_SECDIS, S.secdis, secdis_size, S.protector + M19_CE_TOKEN_BYTES);
    alias_for(id, alias, sizeof(alias));
    status = M19_CE_SP_UNWRAP;
    if (env->keystore->sp_decrypt(env->keystore_context, alias, S.spblob + 2, S.spblob + 2 + M19_CE_GCM_NONCE,
                                  spblob_size - 2 - M19_CE_GCM_NONCE, S.intermediate, sizeof(S.intermediate), &intermediate_size,
                                  &report->detail))
        goto out;
    status = M19_CE_SP_TAG;
    if (intermediate_size <= M19_CE_GCM_NONCE + M19_CE_GCM_TAG || intermediate_size > sizeof(S.intermediate))
        goto out;
    m19_ce_personalized(LABEL_APP_ID, S.protector, sizeof(S.protector), S.app_id);
    sp_size = intermediate_size - M19_CE_GCM_NONCE - M19_CE_GCM_TAG;
    if (env->crypto->gcm_open(S.app_id, S.intermediate, S.intermediate + M19_CE_GCM_NONCE, intermediate_size - M19_CE_GCM_NONCE, S.sp))
        goto out;

    status = M19_CE_CRYPTO;
    if (S.spblob[0] == 3) {
        if (m19_ce_sp800(env->crypto, S.sp, sp_size, LABEL_FBE, SP800_CONTEXT, S.secret))
            goto out;
        secret_size = 32;
    } else {
        m19_ce_personalized(LABEL_FBE, S.sp, sp_size, S.secret);
        secret_size = M19_CE_HASH_BYTES;
    }

    /* vold retrieveKey: no secdiscardable, so the app id is the secret alone. */
    memcpy(S.keygen, PREFIX_KEYGEN, sizeof(PREFIX_KEYGEN) - 1);
    memcpy(S.keygen + PREFIX_BLOCK, S.secret, secret_size);
    m19_sha512_parts(S.keygen, PREFIX_BLOCK, S.keygen + PREFIX_BLOCK, secret_size, S.wrap);
    status = M19_CE_CE_TAG;
    if (env->crypto->gcm_open(S.wrap, S.encrypted, S.encrypted + M19_CE_GCM_NONCE, encrypted_size - M19_CE_GCM_NONCE, S.storage))
        goto out;
    storage_size = encrypted_size - M19_CE_GCM_NONCE - M19_CE_GCM_TAG;

    status = M19_CE_EPHEMERAL;
    result = env->storage->ephemeral(env->storage_context, S.storage, storage_size, S.ephemeral, sizeof(S.ephemeral), &ephemeral_size,
                                     &report->detail);
    if (result != M19_KS_OK || !ephemeral_size || ephemeral_size > sizeof(S.ephemeral))
        goto out;
    status = M19_CE_INSTALL;
    if (env->fs->add_key(env->fs_context, S.ephemeral, ephemeral_size, &report->detail))
        goto out;
    status = M19_CE_OK;
out:
    m19_wipe(&S, sizeof(S));
    m19_wipe(alias, sizeof(alias));
    return status;
}

enum m19_ce_status m19_ce_install_keystore_key(const char *directory, const struct m19_keystore_ops *storage, void *storage_context,
                                               const struct m19_ce_fs *fs, void *fs_context, int *detail, int *upgraded)
{
    size_t plain_size = 0, ephemeral_size = 0;
    enum m19_ce_status status = M19_CE_DE_LAYOUT;
    int result;
    *detail = 0;
    *upgraded = 0;
    if (m19_read_key_dir(directory, &S.keys) != M19_OK)
        goto out;
    status = M19_CE_KS_CONNECT;
    if (storage->connect(storage_context, detail) != M19_KS_OK)
        goto out;
    struct m19_decrypt_request request = {S.keys.blob, S.keys.blob_size, S.keys.app_id, sizeof(S.keys.app_id), S.keys.encrypted,
                                          M19_NONCE_BYTES, S.keys.encrypted + M19_NONCE_BYTES, S.keys.encrypted_size - M19_NONCE_BYTES};
    status = M19_CE_DE_DECRYPT;
    *upgraded = -1; /* UNKNOWN until a successful decrypt response, as in R1. */
    result = storage->decrypt(storage_context, &request, S.plain, sizeof(S.plain), &plain_size, detail);
    if ((result != M19_KS_OK && result != M19_KS_UPGRADE) || !plain_size || plain_size > sizeof(S.plain))
        goto out;
    *upgraded = result == M19_KS_UPGRADE;
    status = M19_CE_EPHEMERAL;
    result = storage->ephemeral(storage_context, S.plain, plain_size, S.ephemeral, sizeof(S.ephemeral), &ephemeral_size, detail);
    if (result != M19_KS_OK || !ephemeral_size || ephemeral_size > sizeof(S.ephemeral))
        goto out;
    status = M19_CE_INSTALL;
    if (fs->add_key(fs_context, S.ephemeral, ephemeral_size, detail))
        goto out;
    status = M19_CE_OK;
out:
    m19_wipe(&S, sizeof(S));
    return status;
}

enum m19_ce_status m19_ce_copy_db(const char *source, const char *target)
{
    static uint8_t buffer[65536];
    int in = open(source, READ_FLAGS & ~O_NONBLOCK), out = -1;
    enum m19_ce_status status = M19_CE_DB_COPY;
    struct stat st;
    if (in < 0 || fstat(in, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > (64 << 20))
        goto done;
    /* As TWRP: the existing file is truncated and rewritten, the same inode the running Keystore2 opened. */
    out = open(target, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (out < 0)
        goto done;
    off_t copied = 0;
    for (;;) {
        ssize_t got = read(in, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            goto done;
        if (got == 0)
            break;
        for (ssize_t put = 0; put < got;) {
            ssize_t wrote = write(out, buffer + put, (size_t)(got - put));
            if (wrote < 0 && errno == EINTR)
                continue;
            if (wrote <= 0)
                goto done;
            put += wrote;
        }
        copied += got;
    }
    if (copied == st.st_size && !fsync(out))
        status = M19_CE_OK;
done:
    if (in >= 0)
        close(in);
    if (out >= 0 && close(out))
        status = M19_CE_DB_COPY;
    m19_wipe(buffer, sizeof(buffer));
    return status;
}
