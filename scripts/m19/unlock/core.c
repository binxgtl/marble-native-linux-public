/* M19 metadata unlock: same key steps as AOSP vold, read-only, with every STOP explicit. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core.h"

#define PREFIX_BLOCK 128

static const char PREFIX_SECDISCARDABLE[] = "Android secdiscardable SHA512";
static const char TARGET[] = "default-key";
static const char FEATURES[] = "3 sector_size:4096 iv_large_sectors wrappedkey_v0";
static const char *const KEY_FILES[] = {"encrypted_key", "keymaster_key_blob", "secdiscardable", "version"};

const char *m19_status_name(enum m19_status status)
{
    static const char *const names[] = {"OK", "ARGUMENTS", "LAYOUT", "VERSION", "UPGRADE_PENDING", "SECDISCARDABLE", "CONNECT",
                                        "DECRYPT", "UPGRADE_REQUIRED", "EPHEMERAL", "SIZE", "TABLE"};
    return (size_t)status < sizeof(names) / sizeof(names[0]) ? names[status] : "UNKNOWN";
}

void m19_wipe(void *data, size_t size)
{
    volatile uint8_t *bytes = data;
    while (size--)
        *bytes++ = 0;
}

void m19_app_id(const uint8_t *secdiscardable, size_t size, uint8_t digest[M19_HASH_BYTES])
{
    uint8_t prefix[PREFIX_BLOCK] = {0};
    memcpy(prefix, PREFIX_SECDISCARDABLE, sizeof(PREFIX_SECDISCARDABLE) - 1);
    m19_sha512_parts(prefix, sizeof(prefix), secdiscardable, size, digest);
}

static int read_file(int directory, const char *name, uint8_t *output, size_t capacity, size_t *size)
{
    int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    size_t used = 0;
    if (fd < 0)
        return -1;
    for (;;) {
        ssize_t got = read(fd, output + used, capacity - used);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            close(fd);
            *size = used;
            return got < 0 ? -1 : 0;
        }
        used += (size_t)got;
        if (used == capacity) {
            uint8_t extra;
            ssize_t more = read(fd, &extra, 1);
            close(fd);
            *size = used;
            return more == 0 ? 0 : -1;
        }
    }
}

static enum m19_status check_names(const char *path)
{
    DIR *directory = opendir(path);
    size_t seen = 0;
    if (!directory)
        return M19_LAYOUT;
    for (struct dirent *entry; (entry = readdir(directory));) {
        size_t known = 0;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (!strcmp(entry->d_name, "keymaster_key_blob_upgraded")) {
            closedir(directory);
            return M19_UPGRADE_PENDING;
        }
        for (size_t i = 0; i < sizeof(KEY_FILES) / sizeof(KEY_FILES[0]); i++)
            known += !strcmp(entry->d_name, KEY_FILES[i]);
        if (!known) {
            closedir(directory);
            return M19_LAYOUT;
        }
        seen++;
    }
    closedir(directory);
    return seen == sizeof(KEY_FILES) / sizeof(KEY_FILES[0]) ? M19_OK : M19_LAYOUT;
}

enum m19_status m19_read_key_dir(const char *path, struct m19_key_dir *keys)
{
    static uint8_t secdiscardable[M19_SECDISCARDABLE_BYTES + 1];
    uint8_t version[2];
    size_t size = 0;
    enum m19_status status = check_names(path);
    if (status != M19_OK)
        return status;
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0)
        return M19_LAYOUT;
    status = M19_LAYOUT;
    if (read_file(directory, "version", version, sizeof(version), &size)) {
        goto out;
    }
    if (size != 1 || version[0] != '1') {
        status = M19_VERSION;
        goto out;
    }
    if (read_file(directory, "secdiscardable", secdiscardable, sizeof(secdiscardable), &size) || size != M19_SECDISCARDABLE_BYTES) {
        status = M19_SECDISCARDABLE;
        goto out;
    }
    m19_app_id(secdiscardable, size, keys->app_id);
    if (read_file(directory, "keymaster_key_blob", keys->blob, sizeof(keys->blob), &keys->blob_size) || !keys->blob_size)
        goto out;
    if (read_file(directory, "encrypted_key", keys->encrypted, sizeof(keys->encrypted), &keys->encrypted_size))
        goto out;
    if (keys->encrypted_size <= M19_NONCE_BYTES + M19_MAC_BYTES)
        goto out;
    status = M19_OK;
out:
    close(directory);
    m19_wipe(secdiscardable, sizeof(secdiscardable));
    return status;
}

int m19_table_parameters(const uint8_t *key, size_t key_size, const char *device, char *output, size_t capacity)
{
    static const char hex[] = "0123456789abcdef";
    int head = snprintf(output, capacity, "aes-xts-plain64 ");
    size_t used = (size_t)head;
    if (head < 0 || used + key_size * 2 + 1 > capacity)
        return -1;
    for (size_t i = 0; i < key_size; i++) {
        output[used++] = hex[key[i] >> 4];
        output[used++] = hex[key[i] & 15];
    }
    int tail = snprintf(output + used, capacity - used, " 0 %s 0 %s", device, FEATURES);
    return tail < 0 || (size_t)tail >= capacity - used ? -1 : 0;
}

static int valid_target(const struct m19_target *target)
{
    return target->name && target->name[0] && target->device && !strncmp(target->device, "/dev/", 5) && !strchr(target->device, ' ') &&
           !strchr(target->device, ':') && target->sectors && !(target->sectors % 8);
}

enum m19_status m19_metadata_unlock(const char *directory, const struct m19_target *target,
                                    const struct m19_keystore_ops *keystore, void *keystore_context,
                                    const struct m19_dm_ops *dm, void *dm_context, int *detail)
{
    static struct m19_key_dir keys;
    static uint8_t storage[M19_KEY_MAX], ephemeral[M19_KEY_MAX];
    static char parameters[M19_PARAMS_MAX];
    size_t storage_size = 0, ephemeral_size = 0;
    uint64_t sectors = 0;
    enum m19_status status;
    int created = 0, result;

    *detail = 0;
    if (!valid_target(target))
        return M19_ARGUMENTS;
    if (dm->sectors(dm_context, target->device, &sectors))
        return M19_SIZE;
    if ((sectors & ~(uint64_t)7) != target->sectors)
        return M19_SIZE;
    status = m19_read_key_dir(directory, &keys);
    if (status != M19_OK)
        goto out;
    if (keystore->connect(keystore_context, detail) != M19_KS_OK) {
        status = M19_CONNECT;
        goto out;
    }
    struct m19_decrypt_request request = {keys.blob, keys.blob_size, keys.app_id, sizeof(keys.app_id), keys.encrypted, M19_NONCE_BYTES,
                                          keys.encrypted + M19_NONCE_BYTES, keys.encrypted_size - M19_NONCE_BYTES};
    result = keystore->decrypt(keystore_context, &request, storage, sizeof(storage), &storage_size, detail);
    if (result != M19_KS_OK) {
        status = result == M19_KS_UPGRADE ? M19_UPGRADE_REQUIRED : M19_DECRYPT;
        goto out;
    }
    result = keystore->ephemeral(keystore_context, storage, storage_size, ephemeral, sizeof(ephemeral), &ephemeral_size, detail);
    if (result != M19_KS_OK) {
        status = result == M19_KS_UPGRADE ? M19_UPGRADE_REQUIRED : M19_EPHEMERAL;
        goto out;
    }
    if (m19_table_parameters(ephemeral, ephemeral_size, target->device, parameters, sizeof(parameters))) {
        status = M19_TABLE;
        goto out;
    }
    status = M19_TABLE;
    if (dm->create(dm_context, target->name))
        goto out;
    created = 1;
    if (dm->load(dm_context, target->name, target->sectors, TARGET, parameters) || dm->resume(dm_context, target->name))
        goto out;
    created = 0;
    status = M19_OK;
out:
    if (created)
        dm->remove(dm_context, target->name);
    m19_wipe(&keys, sizeof(keys));
    m19_wipe(storage, sizeof(storage));
    m19_wipe(ephemeral, sizeof(ephemeral));
    m19_wipe(parameters, sizeof(parameters));
    return status;
}
