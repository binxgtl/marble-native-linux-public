/* M19 core tests with a fake keystore and fake device-mapper. No device, no real key. */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core.h"

#define SECTORS 470183896ULL
#define DEVICE "/dev/block/sda33"

struct fake {
    int connect_result, decrypt_result, ephemeral_result, connects, decrypts, ephemerals;
    int fail_create, fail_load, fail_resume, creates, loads, resumes, removes, order;
    uint64_t device_sectors, loaded_sectors;
    char loaded[M19_PARAMS_MAX], target[32];
    uint8_t seen_app_id[M19_HASH_BYTES], seen_nonce[M19_NONCE_BYTES];
    size_t seen_body;
    uint8_t *leak_storage, *leak_ephemeral;
    int storage_size, ephemeral_size;
};

static char root[128];

static void write_bytes(const char *directory, const char *name, const void *data, size_t size)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", directory, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && write(fd, data, size) == (ssize_t)size);
    close(fd);
}

static void make_key_dir(const char *directory)
{
    static uint8_t secdiscardable[M19_SECDISCARDABLE_BYTES], encrypted[282];
    memset(secdiscardable, 0x5a, sizeof(secdiscardable));
    for (size_t i = 0; i < sizeof(encrypted); i++)
        encrypted[i] = (uint8_t)i;
    mkdir(directory, 0700);
    write_bytes(directory, "version", "1", 1);
    write_bytes(directory, "secdiscardable", secdiscardable, sizeof(secdiscardable));
    write_bytes(directory, "keymaster_key_blob", "BLOB", 4);
    write_bytes(directory, "encrypted_key", encrypted, sizeof(encrypted));
}

static int fake_connect(void *context, int *detail)
{
    struct fake *fake = context;
    fake->connects++;
    *detail = 0;
    return fake->connect_result;
}

static int fake_decrypt(void *context, const struct m19_decrypt_request *request, uint8_t *output, size_t capacity, size_t *size, int *detail)
{
    struct fake *fake = context;
    fake->decrypts++;
    *detail = 7;
    memcpy(fake->seen_app_id, request->app_id, sizeof(fake->seen_app_id));
    memcpy(fake->seen_nonce, request->nonce, sizeof(fake->seen_nonce));
    fake->seen_body = request->body_and_mac_size;
    assert(request->blob_size == 4 && !memcmp(request->blob, "BLOB", 4));
    assert(request->nonce_size == M19_NONCE_BYTES && request->app_id_size == M19_HASH_BYTES);
    if (fake->decrypt_result != M19_KS_OK)
        return fake->decrypt_result;
    assert(capacity >= (size_t)fake->storage_size);
    memset(output, 0xaa, (size_t)fake->storage_size);
    *size = (size_t)fake->storage_size;
    fake->leak_storage = output;
    return M19_KS_OK;
}

static int fake_ephemeral(void *context, const uint8_t *key, size_t key_size, uint8_t *output, size_t capacity, size_t *size, int *detail)
{
    struct fake *fake = context;
    fake->ephemerals++;
    *detail = 9;
    assert(key_size == (size_t)fake->storage_size && key[0] == 0xaa);
    if (fake->ephemeral_result != M19_KS_OK)
        return fake->ephemeral_result;
    assert(capacity >= (size_t)fake->ephemeral_size);
    memset(output, 0xbc, (size_t)fake->ephemeral_size);
    *size = (size_t)fake->ephemeral_size;
    fake->leak_ephemeral = output;
    return M19_KS_OK;
}

static int fake_sectors(void *context, const char *device, uint64_t *sectors)
{
    struct fake *fake = context;
    assert(!strcmp(device, DEVICE));
    *sectors = fake->device_sectors;
    return fake->device_sectors ? 0 : -1;
}

static int fake_create(void *context, const char *name)
{
    struct fake *fake = context;
    assert(!strcmp(name, "m19-userdata"));
    fake->creates++;
    assert(fake->leak_ephemeral);
    return fake->fail_create;
}

static int fake_load(void *context, const char *name, uint64_t sectors, const char *target, const char *parameters)
{
    struct fake *fake = context;
    (void)name;
    fake->loads++;
    fake->loaded_sectors = sectors;
    snprintf(fake->target, sizeof(fake->target), "%s", target);
    snprintf(fake->loaded, sizeof(fake->loaded), "%s", parameters);
    return fake->fail_load;
}

static int fake_resume(void *context, const char *name)
{
    struct fake *fake = context;
    (void)name;
    fake->resumes++;
    assert(fake->loads == 1);
    return fake->fail_resume;
}

static int fake_remove(void *context, const char *name)
{
    struct fake *fake = context;
    (void)name;
    fake->removes++;
    return 0;
}

static const struct m19_keystore_ops KS = {fake_connect, fake_decrypt, fake_ephemeral};
static const struct m19_dm_ops DM = {fake_sectors, fake_create, fake_load, fake_resume, fake_remove};

static struct fake good(void)
{
    struct fake fake;
    memset(&fake, 0, sizeof(fake));
    fake.device_sectors = SECTORS;
    fake.storage_size = 254;
    fake.ephemeral_size = 8;
    return fake;
}

static enum m19_status run(struct fake *fake, const char *directory, const char *device, uint64_t sectors, int *detail)
{
    struct m19_target target = {"m19-userdata", device, sectors};
    return m19_metadata_unlock(directory, &target, &KS, fake, &DM, fake, detail);
}

static void fresh(char *path, const char *name)
{
    snprintf(path, 256, "%s/%s", root, name);
    make_key_dir(path);
}

static void test_happy_path(void)
{
    char path[256];
    int detail = -1;
    struct fake fake = good();
    fresh(path, "good");
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_OK);
    assert(fake.connects == 1 && fake.decrypts == 1 && fake.ephemerals == 1);
    assert(fake.creates == 1 && fake.loads == 1 && fake.resumes == 1 && fake.removes == 0);
    assert(fake.seen_body == 282 - M19_NONCE_BYTES && fake.seen_nonce[0] == 0 && fake.seen_nonce[11] == 11);
    assert(!strcmp(fake.target, "default-key") && fake.loaded_sectors == SECTORS);
    assert(!strcmp(fake.loaded, "aes-xts-plain64 bcbcbcbcbcbcbcbc 0 " DEVICE " 0 3 sector_size:4096 iv_large_sectors wrappedkey_v0"));
    assert(!strstr(fake.loaded, "allow_discards"));
}

static void test_buffers_wiped(void)
{
    char path[256];
    int detail;
    struct fake fake = good();
    fresh(path, "wipe");
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_OK);
    for (int i = 0; i < fake.storage_size; i++)
        assert(fake.leak_storage[i] == 0);
    for (int i = 0; i < fake.ephemeral_size; i++)
        assert(fake.leak_ephemeral[i] == 0);
}

static void test_wiped_after_failure(void)
{
    char path[256];
    int detail;
    struct fake fake = good();
    fresh(path, "wipe2");
    fake.fail_load = -1;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_TABLE);
    for (int i = 0; i < fake.ephemeral_size; i++)
        assert(fake.leak_ephemeral[i] == 0);
}

static void test_upgrade_required_stops_before_table(void)
{
    char path[256];
    int detail;
    struct fake fake = good();
    fresh(path, "upgrade");
    fake.decrypt_result = M19_KS_UPGRADE;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_UPGRADE_REQUIRED);
    assert(fake.ephemerals == 0 && fake.creates == 0);
    fake = good();
    fake.ephemeral_result = M19_KS_UPGRADE;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_UPGRADE_REQUIRED);
    assert(fake.creates == 0);
}

static void test_pending_upgrade_stops_before_keystore(void)
{
    char path[256];
    int detail;
    struct fake fake = good();
    fresh(path, "pending");
    write_bytes(path, "keymaster_key_blob_upgraded", "X", 1);
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_UPGRADE_PENDING);
    assert(fake.connects == 0);
}

static void test_layout_gates(void)
{
    char path[256], file[300];
    int detail;
    struct fake fake = good();
    fresh(path, "extra");
    write_bytes(path, "stretching", "none", 4);
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_LAYOUT);
    fresh(path, "missing");
    snprintf(file, sizeof(file), "%s/keymaster_key_blob", path);
    unlink(file);
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_LAYOUT);
    assert(run(&fake, "/nonexistent/m19", DEVICE, SECTORS, &detail) == M19_LAYOUT);
    /* AOSP reads a missing secdiscardable as an empty hash. This client refuses it. */
    fresh(path, "nosecdis");
    snprintf(file, sizeof(file), "%s/secdiscardable", path);
    unlink(file);
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_LAYOUT);
    fresh(path, "version");
    write_bytes(path, "version", "2", 1);
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_VERSION);
    fresh(path, "secdis");
    write_bytes(path, "secdiscardable", "short", 5);
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_SECDISCARDABLE);
    fresh(path, "encrypted");
    write_bytes(path, "encrypted_key", "tiny", 4);
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_LAYOUT);
    assert(fake.connects == 0);
}

static void test_oversized_blob_refused(void)
{
    static uint8_t big[M19_KEY_MAX + 1];
    char path[256];
    int detail;
    struct fake fake = good();
    fresh(path, "big");
    write_bytes(path, "keymaster_key_blob", big, sizeof(big));
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_LAYOUT);
}

static void test_size_and_argument_gates(void)
{
    char path[256];
    int detail;
    struct fake fake = good();
    fresh(path, "size");
    fake.device_sectors = SECTORS + 8;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_SIZE);
    fake.device_sectors = 0;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_SIZE);
    fake = good();
    fake.device_sectors = SECTORS + 7;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_OK);
    fake = good();
    assert(run(&fake, path, "259:17", SECTORS, &detail) == M19_ARGUMENTS);
    assert(run(&fake, path, "/dev/259:17", SECTORS, &detail) == M19_ARGUMENTS);
    assert(run(&fake, path, "/dev/a b", SECTORS, &detail) == M19_ARGUMENTS);
    assert(run(&fake, path, DEVICE, SECTORS + 1, &detail) == M19_ARGUMENTS);
    assert(run(&fake, path, DEVICE, 0, &detail) == M19_ARGUMENTS);
    assert(fake.connects == 0);
}

static void test_keystore_failures(void)
{
    char path[256];
    int detail;
    struct fake fake = good();
    fresh(path, "ks");
    fake.connect_result = M19_KS_ERROR;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_CONNECT);
    fake = good();
    fake.decrypt_result = M19_KS_ERROR;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_DECRYPT && detail == 7);
    fake = good();
    fake.ephemeral_result = M19_KS_ERROR;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_EPHEMERAL && detail == 9);
    assert(fake.creates == 0);
}

static void test_device_mapper_failures_clean_up(void)
{
    char path[256];
    int detail;
    struct fake fake = good();
    fresh(path, "dm");
    fake.fail_create = -1;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_TABLE && fake.removes == 0 && fake.loads == 0);
    fake = good();
    fake.fail_load = -1;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_TABLE && fake.removes == 1 && fake.resumes == 0);
    fake = good();
    fake.fail_resume = -1;
    assert(run(&fake, path, DEVICE, SECTORS, &detail) == M19_TABLE && fake.removes == 1);
}

static void test_table_capacity(void)
{
    uint8_t key[4] = {0};
    char small[16];
    assert(m19_table_parameters(key, sizeof(key), DEVICE, small, sizeof(small)) == -1);
    assert(!strcmp(m19_status_name(M19_UPGRADE_REQUIRED), "UPGRADE_REQUIRED"));
    assert(!strcmp(m19_status_name((enum m19_status)99), "UNKNOWN"));
}

static void print_hex(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    static uint8_t data[1 << 21];
    uint8_t digest[M19_HASH_BYTES];
    if (argc == 2 && !strcmp(argv[1], "vectors")) {
        /* Python recomputes every line with hashlib and fbe.py. */
        for (size_t size = 0; size < 300; size += 7) {
            memset(data, (int)size & 0xff, size);
            m19_sha256(data, size, digest);
            print_hex(digest, 32);
            m19_sha512_parts(data, size / 2, data + size / 2, size - size / 2, digest);
            print_hex(digest, 64);
        }
        memset(data, 0x5a, M19_SECDISCARDABLE_BYTES);
        m19_app_id(data, M19_SECDISCARDABLE_BYTES, digest);
        print_hex(digest, M19_HASH_BYTES);
        char table[M19_PARAMS_MAX];
        assert(!m19_table_parameters((const uint8_t *)"\x01\xfe", 2, DEVICE, table, sizeof(table)));
        puts(table);
        return 0;
    }
    snprintf(root, sizeof(root), "/tmp/m19-core-%d", getpid());
    mkdir(root, 0700);
    test_happy_path();
    test_buffers_wiped();
    test_wiped_after_failure();
    test_upgrade_required_stops_before_table();
    test_pending_upgrade_stops_before_keystore();
    test_layout_gates();
    test_oversized_blob_refused();
    test_size_and_argument_gates();
    test_keystore_failures();
    test_device_mapper_failures_clean_up();
    test_table_capacity();
    char command[160];
    snprintf(command, sizeof(command), "rm -rf %s", root);
    assert(!system(command));
    puts("core tests PASS");
    return 0;
}
