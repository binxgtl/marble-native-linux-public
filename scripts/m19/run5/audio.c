/* M19 R5a: the audio modules from the stock partitions, read-only, before the ADSP starts (docs/m19-r5.md).
 *
 *   m19-audio map CONTROL SUPER MAJOR:MINOR PARTITION SLOT NAME
 *     Reads PARTITION's extents from the LP metadata of SUPER, metadata slot SLOT, with the geometry, header
 *     and table checksums all checked, and maps them read-only as the device-mapper device NAME through the
 *     control node CONTROL. SUPER must be the block device MAJOR:MINOR. Prints the new device's MAJOR:MINOR.
 *     On any failure nothing stays mapped.
 *   m19-audio unmap CONTROL NAME
 *     Removes NAME.
 *   m19-audio check LIST DLKM BOOT
 *     Reads every module LIST names and checks its size and SHA256, loading nothing.
 *   m19-audio load LIST PHASE DLKM BOOT
 *     Loads PHASE's modules in LIST's order. Each is read whole, from DLKM for vendor_dlkm and from BOOT for
 *     vendor_boot, and its size and SHA256 are checked. Only when the whole phase checks out is the first one
 *     loaded, from the very bytes that were hashed. The first failure stops.
 *     (R6) hwid.ko alone is loaded with parameters: the bootloader's hwid.hwid_value, hwid.project,
 *     hwid.build_adc and hwid.project_adc from the kernel command line, all four decimal and each once, as
 *     Android's modprobe passes them (M12 Run6: without them CNSS picks the generic BDF). Every other module
 *     gets none. A missing or malformed value stops the phase before anything loads.
 *
 * LIST holds one module a line: "PHASE SOURCE NAME SIZE SHA256".
 * Exit status: 0 done; 2 failed, with the kernel as it was; 1 failed after a change (a module loaded, or a
 * device that could not be removed).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "audio.h"
#include "../../m12/run7/hwid.h"

void m19_sha256(const void *data, size_t size, uint8_t digest[32]);

#define SECTOR 512u
#define LP_GEOMETRY_AT 4096u
#define LP_METADATA_AT (4096u + 2u * 4096u)
#define LP_GEOMETRY_MAGIC 0x616c4467u
#define LP_HEADER_MAGIC 0x414c5030u
#define LP_GEOMETRY_BYTES 52u
#define METADATA_MAX (1u << 20)
#define EXTENTS_MAX 8u
#define LIST_MAX 64u
#define MODULE_MAX (20u << 20) /* R6: the WLAN driver is 15.9 MB */
#define DM_BUFFER 4096u

enum { DONE = 0, CHANGED = 1, UNCHANGED = 2 };
enum { PARTITIONS, EXTENTS, GROUPS, DEVICES };
static const uint32_t entry_bytes[] = {52, 24, 48, 64};

struct extent {
    uint64_t sectors, target;
};

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const uint8_t *p) { return (uint32_t)le16(p) | (uint32_t)le16(p + 2) << 16; }
static uint64_t le64(const uint8_t *p) { return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32; }

static int read_at(int fd, void *data, size_t size, uint64_t offset)
{
    for (size_t at = 0; at < size;) {
        ssize_t got = pread(fd, (uint8_t *)data + at, size - at, (off_t)(offset + at));
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return -1;
        at += (size_t)got;
    }
    return 0;
}

/* The checksum field holds the SHA256 of the bytes with that field zeroed. */
static int checksum_ok(const uint8_t *data, size_t size, size_t field)
{
    uint8_t copy[256], digest[32];
    if (size > sizeof(copy) || field + 32 > size)
        return 0;
    memcpy(copy, data, size);
    memset(copy + field, 0, 32);
    m19_sha256(copy, size, digest);
    return !memcmp(digest, data + field, 32);
}

/* A fixed-size, NUL-padded LP name equals text exactly. */
static int name_is(const uint8_t *field, const char *text)
{
    size_t length = strnlen((const char *)field, 36);
    return length == strlen(text) && !memcmp(field, text, length);
}

static int fail(const char *why)
{
    fprintf(stderr, "M19 audio lp: %s\n", why);
    return -1;
}

/* PARTITION's linear extents in super, or -1. Every offset and size is checked against what was read. */
static int lp_extents(int fd, uint64_t super_sectors, const char *partition, unsigned slot, struct extent *out)
{
    uint8_t geometry[LP_GEOMETRY_BYTES];
    if (read_at(fd, geometry, sizeof(geometry), LP_GEOMETRY_AT))
        return fail("geometry read");
    if (le32(geometry) != LP_GEOMETRY_MAGIC || le32(geometry + 4) != LP_GEOMETRY_BYTES)
        return fail("geometry magic");
    if (!checksum_ok(geometry, sizeof(geometry), 8))
        return fail("geometry checksum");
    uint32_t max_size = le32(geometry + 40), slots = le32(geometry + 44);
    if (!max_size || max_size % SECTOR || max_size > METADATA_MAX || slot >= slots || slots > 4)
        return fail("geometry bounds");
    uint8_t *metadata = malloc(max_size);
    int count = -1;
    if (!metadata)
        return fail("memory");
    if (read_at(fd, metadata, max_size, LP_METADATA_AT + (uint64_t)slot * max_size)) {
        fail("metadata read");
        goto out;
    }
    uint32_t minor = le16(metadata + 6), header_size = le32(metadata + 8), tables_size = le32(metadata + 44);
    if (le32(metadata) != LP_HEADER_MAGIC || le16(metadata + 4) != 10 || minor > 2 || header_size != (minor == 2 ? 256u : 128u)) {
        fail("header magic");
        goto out;
    }
    if (!checksum_ok(metadata, header_size, 12)) {
        fail("header checksum");
        goto out;
    }
    if (tables_size > max_size - header_size) {
        fail("tables bounds");
        goto out;
    }
    const uint8_t *tables = metadata + header_size;
    uint8_t digest[32];
    m19_sha256(tables, tables_size, digest);
    if (memcmp(digest, metadata + 48, 32)) {
        fail("tables checksum");
        goto out;
    }
    const uint8_t *table[4];
    uint32_t entries[4];
    for (int i = 0; i < 4; i++) {
        const uint8_t *descriptor = metadata + 80 + 12 * i;
        uint64_t offset = le32(descriptor), end = offset + (uint64_t)le32(descriptor + 4) * le32(descriptor + 8);
        if (le32(descriptor + 8) != entry_bytes[i] || end > tables_size) {
            fail("table bounds");
            goto out;
        }
        table[i] = tables + offset;
        entries[i] = le32(descriptor + 4);
    }
    /* Block device 0 is super itself. No extent may reach into its metadata or past its end. */
    if (!entries[DEVICES] || !name_is(table[DEVICES] + 24, "super")) {
        fail("block device");
        goto out;
    }
    uint64_t first = le64(table[DEVICES]), end = le64(table[DEVICES] + 16) / SECTOR;
    if (end > super_sectors)
        end = super_sectors;
    const uint8_t *found = NULL;
    for (uint32_t i = 0; i < entries[PARTITIONS]; i++) {
        const uint8_t *entry = table[PARTITIONS] + (size_t)i * entry_bytes[PARTITIONS];
        if (!name_is(entry, partition))
            continue;
        if (found) {
            fail("duplicate partition");
            goto out;
        }
        found = entry;
    }
    if (!found) {
        fail("partition missing");
        goto out;
    }
    uint32_t index = le32(found + 40), number = le32(found + 44);
    if (!number || number > EXTENTS_MAX || index > entries[EXTENTS] || number > entries[EXTENTS] - index) {
        fail("extent bounds");
        goto out;
    }
    for (uint32_t i = 0; i < number; i++) {
        const uint8_t *extent = table[EXTENTS] + (size_t)(index + i) * entry_bytes[EXTENTS];
        uint64_t sectors = le64(extent), target = le64(extent + 12);
        /* Only linear extents on super: a zero extent or another block device is refused. */
        if (le32(extent + 8) != 0 || le32(extent + 20) != 0) {
            fail("extent type");
            goto out;
        }
        if (!sectors || target < first || target > end || sectors > end - target) {
            fail("extent range");
            goto out;
        }
        out[i].sectors = sectors;
        out[i].target = target;
    }
    count = (int)number;
out:
    free(metadata);
    return count;
}

static void prepare(struct dm_ioctl *io, size_t size, const char *name, uint32_t flags)
{
    memset(io, 0, sizeof(*io));
    io->version[0] = DM_VERSION_MAJOR;
    io->data_size = (uint32_t)size;
    io->data_start = sizeof(*io);
    io->flags = flags;
    snprintf(io->name, sizeof(io->name), "%s", name);
}

static int dm_simple(const struct m19_audio_kernel *kernel, const char *control, unsigned long request, const char *name)
{
    struct dm_ioctl io;
    prepare(&io, sizeof(io), name, 0);
    return kernel->dm(control, request, &io);
}

/* One linear target an extent, end to end, in a read-only table. */
static int dm_table(const struct m19_audio_kernel *kernel, const char *control, const char *name, const char *super,
                    const struct extent *extents, int count)
{
    static uint64_t words[DM_BUFFER / 8];
    uint8_t *buffer = (uint8_t *)words;
    struct dm_ioctl *io = (struct dm_ioctl *)buffer;
    size_t at = sizeof(*io);
    uint64_t start = 0;
    memset(words, 0, sizeof(words));
    for (int i = 0; i < count; i++) {
        struct dm_target_spec *spec = (struct dm_target_spec *)(buffer + at);
        char *parameters = (char *)(spec + 1);
        size_t room = DM_BUFFER - at - sizeof(*spec);
        int n = snprintf(parameters, room, "%s %llu", super, (unsigned long long)extents[i].target);
        if (n < 0 || (size_t)n >= room)
            return -1;
        size_t step = (sizeof(*spec) + (size_t)n + 1 + 7) & ~(size_t)7;
        spec->sector_start = start;
        spec->length = extents[i].sectors;
        snprintf(spec->target_type, sizeof(spec->target_type), "linear");
        spec->next = (uint32_t)step;
        start += extents[i].sectors;
        at += step;
    }
    prepare(io, at, name, DM_READONLY_FLAG);
    io->target_count = (uint32_t)count;
    return kernel->dm(control, DM_TABLE_LOAD, io);
}

static int parse_number(const char *text, unsigned *major, unsigned *minor)
{
    char extra;
    return sscanf(text, "%u:%u%c", major, minor, &extra) == 2 ? 0 : -1;
}

static int map(const struct m19_audio_kernel *kernel, char **argv)
{
    const char *control = argv[0], *super = argv[1], *partition = argv[3], *name = argv[5];
    unsigned major, minor, slot;
    char extra, device[32];
    uint64_t sectors = 0;
    struct extent extents[EXTENTS_MAX];
    if (parse_number(argv[2], &major, &minor) || sscanf(argv[4], "%u%c", &slot, &extra) != 1 || !*partition ||
        strlen(partition) >= 36 || !*name || strlen(name) >= DM_NAME_LEN)
        return UNCHANGED;
    int fd = open(super, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || kernel->block(fd, major, minor, &sectors)) {
        fprintf(stderr, "M19 audio map: super is not %u:%u\n", major, minor);
        if (fd >= 0)
            close(fd);
        return UNCHANGED;
    }
    int count = lp_extents(fd, sectors, partition, slot, extents);
    close(fd);
    if (count <= 0)
        return UNCHANGED;
    uint64_t total = 0;
    for (int i = 0; i < count; i++) {
        total += extents[i].sectors;
        fprintf(stderr, "M19 audio map: %s extent %d sectors=%llu at=%llu\n", partition, i, (unsigned long long)extents[i].sectors,
                (unsigned long long)extents[i].target);
    }
    snprintf(device, sizeof(device), "%u:%u", major, minor);
    struct dm_ioctl io;
    prepare(&io, sizeof(io), name, 0);
    if (kernel->dm(control, DM_DEV_CREATE, &io)) {
        fprintf(stderr, "M19 audio map: create errno=%d\n", errno);
        return UNCHANGED;
    }
    unsigned long long dev = io.dev;
    /* The kernel's huge_encode_dev: minor's low byte, major, then minor's high bits. */
    unsigned new_major = (unsigned)((dev >> 8) & 0xfff), new_minor = (unsigned)((dev & 0xff) | ((dev >> 12) & 0xfff00));
    if (dm_table(kernel, control, name, device, extents, count) || dm_simple(kernel, control, DM_DEV_SUSPEND, name)) {
        fprintf(stderr, "M19 audio map: table errno=%d\n", errno);
        if (dm_simple(kernel, control, DM_DEV_REMOVE, name)) {
            fprintf(stderr, "M19 audio map: remove errno=%d\n", errno);
            return CHANGED;
        }
        return UNCHANGED;
    }
    fprintf(stderr, "M19 audio map: %s sectors=%llu read-only as %s %u:%u\n", partition, (unsigned long long)total, name, new_major, new_minor);
    printf("%u:%u\n", new_major, new_minor);
    return fflush(stdout) ? CHANGED : DONE;
}

struct row {
    char phase[16], source[16], name[64], hash[65];
    unsigned long size;
};

static int is_hex(const char *text)
{
    for (; *text; text++)
        if (!((*text >= '0' && *text <= '9') || (*text >= 'a' && *text <= 'f')))
            return 0;
    return 1;
}

static int plain_module(const char *name)
{
    size_t length = strlen(name);
    return length > 3 && length < 64 && !strchr(name, '/') && strcmp(name + length - 3, ".ko") == 0 && name[0] != '.';
}

static int read_list(const char *path, struct row *rows)
{
    FILE *list = fopen(path, "re");
    char line[256];
    int count = 0;
    if (!list)
        return -1;
    while (fgets(line, sizeof(line), list)) {
        struct row *row = &rows[count];
        char extra;
        if (!strchr(line, '\n') || count == (int)LIST_MAX ||
            sscanf(line, "%15s %15s %63s %lu %64s %c", row->phase, row->source, row->name, &row->size, row->hash, &extra) != 5 ||
            (strcmp(row->source, "vendor_dlkm") && strcmp(row->source, "vendor_boot")) || !plain_module(row->name) ||
            strlen(row->hash) != 64 || !is_hex(row->hash) || !row->size || row->size > MODULE_MAX) {
            fclose(list);
            return -1;
        }
        for (int i = 0; i < count; i++)
            if (!strcmp(rows[i].name, row->name)) {
                fclose(list);
                return -1;
            }
        count++;
    }
    int error = ferror(list);
    fclose(list);
    return error ? -1 : count;
}

/* The whole file, exactly size bytes, or NULL. */
static uint8_t *read_module(const char *path, unsigned long size)
{
    struct stat st;
    uint8_t *data = NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NULL;
    if (!fstat(fd, &st) && S_ISREG(st.st_mode) && (unsigned long long)st.st_size == size && (data = malloc(size)) &&
        read_at(fd, data, size, 0)) {
        free(data);
        data = NULL;
    }
    close(fd);
    return data;
}

/* Reads and checks PHASE's rows, or every row when phase is NULL, keeping each image. Returns how many. */
static int verify(const struct row *rows, int count, const char *phase, const char *dlkm, const char *boot, uint8_t **images)
{
    int wanted = 0;
    for (int i = 0; i < count; i++) {
        if (phase && strcmp(rows[i].phase, phase))
            continue;
        char path[512], hash[65];
        uint8_t digest[32];
        snprintf(path, sizeof(path), "%s/%s", strcmp(rows[i].source, "vendor_dlkm") ? boot : dlkm, rows[i].name);
        images[i] = read_module(path, rows[i].size);
        if (!images[i]) {
            fprintf(stderr, "M19 audio: %s unreadable or not %lu bytes\n", rows[i].name, rows[i].size);
            return -1;
        }
        m19_sha256(images[i], rows[i].size, digest);
        for (int j = 0; j < 32; j++)
            snprintf(hash + 2 * j, 3, "%02x", digest[j]);
        if (strcmp(hash, rows[i].hash)) {
            fprintf(stderr, "M19 audio: %s sha256 %s\n", rows[i].name, hash);
            return -1;
        }
        wanted++;
    }
    return wanted;
}

static void release(uint8_t **images, int count)
{
    for (int i = 0; i < count; i++) {
        free(images[i]);
        images[i] = NULL;
    }
}

/* hwid.ko's parameters from the command line at path, as "hwid_value=N project=N build_adc=N project_adc=N". */
static int hwid_params(const char *path, char *out, size_t room)
{
    char text[16384];
    struct m12_hwid values;
    int fd = path ? open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (n <= 0 || n == (ssize_t)sizeof(text) - 1)
        return -1;
    text[n] = 0;
    if (m12_hwid_parse(text, (unsigned long)n, 1, &values) || m12_hwid_format(&values, out, room))
        return -1;
    return 0;
}

/* argv: LIST PHASE DLKM BOOT for load, LIST DLKM BOOT for check (phase NULL). */
static int load(const struct m19_audio_kernel *kernel, const char *list, const char *phase, const char *dlkm, const char *boot)
{
    static struct row rows[LIST_MAX];
    static uint8_t *images[LIST_MAX];
    int count = read_list(list, rows), loaded = 0, status = UNCHANGED;
    if (count <= 0) {
        fprintf(stderr, "M19 audio: bad list\n");
        return UNCHANGED;
    }
    int wanted = verify(rows, count, phase, dlkm, boot, images);
    if (!phase) {
        fprintf(stderr, "M19 audio check: %d of %d modules checked\n", wanted, count);
        release(images, count);
        return wanted == count ? DONE : UNCHANGED;
    }
    if (wanted <= 0) {
        fprintf(stderr, "M19 audio load: phase %s %s\n", phase, wanted ? "not checked" : "is empty");
        goto out;
    }
    static char hwid[160];
    hwid[0] = 0;
    for (int i = 0; i < count; i++)
        if (images[i] && !strcmp(rows[i].name, "hwid.ko") && hwid_params(kernel->cmdline, hwid, sizeof(hwid))) {
            fprintf(stderr, "M19 audio load: hwid parameters missing or malformed\n");
            wanted = 0;
            goto out;
        }
    for (int i = 0; i < count; i++) {
        if (!images[i])
            continue;
        const char *params = strcmp(rows[i].name, "hwid.ko") ? "" : hwid;
        errno = 0;
        long rc = kernel->load(images[i], rows[i].size, params);
        fprintf(stderr, "M19 audio load: %s %s rc=%ld errno=%d%s%s\n", rows[i].phase, rows[i].name, rc, rc ? errno : 0, *params ? " params=" : "",
                params);
        if (rc) {
            status = loaded ? CHANGED : UNCHANGED;
            goto out;
        }
        loaded++;
    }
    status = DONE;
out:
    fprintf(stderr, "M19 audio load: phase %s loaded=%d of %d\n", phase, loaded, wanted > 0 ? wanted : 0);
    release(images, count);
    return status;
}

int m19_audio_main(int argc, char **argv, const struct m19_audio_kernel *kernel)
{
    if (argc == 8 && !strcmp(argv[1], "map"))
        return map(kernel, argv + 2);
    if (argc == 4 && !strcmp(argv[1], "unmap")) {
        if (dm_simple(kernel, argv[2], DM_DEV_REMOVE, argv[3])) {
            fprintf(stderr, "M19 audio unmap: %s errno=%d\n", argv[3], errno);
            return CHANGED;
        }
        return DONE;
    }
    if (argc == 6 && !strcmp(argv[1], "load"))
        return load(kernel, argv[2], argv[3], argv[4], argv[5]);
    if (argc == 5 && !strcmp(argv[1], "check"))
        return load(kernel, argv[2], NULL, argv[3], argv[4]);
    fprintf(stderr, "M19 audio: usage\n");
    return UNCHANGED;
}

#ifndef M19_AUDIO_TEST
#include <linux/fs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>

static int real_block(int fd, unsigned major_number, unsigned minor_number, uint64_t *sectors)
{
    struct stat st;
    uint64_t bytes = 0;
    if (fstat(fd, &st) || !S_ISBLK(st.st_mode) || major(st.st_rdev) != major_number || minor(st.st_rdev) != minor_number ||
        ioctl(fd, BLKGETSIZE64, &bytes))
        return -1;
    *sectors = bytes / SECTOR;
    return 0;
}

static int real_dm(const char *control, unsigned long request, void *io)
{
    int fd = open(control, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int rc = ioctl(fd, request, io), error = errno;
    close(fd);
    errno = error;
    return rc;
}

static long real_load(const void *image, size_t size, const char *params)
{
    return syscall(SYS_init_module, image, (unsigned long)size, params);
}

int main(int argc, char **argv)
{
    static const struct m19_audio_kernel kernel = {real_block, real_dm, real_load, "/proc/cmdline"};
    return m19_audio_main(argc, argv, &kernel);
}
#endif
