/* m19-rdx: unpack the pinned recovery ramdisk into a tmpfs for the transient TEE environment.
 *
 * Usage: m19-rdx <device> <sha256> <dest> <init.rc> [name=value ...]
 * Reads the partition read-only, refuses any image but the pinned one, and leaves out the
 * recovery program, the recovery rc files and kernel modules. Each name=value must replace
 * an existing line of prop.default.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core.h"

#define PAGE 4096u
#define HEADER_VERSION 4u
#define NEWC_HEADER 110u
#define LZ4_BLOCK_MAX (8u << 20)
#define RAMDISK_MAX (512u << 20)
#define OVERRIDES_MAX 8
#define RC_PATH "system/etc/init/hw/init.rc"
#define RECOVERY_MARKER "system/bin/recovery"

static const uint8_t BOOT_MAGIC[8] = {'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'};
static const uint8_t LZ4_LEGACY[4] = {0x02, 0x21, 0x4c, 0x18};
/* Same list as RECOVERY_REMOVED in scripts/m19/plan.py. test-native.py checks them together. */
static const char *const REMOVED[] = {"system/bin/recovery", "system/bin/twrp", "init.recovery.service.rc", "init.recovery.usb.rc",
                                      "init.recovery.hlthchrg.rc", "init.recovery.qcom.rc"};

struct overrides {
    const char *values[OVERRIDES_MAX];
    int seen[OVERRIDES_MAX];
    int count;
};

static int finish(const char *status, int code)
{
    printf("M19_RDX status=%s\n", status);
    return code;
}

static uint8_t *read_all(const char *path, size_t *size)
{
    struct stat st;
    uint64_t bytes = 0;
    uint8_t *data = NULL;
    size_t used = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st))
        goto fail;
    if (S_ISBLK(st.st_mode)) {
        if (ioctl(fd, BLKGETSIZE64, &bytes))
            goto fail;
    } else {
        bytes = (uint64_t)st.st_size;
    }
    data = malloc(bytes ? bytes : 1);
    if (!data)
        goto fail;
    while (used < bytes) {
        ssize_t got = read(fd, data + used, bytes - used);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            goto fail;
        used += (size_t)got;
    }
    close(fd);
    *size = used;
    return data;
fail:
    if (fd >= 0)
        close(fd);
    free(data);
    return NULL;
}

static int parse_sha256(const char *text, uint8_t digest[32])
{
    if (strlen(text) != 64)
        return -1;
    for (int i = 0; i < 32; i++) {
        unsigned value;
        if (sscanf(text + i * 2, "%2x", &value) != 1)
            return -1;
        digest[i] = (uint8_t)value;
    }
    return 0;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static long lz4_block(const uint8_t *src, size_t size, uint8_t *dst, size_t capacity)
{
    size_t i = 0, o = 0;
    while (i < size) {
        unsigned token = src[i++];
        size_t length = token >> 4;
        if (length == 15) {
            unsigned more;
            do {
                if (i >= size)
                    return -1;
                more = src[i++];
                length += more;
            } while (more == 255);
        }
        if (length > size - i || length > capacity - o)
            return -1;
        memcpy(dst + o, src + i, length);
        i += length;
        o += length;
        if (i == size)
            break;
        if (size - i < 2)
            return -1;
        size_t offset = (size_t)src[i] | (size_t)src[i + 1] << 8;
        i += 2;
        if (offset == 0 || offset > o)
            return -1;
        size_t match = token & 15;
        if (match == 15) {
            unsigned more;
            do {
                if (i >= size)
                    return -1;
                more = src[i++];
                match += more;
            } while (more == 255);
        }
        match += 4;
        if (match > capacity - o)
            return -1;
        for (size_t n = 0; n < match; n++, o++)
            dst[o] = dst[o - offset];
    }
    return (long)o;
}

static uint8_t *unpack(const uint8_t *data, size_t size, size_t *output_size)
{
    size_t used = 0, capacity = 64u << 20, position = sizeof(LZ4_LEGACY);
    uint8_t *output;
    if (size < sizeof(LZ4_LEGACY) || memcmp(data, LZ4_LEGACY, sizeof(LZ4_LEGACY)))
        return NULL;
    output = malloc(capacity);
    while (output && position + 4 <= size) {
        uint32_t block = le32(data + position);
        if (block == 0x184c2102u) {
            position += 4;
            continue;
        }
        if (!block)
            break;
        if (block > size - position - 4 || block > 2 * LZ4_BLOCK_MAX)
            goto fail;
        while (capacity - used < LZ4_BLOCK_MAX) {
            uint8_t *grown;
            if (capacity >= RAMDISK_MAX)
                goto fail;
            capacity *= 2;
            grown = realloc(output, capacity);
            if (!grown)
                goto fail;
            output = grown;
        }
        long got = lz4_block(data + position + 4, block, output + used, LZ4_BLOCK_MAX);
        if (got < 0)
            goto fail;
        used += (size_t)got;
        position += 4 + (size_t)block;
    }
    *output_size = used;
    return output;
fail:
    free(output);
    return NULL;
}

static int hex_field(const uint8_t *field, uint32_t *value)
{
    char text[9];
    char *end;
    memcpy(text, field, 8);
    text[8] = 0;
    *value = (uint32_t)strtoul(text, &end, 16);
    return *end ? -1 : 0;
}

static int safe_name(const char *name)
{
    const char *part = name;
    if (name[0] == '/' || !name[0])
        return 0;
    while (part) {
        const char *next = strchr(part, '/');
        size_t length = next ? (size_t)(next - part) : strlen(part);
        if (length == 2 && !memcmp(part, "..", 2))
            return 0;
        part = next ? next + 1 : NULL;
    }
    return 1;
}

static int skipped(const char *name)
{
    size_t length = strlen(name);
    if (length > 3 && !strcmp(name + length - 3, ".ko"))
        return 1;
    if (!strncmp(name, "twres/", 6) || !strcmp(name, "twres"))
        return 1;
    for (size_t i = 0; i < sizeof(REMOVED) / sizeof(REMOVED[0]); i++)
        if (!strcmp(name, REMOVED[i]))
            return 1;
    return 0;
}

/* Walk one path component at a time. Never let an archive symlink become a parent. */
static int child_directory(int parent, char *name, mode_t mode, int create)
{
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT && create) {
        if (mkdirat(parent, name, mode) && errno != EEXIST)
            return -1;
        fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode)) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Return an opened, verified parent directory and a single-component leaf. */
static int open_parent(int root, const char *name, int create, char *leaf, size_t leaf_size)
{
    char path[512];
    size_t length = strlen(name);
    if (!length || length >= sizeof(path))
        return -1;
    memcpy(path, name, length + 1);
    while (length && path[length - 1] == '/')
        path[--length] = 0;
    if (!length)
        return -1;

    char *last = strrchr(path, '/');
    char *parents = NULL;
    char *base = path;
    if (last) {
        *last = 0;
        parents = path;
        base = last + 1;
    }
    if (!*base || !strcmp(base, ".") || !strcmp(base, "..") || strlen(base) >= leaf_size)
        return -1;
    strcpy(leaf, base);

    int current = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (current < 0)
        return -1;
    char *part = parents;
    while (part && *part) {
        while (*part == '/')
            part++;
        if (!*part)
            break;
        char *end = strchr(part, '/');
        if (end)
            *end = 0;
        if (strcmp(part, ".") && strcmp(part, "..")) {
            int next = child_directory(current, part, 0755, create);
            if (next < 0) {
                close(current);
                return -1;
            }
            close(current);
            current = next;
        } else if (!strcmp(part, "..")) {
            close(current);
            return -1;
        }
        if (!end)
            break;
        part = end + 1;
    }
    return current;
}

static int make_directory(int root, const char *name, mode_t mode)
{
    char leaf[512];
    int parent = open_parent(root, name, 1, leaf, sizeof(leaf));
    if (parent < 0)
        return -1;
    int directory = child_directory(parent, leaf, mode & 07777, 1);
    close(parent);
    if (directory < 0)
        return -1;
    close(directory);
    return 0;
}

static int write_new_at(int parent, const char *name, const uint8_t *data, size_t size, mode_t mode)
{
    int fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    size_t done = 0;
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1)
        goto fail;
    while (done < size) {
        ssize_t put = write(fd, data + done, size - done);
        if (put < 0 && errno == EINTR)
            continue;
        if (put <= 0)
            goto fail;
        done += (size_t)put;
    }
    int status = fchmod(fd, mode & 07777);
    if (close(fd))
        status = -1;
    if (status) {
        unlinkat(parent, name, 0);
        return -1;
    }
    return 0;
fail:
    close(fd);
    unlinkat(parent, name, 0);
    return -1;
}

static int write_file(int root, const char *name, const uint8_t *data, size_t size, mode_t mode)
{
    char leaf[512];
    int parent = open_parent(root, name, 1, leaf, sizeof(leaf));
    if (parent < 0)
        return -1;
    int status = write_new_at(parent, leaf, data, size, mode);
    close(parent);
    return status;
}

/* Replace init.rc by renaming a fresh file; rename never follows the old leaf. */
static int replace_file(int root, const char *name, const uint8_t *data, size_t size, mode_t mode)
{
    char leaf[512], temporary[64];
    int parent = open_parent(root, name, 0, leaf, sizeof(leaf));
    if (parent < 0)
        return -1;
    struct stat st;
    if (fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        close(parent);
        return -1;
    }
    int length = snprintf(temporary, sizeof(temporary), ".m19-rdx-%ld.tmp", (long)getpid());
    if (length < 0 || (size_t)length >= sizeof(temporary) ||
        write_new_at(parent, temporary, data, size, mode)) {
        close(parent);
        return -1;
    }
    int status = renameat(parent, temporary, parent, leaf);
    if (status)
        unlinkat(parent, temporary, 0);
    close(parent);
    return status;
}

static int write_symlink(int root, const char *name, const char *target)
{
    char leaf[512];
    int parent = open_parent(root, name, 1, leaf, sizeof(leaf));
    if (parent < 0)
        return -1;
    int status = symlinkat(target, parent, leaf);
    close(parent);
    return status;
}

/* Resolve every destination component from a fixed anchor without following links. */
static int open_root_directory(const char *path)
{
    int absolute = path[0] == '/';
    const char *relative = path;
    if (absolute) {
        while (*relative == '/')
            relative++;
    }
    if (!*relative)
        return -1;

    int anchor = open(absolute ? "/" : ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (anchor < 0)
        return -1;
    char leaf[512];
    int parent = open_parent(anchor, relative, 0, leaf, sizeof(leaf));
    close(anchor);
    if (parent < 0)
        return -1;
    int root = child_directory(parent, leaf, 0755, 0);
    close(parent);
    return root;
}

/* Rewrites matching name= lines. Returns a new buffer that the caller frees. */
static uint8_t *patch_properties(const uint8_t *data, size_t size, struct overrides *wanted, size_t *output_size)
{
    size_t capacity = size + 512 * OVERRIDES_MAX, used = 0, position = 0;
    uint8_t *output = malloc(capacity);
    if (!output)
        return NULL;
    while (position < size) {
        const uint8_t *newline = memchr(data + position, '\n', size - position);
        size_t length = newline ? (size_t)(newline - (data + position)) : size - position;
        const char *replacement = NULL;
        for (int i = 0; i < wanted->count; i++) {
            size_t name = (size_t)(strchr(wanted->values[i], '=') - wanted->values[i]) + 1;
            if (length >= name && !memcmp(data + position, wanted->values[i], name)) {
                replacement = wanted->values[i];
                wanted->seen[i] = 1;
            }
        }
        const uint8_t *line = replacement ? (const uint8_t *)replacement : data + position;
        size_t line_size = replacement ? strlen(replacement) : length;
        if (line_size + 1 > capacity - used) {
            free(output);
            return NULL;
        }
        memcpy(output + used, line, line_size);
        used += line_size;
        output[used++] = '\n';
        position += length + 1;
    }
    *output_size = used;
    return output;
}

static const char *extract(const uint8_t *cpio, size_t size, int root, struct overrides *wanted, int *rc_seen)
{
    size_t position = 0;
    for (;;) {
        uint32_t mode, file_size, name_size;
        if (size - position < NEWC_HEADER || (memcmp(cpio + position, "070701", 6) && memcmp(cpio + position, "070702", 6)))
            return "CPIO";
        if (hex_field(cpio + position + 14, &mode) || hex_field(cpio + position + 54, &file_size) || hex_field(cpio + position + 94, &name_size))
            return "CPIO";
        size_t name_start = position + NEWC_HEADER;
        if (!name_size || name_size > size - name_start || cpio[name_start + name_size - 1])
            return "CPIO";
        const char *name = (const char *)cpio + name_start;
        size_t body = (name_start + name_size + 3) & ~(size_t)3;
        if (body > size || file_size > size - body)
            return "CPIO";
        if (!strcmp(name, "TRAILER!!!"))
            return NULL;
        if (!safe_name(name))
            return "CPIO";
        const uint8_t *payload = cpio + body;
        position = (body + file_size + 3) & ~(size_t)3;
        if (position > size)
            return "CPIO";
        if (skipped(name) || !strcmp(name, "."))
            continue;
        switch (mode & S_IFMT) {
        case S_IFDIR:
            if (make_directory(root, name, mode))
                return "WRITE";
            break;
        case S_IFLNK: {
            char target[512];
            if (file_size >= sizeof(target))
                return "CPIO";
            memcpy(target, payload, file_size);
            target[file_size] = 0;
            if (write_symlink(root, name, target))
                return "WRITE";
            break;
        }
        case S_IFREG:
            if (!strcmp(name, "prop.default")) {
                size_t patched_size = 0;
                uint8_t *patched = patch_properties(payload, file_size, wanted, &patched_size);
                int status = patched ? write_file(root, name, patched, patched_size, mode) : -1;
                free(patched);
                if (status)
                    return "WRITE";
                break;
            }
            *rc_seen |= !strcmp(name, RC_PATH);
            if (write_file(root, name, payload, file_size, mode))
                return "WRITE";
            break;
        default:
            break;
        }
    }
}

int main(int argc, char **argv)
{
    struct overrides wanted = {.count = 0};
    uint8_t expected[32], actual[32];
    size_t image_size = 0, cpio_size = 0, rc_size = 0;
    int rc_seen = 0;

    if (argc < 5 || argc - 5 > OVERRIDES_MAX || parse_sha256(argv[2], expected))
        return finish("ARGUMENTS", 2);
    for (int i = 5; i < argc; i++) {
        if (!strchr(argv[i], '=') || strlen(argv[i]) > 400)
            return finish("ARGUMENTS", 2);
        wanted.values[wanted.count++] = argv[i];
    }
    uint8_t *rc = read_all(argv[4], &rc_size);
    if (!rc)
        return finish("RC", 1);
    uint8_t *image = read_all(argv[1], &image_size);
    if (!image)
        return finish("READ", 1);
    m19_sha256(image, image_size, actual);
    if (memcmp(actual, expected, sizeof(actual)))
        return finish("HASH", 1);
    if (image_size < PAGE || memcmp(image, BOOT_MAGIC, sizeof(BOOT_MAGIC)) || le32(image + 40) != HEADER_VERSION)
        return finish("HEADER", 1);
    uint64_t kernel = le32(image + 8), ramdisk = le32(image + 12);
    uint64_t start = PAGE + (kernel + PAGE - 1) / PAGE * PAGE;
    if (!ramdisk || start + ramdisk > image_size)
        return finish("HEADER", 1);
    uint8_t *cpio = unpack(image + start, (size_t)ramdisk, &cpio_size);
    if (!cpio)
        return finish("RAMDISK", 1);
    int root = open_root_directory(argv[3]);
    if (root < 0)
        return finish("WRITE", 1);
    const char *failure = extract(cpio, cpio_size, root, &wanted, &rc_seen);
    if (failure) {
        close(root);
        return finish(failure, 1);
    }
    for (int i = 0; i < wanted.count; i++)
        if (!wanted.seen[i]) {
            close(root);
            return finish("PROPERTY", 1);
        }
    if (!rc_seen) {
        close(root);
        return finish("RC", 1);
    }
    if (replace_file(root, RC_PATH, rc, rc_size, 0644)) {
        close(root);
        return finish("WRITE", 1);
    }
    /* Android init reads prop.default only if this path exists. It holds no program. */
    if (write_file(root, RECOVERY_MARKER, (const uint8_t *)"", 0, 0600)) {
        close(root);
        return finish("WRITE", 1);
    }
    close(root);
    return finish("OK", 0);
}
