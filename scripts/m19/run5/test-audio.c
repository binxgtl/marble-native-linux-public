/* The audio helper on a fake kernel: every call is logged to stderr, and M19_FAKE_FAIL fails some of them.
 *   M19_FAKE_FAIL: comma-separated block, create, table, resume, remove, or load:TEXT (the image whose first
 *   line is TEXT).
 *   M19_FAKE_SECTORS: the size of "super" in sectors; the file's own size otherwise. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/dm-ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "audio.h"

static int failing(const char *what)
{
    const char *fail = getenv("M19_FAKE_FAIL");
    size_t length = strlen(what);
    for (const char *at = fail; at && *at;) {
        const char *end = strchr(at, ',');
        size_t n = end ? (size_t)(end - at) : strlen(at);
        if (n == length && !strncmp(at, what, n))
            return 1;
        at = end ? end + 1 : NULL;
    }
    return 0;
}

static int fake_block(int fd, unsigned major, unsigned minor, uint64_t *sectors)
{
    struct stat st;
    const char *size = getenv("M19_FAKE_SECTORS");
    fprintf(stderr, "FAKE block %u:%u\n", major, minor);
    if (failing("block") || fstat(fd, &st))
        return -1;
    *sectors = size ? strtoull(size, NULL, 10) : (uint64_t)st.st_size / 512;
    return 0;
}

static int fake_dm(const char *control, unsigned long request, void *data)
{
    struct dm_ioctl *io = data;
    const char *what = request == DM_DEV_CREATE ? "create" : request == DM_TABLE_LOAD ? "table" : request == DM_DEV_SUSPEND ? "resume"
                       : request == DM_DEV_REMOVE ? "remove" : "other";
    fprintf(stderr, "FAKE dm %s %s %s version=%u flags=%u", control, what, io->name, io->version[0], io->flags);
    if (request == DM_TABLE_LOAD) {
        const char *at = (const char *)data + io->data_start;
        fprintf(stderr, " targets=%u size=%u", io->target_count, io->data_size);
        for (uint32_t i = 0; i < io->target_count; i++) {
            const struct dm_target_spec *spec = (const void *)at;
            fprintf(stderr, " [%llu+%llu %s %s]", (unsigned long long)spec->sector_start, (unsigned long long)spec->length, spec->target_type,
                    (const char *)(spec + 1));
            at += spec->next;
        }
        if ((size_t)(at - (const char *)data) != io->data_size)
            fprintf(stderr, " SIZE-MISMATCH");
    }
    fprintf(stderr, "\n");
    if (failing(what)) {
        errno = ENXIO;
        return -1;
    }
    if (request == DM_DEV_CREATE)
        io->dev = (0x1207u & 0xffu) | (253u << 8) | ((0x1207u & ~0xffu) << 12); /* 253:4615, the kernel's encoding */
    return 0;
}

static long fake_load(const void *image, size_t size)
{
    char first[80], what[96];
    size_t n = 0;
    while (n < size && n < sizeof(first) - 1 && ((const char *)image)[n] != '\n') {
        first[n] = ((const char *)image)[n];
        n++;
    }
    first[n] = 0;
    fprintf(stderr, "FAKE init_module %s size=%zu\n", first, size);
    snprintf(what, sizeof(what), "load:%s", first);
    if (failing(what)) {
        errno = EEXIST;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    static const struct m19_audio_kernel kernel = {fake_block, fake_dm, fake_load};
    return m19_audio_main(argc, argv, &kernel);
}
