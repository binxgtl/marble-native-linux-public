/* Device-mapper ioctls for the unlock client. Every table loads read-only. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "core.h"
#include "dm.h"

#define BUFFER_BYTES (sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec) + M19_PARAMS_MAX + 16)

static void prepare(struct dm_ioctl *io, size_t size, const char *name, uint32_t flags)
{
    memset(io, 0, sizeof(*io));
    io->version[0] = DM_VERSION_MAJOR;
    io->data_size = (uint32_t)size;
    io->data_start = sizeof(*io);
    io->flags = flags;
    snprintf(io->name, sizeof(io->name), "%s", name);
}

static int control(struct m19_dm_real *real)
{
    if (real->control < 0)
        real->control = open("/dev/device-mapper", O_RDWR | O_CLOEXEC);
    return real->control;
}

static int device_sectors(void *context, const char *device, uint64_t *sectors)
{
    (void)context;
    uint64_t bytes = 0;
    int fd = open(device, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int status = ioctl(fd, BLKGETSIZE64, &bytes);
    close(fd);
    *sectors = bytes / 512;
    return status;
}

static int device_create(void *context, const char *name)
{
    struct dm_ioctl io;
    struct m19_dm_real *real = context;
    int fd = control(real);
    if (fd < 0)
        return -1;
    prepare(&io, sizeof(io), name, 0);
    if (ioctl(fd, DM_DEV_CREATE, &io))
        return -1;
    real->major = major(io.dev);
    real->minor = minor(io.dev);
    return 0;
}

static int device_load(void *context, const char *name, uint64_t sectors, const char *target, const char *parameters)
{
    static uint8_t buffer[BUFFER_BYTES];
    struct dm_ioctl *io = (struct dm_ioctl *)buffer;
    struct dm_target_spec *spec = (struct dm_target_spec *)(buffer + sizeof(*io));
    size_t length = strlen(parameters) + 1, total = sizeof(*io) + sizeof(*spec) + ((length + 7) & ~(size_t)7);
    int fd = control(context), status = -1;
    if (fd < 0 || total > sizeof(buffer))
        return -1;
    memset(buffer, 0, sizeof(buffer));
    prepare(io, total, name, DM_READONLY_FLAG);
    io->target_count = 1;
    spec->sector_start = 0;
    spec->length = sectors;
    snprintf(spec->target_type, sizeof(spec->target_type), "%s", target);
    spec->next = (uint32_t)(total - sizeof(*io));
    memcpy(spec + 1, parameters, length);
    status = ioctl(fd, DM_TABLE_LOAD, io);
    m19_wipe(buffer, sizeof(buffer));
    return status;
}

static int device_resume(void *context, const char *name)
{
    struct dm_ioctl io;
    int fd = control(context);
    if (fd < 0)
        return -1;
    prepare(&io, sizeof(io), name, 0);
    return ioctl(fd, DM_DEV_SUSPEND, &io);
}

static int device_remove(void *context, const char *name)
{
    struct dm_ioctl io;
    int fd = control(context);
    if (fd < 0)
        return -1;
    prepare(&io, sizeof(io), name, 0);
    return ioctl(fd, DM_DEV_REMOVE, &io);
}

const struct m19_dm_ops m19_dm_real_ops = {device_sectors, device_create, device_load, device_resume, device_remove};
