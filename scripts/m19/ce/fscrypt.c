/* FS_IOC_ADD_ENCRYPTION_KEY for a hardware-wrapped key, laid out as TWRP's vold does on this kernel
 * (android12-5.10): a 0x50-byte header, the HW_WRAPPED flag at +0x4c, the raw key at +0x50. Adding a key
 * changes the kernel's keyring for the filesystem only; nothing is written to the device. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "fscrypt.h"

#define ADD_KEY_HEADER 0x50
#define KEY_SPEC_TYPE_IDENTIFIER 2
#define FLAG_HW_WRAPPED 1u
#define IOCTL_ADD_ENCRYPTION_KEY 0xc0506617u

_Static_assert(ADD_KEY_HEADER == 8 + 32 + 4 + 4 + 7 * 4 + 4, "fscrypt_add_key_arg header");

int m19_ce_fs_layout(const uint8_t *raw, size_t raw_size, uint8_t *arg, size_t capacity)
{
    if (!raw_size || raw_size > M19_KEY_MAX || capacity < ADD_KEY_HEADER + raw_size)
        return -1;
    memset(arg, 0, ADD_KEY_HEADER);
    uint32_t type = KEY_SPEC_TYPE_IDENTIFIER, size = (uint32_t)raw_size, flags = FLAG_HW_WRAPPED;
    memcpy(arg, &type, 4);
    memcpy(arg + 0x28, &size, 4);
    memcpy(arg + 0x4c, &flags, 4);
    memcpy(arg + ADD_KEY_HEADER, raw, raw_size);
    return (int)(ADD_KEY_HEADER + raw_size);
}

static int add_key(void *opaque, const uint8_t *raw, size_t raw_size, int *detail)
{
    static uint8_t arg[ADD_KEY_HEADER + M19_KEY_MAX];
    struct m19_ce_fs_context *context = opaque;
    int length = m19_ce_fs_layout(raw, raw_size, arg, sizeof(arg)), result = -1;
    if (length < 0) {
        *detail = -EINVAL;
        return -1;
    }
    if (context->ioctl(context->fd, IOCTL_ADD_ENCRYPTION_KEY, arg)) {
        *detail = -errno;
    } else {
        context->added++;
        result = 0;
    }
    m19_wipe(arg, sizeof(arg));
    return result;
}

static int real_ioctl(int fd, unsigned long request, void *arg)
{
    return ioctl(fd, request, arg);
}

const struct m19_ce_fs m19_ce_fs_ops = {add_key};

int m19_ce_fs_open(struct m19_ce_fs_context *context, const char *mountpoint)
{
    memset(context, 0, sizeof(*context));
    context->ioctl = real_ioctl;
    context->fd = open(mountpoint, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    return context->fd < 0 ? -1 : 0;
}
