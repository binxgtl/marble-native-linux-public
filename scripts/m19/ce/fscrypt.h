#ifndef M19_CE_FSCRYPT_H
#define M19_CE_FSCRYPT_H

#include "ce.h"

#ifdef __cplusplus
extern "C" {
#endif

struct m19_ce_fs_context {
    int fd;      /* the /data mount's root, opened read-only */
    int added;
    int (*ioctl)(int fd, unsigned long request, void *arg);
};

extern const struct m19_ce_fs m19_ce_fs_ops;
int m19_ce_fs_open(struct m19_ce_fs_context *context, const char *mountpoint);
/* The ioctl argument for a hardware-wrapped key; its length, or -1. */
int m19_ce_fs_layout(const uint8_t *raw, size_t raw_size, uint8_t *arg, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
