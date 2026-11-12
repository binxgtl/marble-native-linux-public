/* M19 R5a audio helper: the kernel calls it makes, so tests can stand in for the kernel. */
#ifndef M19_AUDIO_H
#define M19_AUDIO_H

#include <stddef.h>
#include <stdint.h>

struct m19_audio_kernel {
    /* fd must be the block device major:minor; its size in 512-byte sectors. */
    int (*block)(int fd, unsigned major, unsigned minor, uint64_t *sectors);
    /* One device-mapper ioctl through the control node. */
    int (*dm)(const char *control, unsigned long request, void *io);
    /* init_module of an image already in memory, with its parameter string ("" for all but hwid.ko). */
    long (*load)(const void *image, size_t size, const char *params);
    /* The kernel command line (R6: hwid.ko's parameters): "/proc/cmdline". */
    const char *cmdline;
};

int m19_audio_main(int argc, char **argv, const struct m19_audio_kernel *kernel);

#endif
