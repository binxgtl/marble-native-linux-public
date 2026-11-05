/* The modules M19 adds to the M8 closure, named on the command line and loaded in order from /lib/modules.
 * Their dependencies come from the M8 tail. Only plain names ending in .ko are accepted. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int plain_module(const char *name)
{
    size_t length = strlen(name);
    return length > 3 && length < 64 && !strchr(name, '/') && strcmp(name + length - 3, ".ko") == 0 && name[0] != '.';
}

int main(int argc, char **argv)
{
    static const char empty[] = "";
    char path[96];
    if (argc < 2) {
        fprintf(stderr, "M19 heaps no module named\n");
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        if (!plain_module(argv[i])) {
            fprintf(stderr, "M19 heaps refused name\n");
            return 2;
        }
    }
    for (int i = 1; i < argc; i++) {
        snprintf(path, sizeof(path), "/lib/modules/%s", argv[i]);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            fprintf(stderr, "M19 heaps %s open errno=%d\n", argv[i], errno);
            return 1;
        }
        errno = 0;
        long rc = syscall(SYS_finit_module, fd, empty, 0);
        int error = errno, closed = close(fd);
        fprintf(stderr, "M19 heaps %s rc=%ld errno=%d close=%d\n", argv[i], rc, error, closed);
        if (rc || closed)
            return 1;
    }
    return 0;
}
