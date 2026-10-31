/* The one module R1 adds to the M8 closure. Its dependencies come from the M8 tail. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    static const char empty[] = "";
    int fd = open("/lib/modules/qcom_dma_heaps.ko", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "M19 heaps open errno=%d\n", errno);
        return 1;
    }
    errno = 0;
    long rc = syscall(SYS_finit_module, fd, empty, 0);
    int error = errno, closed = close(fd);
    fprintf(stderr, "M19 heaps rc=%ld errno=%d close=%d\n", rc, error, closed);
    return rc || closed ? 1 : 0;
}
