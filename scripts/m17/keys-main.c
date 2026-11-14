/* M17 G3 K1-keys on the phone (g3.h, docs/m17-g3.md): run by M19's runtime as a step, its output in the boot log. */
#define _GNU_SOURCE
#include "g3.h"
#include "select.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int finit(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    int rc = syscall(SYS_finit_module, fd, "", 0) ? -errno : 0;
    close(fd);
    return rc;
}

int main(void) {
    struct timespec t;
    clock_gettime(CLOCK_BOOTTIME, &t);
    printf("M17 G3 start boottime_ms=%llu\n", (unsigned long long)t.tv_sec * 1000u + (unsigned long long)t.tv_nsec / 1000000u);
    fflush(stdout);
    struct m17_g3 g = {
        .sys_root = "/sys", .dev_root = "/dev", .modules_dir = "/lib/modules", .make_nodes = 1, .require_chr = 1, .load = finit,
        .now_ms = m17_monotonic_ms, .up_wait_ms = 5000, .down_wait_ms = 15000, .window_ms = 120000, .settle_ms = 5000, .poll_ms = 20,
        .select_ms = M17_WINDOW_MS, .out = stdout,
    };
    struct m17_g3_result r;
    return m17_g3_run(&g, &r);
}
