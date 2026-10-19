/* P4 helper stand-in (an ELF, as the environment phase requires): with --serve it plays the PD
 * locator, without it the kmsg relay. It writes its ready marker in the working directory with
 * its effective uid and capability mask, then waits to be killed with its parent. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (getppid() == 1) return 3; /* the parent is gone already */
    int fds = 0; /* before anything here opens a file: every fd above stdio was inherited */
    for (int fd = 3; fd < 256; fd++) fds += fcntl(fd, F_GETFD) != -1;
    const char *ready = argc > 1 && !strcmp(argv[1], "--serve") ? "pd.endpoint" : "logger.ready";
    char caps[64] = "?", line[256];
    FILE *f = fopen("/proc/self/status", "r");
    while (f && fgets(line, sizeof line, f)) if (!strncmp(line, "CapEff:", 7)) { sscanf(line + 7, "%63s", caps); break; }
    if (f) fclose(f);
    char b[160];
    int n = snprintf(b, sizeof b, "uid=%d caps=%s fds=%d\n", (int)geteuid(), caps, fds);
    int fd = open(ready, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0 || write(fd, b, (size_t)n) != n) return 4;
    close(fd);
    for (;;) pause();
}
