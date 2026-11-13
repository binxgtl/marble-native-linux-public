/* M19 R6 tests: a stand-in for m12-cnssd on its owner socket, and for the kernel's CNSS log lines after fs_ready.
 *   argv[1]: the inherited SOCK_SEQPACKET descriptor, as m12-cnssd takes it.
 *   M19_FAKE_CNSSD: ready (default), poison (POISON in place of READY), silent (never READY), exit (at once), bad (a malformed
 *                   record), late-poison (READY, then POISON once fs_ready was written).
 *   M19_FAKE_CBC:   good (default), wrong-bdf, caldb (CalDB: 1, a seed would be needed), none (no lines).
 *   M19_FAKE_FS_READY, M19_FAKE_KMSG: the files standing in for /sys/kernel/cnss/fs_ready and /dev/kmsg.
 *   M19_FAKE_POISON_ON: a path; once it exists, a POISON record (a daemon fault after the bring-up).
 *   M19_FAKE_PARENT: the test's init (its subreaper). Like m12-cnssd (getppid() != 1: return 2), the stand-in returns 2
 *                    at once under any other parent, as R6a's daemon did under m19-wifi. */
#define _GNU_SOURCE
#include "../../m12/next/cnssd.h"

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fd;
static uint32_t sequence;

static void send_record(uint32_t event, uint32_t phase)
{
    struct m12_owner_record r;
    memset(&r, 0, sizeof(r));
    r.magic = M12_OWNER_MAGIC;
    r.version = M12_OWNER_VERSION;
    r.sequence = ++sequence;
    r.event = event;
    r.phase = phase;
    r.node = 1;
    r.port = 0x4000;
    if (send(fd, &r, sizeof(r), MSG_NOSIGNAL) != (ssize_t)sizeof(r))
        exit(5);
}

static void kernel(const char *message)
{
    const char *path = getenv("M19_FAKE_KMSG");
    FILE *log = path ? fopen(path, "a") : NULL;
    if (!log)
        exit(6);
    static unsigned long long seq = 900000;
    seq++;
    fprintf(log, "6,%llu,%llu,-;%s\n", seq, seq * 10, message);
    fclose(log);
}

static int fs_ready_written(void)
{
    const char *path = getenv("M19_FAKE_FS_READY");
    char text[8] = {0};
    FILE *file = path ? fopen(path, "r") : NULL;
    if (!file)
        return 0;
    size_t n = fread(text, 1, sizeof(text) - 1, file);
    fclose(file);
    return n == 1 && text[0] == '1';
}

int main(int argc, char **argv)
{
    const char *init = getenv("M19_FAKE_PARENT");
    if (!init || getppid() != (pid_t)atol(init) || argc != 2)
        return 2;
    fd = atoi(argv[1]);
    const char *mode = getenv("M19_FAKE_CNSSD") ? getenv("M19_FAKE_CNSSD") : "ready";
    const char *cbc = getenv("M19_FAKE_CBC") ? getenv("M19_FAKE_CBC") : "good";
    if (!strcmp(mode, "exit"))
        return 1;
    if (!strcmp(mode, "bad")) {
        uint32_t junk[4] = {1, 2, 3, 4};
        (void)send(fd, junk, sizeof(junk), MSG_NOSIGNAL);
    } else if (!strcmp(mode, "poison")) {
        send_record(M12_DISCOVERY, M12_DB_REGISTER);
        send_record(M12_POISON, M12_DB_FAILED);
    } else if (strcmp(mode, "silent")) {
        send_record(M12_DISCOVERY, M12_DB_REGISTER);
        send_record(M12_READY, M12_DB_IDLE);
    }
    int calibrated = 0, poisoned = 0;
    const char *poison_on = getenv("M19_FAKE_POISON_ON");
    for (;;) {
        if (poison_on && !poisoned && access(poison_on, F_OK) == 0) {
            poisoned = 1;
            send_record(M12_POISON, M12_DB_FAILED);
        }
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int rc = poll(&p, 1, 20);
        if (rc > 0) {
            char buffer[256];
            ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
            if (n <= 0)
                return 0; /* the owner went away */
        }
        if (!calibrated && fs_ready_written()) {
            calibrated = 1;
            if (!strcmp(mode, "late-poison")) {
                send_record(M12_POISON, M12_DB_FAILED);
                continue;
            }
            if (!strcmp(cbc, "none"))
                continue;
            kernel(!strcmp(cbc, "caldb") ? "cnss: Host BDF config: HW_XPA: 1 CalDB: 1" : "cnss: Host BDF config: HW_XPA: 1 CalDB: 0");
            kernel(!strcmp(cbc, "wrong-bdf") ? "cnss: Downloading BDF: qca6490/bdwlang.elf, size: 59936"
                                             : "cnss: Downloading BDF: qca6490/bd_m16tgf.elf, size: 59872");
            kernel("cnss: Processing driver event: COLD_BOOT_CAL_START(14)");
            kernel("cnss: Processing driver event: COLD_BOOT_CAL_DONE(15)");
            kernel("cnss: Calibration completed successfully");
            kernel("cnss: Setting mode: MISSION(0)");
            send_record(M12_STATE, M12_DB_IDLE);
        }
    }
}
