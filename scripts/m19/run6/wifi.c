/* M19 R6: m19-wifi, the session's Wi-Fi bring-up (wifi.h, docs/m19-r6.md).
 *
 * The order is M12 Run10/Run11's, which reached WPA2, DHCP and a gateway ping natively:
 *   1. checks: one run a boot, T9-wifi's stage "staged", the firmware loader on the RAM copy, and hwid.ko's four
 *      parameters equal to the bootloader's (the audio stage loaded it with them; without them CNSS picks the
 *      generic BDF, M12 Run6);
 *   2. the kernel log cursor, before anything loads (M12's CBC evidence comes from it);
 *   3. the seven CNSS modules through the checked loader (m19-audio load LIST wifi), then M12's 20 s settle and a
 *      unique PCI 17cb:1103 bound to cnss_pci;
 *   4. the six WLAN modules (m19-audio load LIST wlan);
 *   5. the RAM-only CNSS daemon (M12 Run9 to Run11's m12-cnssd, byte for byte) under this owner, READY and idle,
 *      and the firmware name CNSS chose;
 *   6. one fs_ready write, from a child; then the cold-boot calibration to MISSION mode with the exact BDF and
 *      target, as M12's parser reads them from the kernel log;
 *   7. one interface with a wiphy below that PCI device.
 * Then the kernel log closes for good (network names follow), wifi.ready appears, NetworkManager starts, and this
 * process stays the daemon's owner. Nothing is ever unloaded, killed or retried: a failure records its step and the
 * process holds what it has. */
#define _GNU_SOURCE
#include "wifi.h"

#include "../../m12/run10/owner-supervisor.h"
#include "../../m12/run5/cbc-evidence.h"
#include "../../m12/run7/hwid.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct m19_wifi_config m19_wifi_config_default(void)
{
    struct m19_wifi_config c = {
        .stage = "/run/m19/wifi.stage", .helper = "/run/m19/wifi/m19-audio", .list = "/run/m19/wifi/modules.list",
        .modules = "/run/m19/wifi/modules", .cnssd = "/run/m19/wifi/m12-cnssd", .systemctl = "/usr/bin/systemctl",
        .nm_unit = "NetworkManager.service", .started = "/run/m19/wifi.started", .result = "/run/m19/wifi.result",
        .report = "/run/m19/wifi.report", .ready = "/run/m19/wifi.ready", .cmdline = "/proc/cmdline", .proc_modules = "/proc/modules",
        .hwid = "/sys/module/hwid/parameters", .fw_path = "/sys/module/firmware_class/parameters/path", .fw_want = "/run/m19/firmware",
        .pci = "/sys/bus/pci/devices", .platform = "/sys/bus/platform/devices/b0000000.qcom,cnss-qca6490", .mhi = "/sys/bus/mhi/devices",
        .net = "/sys/class/net", .fs_ready = "/sys/kernel/cnss/fs_ready", .kmsg = "/dev/kmsg",
        .load_ms = 180000, .settle_ms = 20000, .owner_ms = 20000, .fs_ready_ms = 10000, .cbc_ms = 180000, .iface_ms = 25000,
        .command_ms = 30000, .pump_ms = 10, .return_after_ms = 0, .require_root = 1,
    };
    return c;
}

static const struct m19_wifi_config *C;
static struct m12_owner_supervisor owner = {.fd = -1, .child = -1};
static struct m12_cbc_evidence cbc;
static int kmsg_fd = -1, owner_ready, owner_fault;
static unsigned long long kmsg_seq, kmsg_records, kmsg_gaps, owner_records;
static int kmsg_seen;
static char carry[8192];
static size_t carried;

/* What the reporter reads. */
static struct {
    char step[32], iface[32], bdf[32];
    int rc, hwid, wifi_rc, pci, wlan_rc, owner, firmware, fs_ready, cbc, nm;
    unsigned long long began_ms, ready_ms;
} st;

static unsigned long long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000ull + (unsigned long long)t.tv_nsec / 1000000ull;
}

static void say(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    fputs("M19 wifi: ", stdout);
    vprintf(format, ap);
    fputc('\n', stdout);
    fflush(stdout);
    va_end(ap);
}

/* path holds text, written whole through a temporary file and a rename. */
static int publish(const char *path, const char *text)
{
    char temporary[PATH_MAX];
    if (snprintf(temporary, sizeof(temporary), "%s.tmp", path) >= (int)sizeof(temporary))
        return -1;
    int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0)
        return -1;
    size_t length = strlen(text);
    ssize_t written = write(fd, text, length);
    int bad = written != (ssize_t)length || fsync(fd);
    if (close(fd) || bad || rename(temporary, path))
        return -1;
    return 0;
}

static void write_report(void)
{
    char text[1024];
    snprintf(text, sizeof(text),
             "step=%s\nrc=%d\nhwid=%d\nwifi_rc=%d\npci=%d\nbdf=%s\nwlan_rc=%d\nowner=%d\nfirmware=%d\nfs_ready=%d\ncbc=%d\n"
             "cbc_bdf=%u\ncbc_capability=%u\ncbc_mission=%u\ncbc_done=%u\ncbc_requirement=%d\ncbc_fault=%d\niface=%s\nnm=%d\n"
             "kmsg_records=%llu\nkmsg_gaps=%llu\nowner_records=%llu\nowner_poisoned=%d\nready_ms=%llu\n",
             st.step, st.rc, st.hwid, st.wifi_rc, st.pci, st.bdf[0] ? st.bdf : "-", st.wlan_rc, st.owner, st.firmware, st.fs_ready,
             st.cbc, cbc.bdf, cbc.capability, cbc.mission, cbc.done, (int)cbc.requirement, cbc.fault, st.iface[0] ? st.iface : "-", st.nm,
             kmsg_records, kmsg_gaps, owner_records, owner.poisoned, st.ready_ms);
    if (publish(C->report, text))
        say("report write failed errno=%d", errno);
}

static int read_text(const char *path, char *text, size_t room)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    ssize_t n = read(fd, text, room - 1);
    int error = errno;
    close(fd);
    if (n < 0)
        return -error;
    if ((size_t)n == room - 1)
        return -EOVERFLOW;
    text[n] = 0;
    return 0;
}

int m19_wifi_kmsg_record(const char *line, unsigned long long *seq, const char **message)
{
    if (line[0] == ' ')
        return 1;
    const char *semicolon = strchr(line, ';');
    unsigned priority;
    unsigned long long sequence, stamp;
    int used = 0;
    if (!semicolon || sscanf(line, "%u,%llu,%llu,%n", &priority, &sequence, &stamp, &used) != 3 || !used || line + used > semicolon)
        return -1;
    *seq = sequence;
    *message = semicolon + 1;
    return 0;
}

static void kmsg_line(char *line)
{
    unsigned long long sequence;
    const char *message;
    if (m19_wifi_kmsg_record(line, &sequence, &message))
        return;
    if (kmsg_seen && sequence != kmsg_seq + 1)
        kmsg_gaps++;
    kmsg_seq = sequence;
    kmsg_seen = 1;
    kmsg_records++;
    if (m12_cbc_line(&cbc, message))
        say("kernel %s", message);
}

/* /dev/kmsg gives one record a read; a test's regular file gives any amount. Either way, whole lines only. */
static void pump_kmsg(void)
{
    for (unsigned rounds = 0; kmsg_fd >= 0 && rounds < 256; rounds++) {
        ssize_t n = read(kmsg_fd, carry + carried, sizeof(carry) - 1 - carried);
        if (n < 0) {
            if (errno == EPIPE) {
                kmsg_gaps++;
                continue;
            }
            if (errno != EAGAIN && errno != EINTR) {
                say("kernel log read errno=%d", errno);
                cbc.fault = -EIO;
            }
            return;
        }
        if (!n)
            return;
        carried += (size_t)n;
        carry[carried] = 0;
        char *start = carry, *end;
        while ((end = strchr(start, '\n'))) {
            *end = 0;
            kmsg_line(start);
            start = end + 1;
        }
        carried = strlen(start);
        memmove(carry, start, carried);
        if (carried == sizeof(carry) - 1)
            carried = 0; /* a line longer than any record: dropped */
    }
}

static int owner_idle(void)
{
    return owner_ready && !owner_fault && !owner.poisoned && owner.latest.phase == M12_DB_IDLE && !owner.latest.waiting_message;
}

static void pump_owner(void)
{
    for (unsigned i = 0; owner.fd >= 0 && !owner_fault && i < 64; i++) {
        int rc = m12_owner_receive(&owner, 0);
        if (!rc)
            break;
        if (rc < 0) {
            say("daemon receipt rc=%d; daemon kept, never killed", rc);
            owner_fault = 1;
            break;
        }
        const struct m12_owner_record *r = &owner.latest;
        owner_records++;
        if (owner_records <= 64 || r->event != M12_STATE)
            say("daemon sequence=%u event=%u phase=%u rc=%d qmi=%u/%u waiting=%u", r->sequence, r->event, r->phase, r->rc, r->qmi_result,
                r->qmi_error, r->waiting_message);
        if (r->event == M12_READY)
            owner_ready = 1;
        if (owner.poisoned)
            owner_fault = 1;
    }
}

static void pump(void)
{
    pump_owner();
    pump_kmsg();
}

static void wait_ms(unsigned ms)
{
    unsigned long long end = now_ms() + ms;
    while (now_ms() < end) {
        pump();
        (void)poll(NULL, 0, (int)C->pump_ms);
    }
}

/* Runs argv with the journal as its output and waits up to ms, pumping. The exit status; -ECHILD when it died
 * of a signal; -ETIMEDOUT when it still runs (it is left running: a module load cannot be cancelled). */
static int child(char *const argv[], unsigned ms)
{
    pid_t pid = fork();
    if (pid < 0)
        return -errno;
    if (!pid) {
        execv(argv[0], argv);
        _exit(127);
    }
    unsigned long long end = now_ms() + ms;
    for (;;) {
        int status;
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : -ECHILD;
        if (got < 0 && errno != EINTR)
            return -errno;
        if (now_ms() >= end)
            return -ETIMEDOUT;
        pump();
        (void)poll(NULL, 0, (int)C->pump_ms);
    }
}

static int hwid_check(void)
{
    char text[16384];
    struct m12_hwid want;
    if (read_text(C->cmdline, text, sizeof(text)) || m12_hwid_parse(text, strlen(text), 1, &want))
        return -EINVAL;
    for (unsigned i = 0; i < 4; i++) {
        char path[PATH_MAX], value[64];
        unsigned got = 0;
        snprintf(path, sizeof(path), "%s/%s", C->hwid, m12_hwid_keys[i]);
        if (read_text(path, value, sizeof(value)) || m12_hwid_uint(value, strlen(value), &got))
            return -EPROTO;
        say("hwid %s expected=%u observed=%u", m12_hwid_keys[i], want.v[i], got);
        if (got != want.v[i])
            return -EXDEV;
    }
    return 0;
}

static int text_is(const char *path, const char *want)
{
    char text[256];
    if (read_text(path, text, sizeof(text)))
        return 0;
    size_t n = strlen(text);
    while (n && (text[n - 1] == '\n' || text[n - 1] == '\r'))
        text[--n] = 0;
    return !strcmp(text, want);
}

static int driver_is(const char *link, const char *name)
{
    char target[PATH_MAX];
    if (!realpath(link, target))
        return 0;
    const char *base = strrchr(target, '/');
    return base && !strcmp(base + 1, name);
}

/* Exactly one PCI 17cb:1103 bound to cnss_pci: its name in bdf. */
static int pci_ready(char *bdf, size_t room)
{
    DIR *directory = opendir(C->pci);
    if (!directory)
        return -ENODEV;
    int found = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] == '.')
            continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s/vendor", C->pci, entry->d_name);
        if (!text_is(path, "0x17cb"))
            continue;
        snprintf(path, sizeof(path), "%s/%s/device", C->pci, entry->d_name);
        if (!text_is(path, "0x1103"))
            continue;
        snprintf(path, sizeof(path), "%s/%s/driver", C->pci, entry->d_name);
        if (!driver_is(path, "cnss_pci"))
            continue;
        if (++found == 1)
            snprintf(bdf, room, "%s", entry->d_name);
    }
    closedir(directory);
    return found == 1 ? 0 : found ? -EEXIST : -ENODEV;
}

static int module_loaded(const char *name)
{
    FILE *modules = fopen(C->proc_modules, "re");
    if (!modules)
        return 0;
    char line[512];
    size_t n = strlen(name);
    int yes = 0;
    while (!yes && fgets(line, sizeof(line), modules))
        yes = !strncmp(line, name, n) && line[n] == ' ';
    fclose(modules);
    return yes;
}

static int below(const char *child_path, const char *parent)
{
    size_t n = strlen(parent);
    return !strncmp(child_path, parent, n) && (child_path[n] == '/' || !child_path[n]);
}

/* One interface whose device and wiphy both sit below the PCI device (or the CNSS platform device). */
static int find_iface(const char *bdf, char *iface, size_t room)
{
    char pci_real[PATH_MAX], platform_real[PATH_MAX], path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", C->pci, bdf);
    int have_pci = realpath(path, pci_real) != NULL, have_platform = realpath(C->platform, platform_real) != NULL;
    DIR *directory = opendir(C->net);
    if (!directory)
        return -ENODEV;
    int found = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] == '.' || strlen(entry->d_name) >= 16)
            continue;
        char device[PATH_MAX], phy[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s/device", C->net, entry->d_name);
        if (!realpath(path, device))
            continue;
        snprintf(path, sizeof(path), "%s/%s/phy80211/device", C->net, entry->d_name);
        if (!realpath(path, phy))
            continue;
        if (!((have_pci && below(device, pci_real) && below(phy, pci_real)) ||
              (have_platform && below(device, platform_real) && below(phy, platform_real))))
            continue;
        if (++found == 1)
            snprintf(iface, room, "%s", entry->d_name);
    }
    closedir(directory);
    return found == 1 ? 0 : found ? -EEXIST : -ENODEV;
}

/* M12's readiness: the WLAN driver and cnss_utils loaded, the same PCI endpoint, CNSS bound to its platform device,
 * MHI devices present, and one interface. */
static int stack_ready(const char *bdf, char *iface, size_t room)
{
    char again[64], link[PATH_MAX];
    snprintf(link, sizeof(link), "%s/driver", C->platform);
    DIR *mhi = opendir(C->mhi);
    int mhi_entries = 0;
    if (mhi) {
        struct dirent *entry;
        while ((entry = readdir(mhi)))
            mhi_entries += entry->d_name[0] != '.';
        closedir(mhi);
    }
    if (!module_loaded("qca6490") || !module_loaded("cnss_utils") || pci_ready(again, sizeof(again)) || strcmp(again, bdf) ||
        !driver_is(link, "cnss2") || !mhi_entries)
        return -ENODEV;
    return find_iface(bdf, iface, room);
}

/* The daemon, under this process as its owner: a private SOCK_SEQPACKET pair, the daemon's end as its argument. */
static int launch_owner(void)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair))
        return -errno;
    pid_t pid = fork();
    if (pid < 0) {
        int error = errno;
        close(pair[0]);
        close(pair[1]);
        return -error;
    }
    if (!pid) {
        char fd[16];
        snprintf(fd, sizeof(fd), "%d", pair[1]);
        if (close(pair[0]) || fcntl(pair[1], F_SETFD, 0))
            _exit(126);
        execl(C->cnssd, "m12-cnssd", fd, (char *)NULL);
        _exit(127);
    }
    close(pair[1]);
    owner.fd = pair[0];
    owner.child = pid;
    unsigned long long end = now_ms() + C->owner_ms;
    while (now_ms() < end && !owner_ready && !owner_fault) {
        pump();
        (void)poll(NULL, 0, (int)C->pump_ms);
    }
    if (!owner_idle())
        return owner_fault ? -EPROTO : -ETIMEDOUT;
    return 0;
}

/* One write of "1", from a child: a sysfs store may block, and the owner and the kernel log keep being read. */
static int fs_ready(void)
{
    pid_t pid = fork();
    if (pid < 0)
        return -errno;
    if (!pid) {
        int fd = open(C->fs_ready, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            _exit(10);
        ssize_t n = write(fd, "1", 1);
        int closed = close(fd);
        _exit(n == 1 && !closed ? 0 : 11);
    }
    unsigned long long end = now_ms() + C->fs_ready_ms;
    for (;;) {
        int status;
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid)
            return WIFEXITED(status) ? -WEXITSTATUS(status) : -ECHILD;
        if (now_ms() >= end)
            return -ETIMEDOUT;
        pump();
        (void)poll(NULL, 0, (int)C->pump_ms);
    }
}

/* The end: what the reporter reads, then the daemon's owner for good (tests return). */
static int finish(int ready, const char *step, int rc)
{
    char text[128];
    snprintf(st.step, sizeof(st.step), "%s", step);
    st.rc = rc;
    if (ready)
        snprintf(text, sizeof(text), "ready %s\n", st.iface);
    else
        snprintf(text, sizeof(text), "failed %s %d\n", step, rc);
    write_report();
    if (publish(C->result, text))
        say("result write failed errno=%d", errno);
    say("result %s", text);
    unsigned long long end = now_ms() + C->return_after_ms;
    int faulted = owner_fault;
    for (;;) {
        if (C->return_after_ms && now_ms() >= end)
            return ready ? 0 : 1;
        pump_owner();
        if (!faulted && owner_fault) {
            faulted = 1;
            say("daemon fault after %s", ready ? "readiness" : step);
            if (ready && publish(C->result, "fault owner\n"))
                say("result write failed errno=%d", errno);
            write_report();
        }
        (void)poll(NULL, 0, owner.fd >= 0 && !owner_fault ? 1000 : 60000);
    }
}

int m19_wifi_run(const struct m19_wifi_config *c)
{
    C = c;
    st.began_ms = now_ms();
    snprintf(st.step, sizeof(st.step), "start");
    signal(SIGPIPE, SIG_IGN);
    if (c->require_root && getuid() != 0) {
        say("refused: not root");
        return 2;
    }
    int stamp = open(c->started, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (stamp < 0) {
        say("refused: already started (errno=%d)", errno);
        return 2;
    }
    close(stamp);

    /* 1. checks: nothing is touched before these pass. */
    char text[256];
    if (read_text(c->stage, text, sizeof(text)) || strcmp(text, "staged\n")) {
        say("not staged: %s", read_text(c->stage, text, sizeof(text)) ? "missing" : text);
        if (publish(c->result, "skipped stage\n"))
            say("result write failed errno=%d", errno);
        snprintf(st.step, sizeof(st.step), "stage");
        write_report();
        return 2;
    }
    if (!text_is(c->fw_path, c->fw_want))
        return finish(0, "firmware-path", -EXDEV);
    int rc = hwid_check();
    st.hwid = !rc;
    if (rc)
        return finish(0, "hwid", rc);

    /* 2. the kernel log, from its end */
    kmsg_fd = open(c->kmsg, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (kmsg_fd < 0 || lseek(kmsg_fd, 0, SEEK_END) < 0)
        return finish(0, "kmsg", -errno);

    /* 3. the CNSS modules, M12's settle, the PCI endpoint */
    char *wifi[] = {(char *)c->helper, "load", (char *)c->list, "wifi", (char *)c->modules, (char *)c->modules, NULL};
    say("loading the CNSS modules");
    st.wifi_rc = child(wifi, c->load_ms);
    if (st.wifi_rc)
        return finish(0, "load-wifi", st.wifi_rc);
    wait_ms(c->settle_ms);
    rc = pci_ready(st.bdf, sizeof(st.bdf));
    st.pci = !rc;
    say("pci %s rc=%d", st.pci ? st.bdf : "-", rc);
    if (rc)
        return finish(0, "pci", rc);

    /* 4. the WLAN modules */
    char *wlan[] = {(char *)c->helper, "load", (char *)c->list, "wlan", (char *)c->modules, (char *)c->modules, NULL};
    say("loading the WLAN modules");
    st.wlan_rc = child(wlan, c->load_ms);
    if (st.wlan_rc)
        return finish(0, "load-wlan", st.wlan_rc);

    /* 5. the daemon, and the firmware CNSS named */
    rc = launch_owner();
    st.owner = !rc;
    say("daemon pid=%d ready=%d idle=%d rc=%d", (int)owner.child, owner_ready, owner_idle(), rc);
    if (rc)
        return finish(0, "owner", rc);
    pump_kmsg();
    st.firmware = cbc.firmware && !cbc.fault;
    if (!st.firmware)
        return finish(0, "firmware", cbc.fault ? cbc.fault : -ENOENT);

    /* 6. fs_ready once, then calibration to MISSION */
    rc = fs_ready();
    st.fs_ready = !rc;
    say("fs_ready rc=%d", rc);
    if (rc)
        return finish(0, "fs-ready", rc);
    unsigned long long end = now_ms() + c->cbc_ms;
    while (!m12_cbc_ready(&cbc, owner_idle(), 0)) {
        if (owner_fault || cbc.fault)
            return finish(0, "cbc", owner_fault ? -EPROTO : cbc.fault);
        if (cbc.requirement == M12_CAL_REQUIRED)
            return finish(0, "cbc", -ENODATA);
        if (now_ms() >= end)
            return finish(0, "cbc", -ETIMEDOUT);
        pump();
        (void)poll(NULL, 0, (int)c->pump_ms);
    }
    st.cbc = 1;
    say("calibration done, MISSION mode");

    /* 7. the interface */
    end = now_ms() + c->iface_ms;
    while ((rc = stack_ready(st.bdf, st.iface, sizeof(st.iface)))) {
        if (now_ms() >= end)
            return finish(0, "iface", rc);
        wait_ms(250);
    }
    say("interface %s", st.iface);

    /* The kernel log closes for good: from here it carries network names. */
    close(kmsg_fd);
    kmsg_fd = -1;
    st.ready_ms = now_ms() - st.began_ms;
    int marker = open(c->ready, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (marker < 0)
        return finish(0, "ready-marker", -errno);
    close(marker);
    char *start[] = {(char *)c->systemctl, "start", "--no-block", (char *)c->nm_unit, NULL};
    st.nm = child(start, c->command_ms);
    say("NetworkManager start rc=%d", st.nm);
    return finish(1, "ready", 0);
}
