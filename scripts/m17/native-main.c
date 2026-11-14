/* M17 G5: the native path's PID 1 and its daily helpers, one static binary (docs/m17-g5.md).
 *
 * As PID 1 (the selector exec'd M19's init script, which execs this as /sbin/m19-pid1): native.c's runtime with R9's
 * steps, then M19's hand-off to systemd on a PASS. T9-root copies this binary into the new root as
 * /run/m19/m19-report, where the session's units run its other modes:
 *   guard    M19 R3's guard with the daily limits: the battery at 42.0 C and any zone at 80 C, as in every M19 run;
 *            no CPU or session-length limit;
 *   session  session.c: the sink, PulseAudio and the CE keypad started in R6 to R9's order, and the record on disk;
 *   volkeys  volkeys.c: Volume Up and Down step the volume, both together take a screenshot;
 *   load     load.c, for the native bootstrap: the modules the selector did not load.
 * M19's reporter mode is not here: nothing reports over USB. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../m19/run2/r2.h"
#include "load.h"
#include "native.h"
#include "session.h"
#include "volkeys.h"

/* R9's steps (scripts/m19/run2/pid9.c), unchanged in order, flags and limits. */
static const struct m19_step steps[] = {
    {"T3-audio", "/m19/t3-audio", 120000, M19_STEP_REQUIRED},
    {"T0-extract", "/m19/t0-extract", 120000, M19_STEP_REQUIRED},
    {"T1-services", "/m19/t1-start", 150000, M19_STEP_REQUIRED},
    {"T2-unlock", "/m19/t2-unlock", 90000, M19_STEP_REQUIRED | M19_STEP_OWNED},
    {"T5-mount", "/m19/t5-mount", 30000, M19_STEP_REQUIRED},
    {"T6-read", "/m19/t6-read", 30000, M19_STEP_REQUIRED},
    {"T7-de", "/m19/t7-de", 120000, M19_STEP_REQUIRED},
    {"T9-root", "/m19/t9-root", 120000, M19_STEP_REQUIRED},
    {"T9-desktop", "/m19/t9-desktop", 60000, M19_STEP_REQUIRED},
    {"T9-gpu", "/m19/t9-gpu", 90000, M19_STEP_REQUIRED},
    {"T9-sound", "/m19/t9-sound", 30000, M19_STEP_REQUIRED},
    {"T9-wifi", "/m19/t9-wifi", 240000, M19_STEP_REQUIRED},
    {"T9-ce", "/m19/t9-ce", 30000, M19_STEP_REQUIRED},
    {"T8-writes", "/m19/t8-writes", 30000, M19_STEP_REQUIRED | M19_STEP_ALWAYS},
};

/* The bootstrap is M17's (the selector already loaded the display and the keys); the ADSP is M19's script. The log
 * goes to the tree's /var/lib/m19, as T5 mounted /data, where R8 and R9 kept the persist file and the sink's log. */
static struct m17_native run = {
    .bootstrap = "/m17/native-bootstrap", .adsp = "/m19/adsp", .display = "/sbin/m16-display", .kmsg = "/dev/kmsg",
    .boot_log = "/run/m19/bootstrap.log", .logcat = "/tee/tmp/m19/logcat.txt", .log_dir = "/m19-data/ubuntu/var/lib/m19",
    .log_name = "m17-native.log", .steps = steps, .step_count = sizeof(steps) / sizeof(steps[0]),
    .bootstrap_ms = 180000, .adsp_ms = 120000, .display_ms = 20000, .blue_ms = 3000, .final_ms = 600000,
};

/* M19 R3's guard. Daily: the battery and zone limits stay; the CPU and session limits are out of reach (a busy
 * browser is daily use, and so is an hour's session). */
static const struct m19_guard guard = {
    .battery_temp = "/sys/class/power_supply/battery/temp", .thermal = "/sys/class/thermal", .stat = "/proc/stat", .kmsg = "/dev/kmsg",
    .systemctl = "/usr/bin/systemctl", .display = "/run/m19/m16-display", .marker = "/run/m19/guard-tripped",
    .units = {"marble-xfce.service", "marble-xorg.service", "marble-xorg-fallback.service"},
    .period_ms = 2000, .note_ms = 30000, .busy_limit = 101, .busy_ms = UINT_MAX, .session_ms = UINT_MAX, .run_ms = 0,
    .command_ms = 30000, .final_ms = 600000, .battery_limit = 420, .zone_limit = 80000,
};

/* The session's PulseAudio, for root (R6), and its display. */
static const char *const pulse_env[] = {"HOME=/run/m19/session", "XDG_RUNTIME_DIR=/run/m19/xdg", "PULSE_SERVER=unix:/run/m19/xdg/pulse/native",
                                        "LC_ALL=C", "PATH=/usr/bin:/bin", NULL};
static const char *const x_env[] = {"DISPLAY=:0", "HOME=/root", "XDG_RUNTIME_DIR=/run/m19/xdg", "PATH=/usr/bin:/bin", NULL};

static const struct m17_session session = {
    .systemctl = "/usr/bin/systemctl", .pactl = "/usr/bin/pactl", .nmcli = "/usr/bin/nmcli", .proc = "/proc",
    .x_socket = "/tmp/.X11-unix/X0", .sink_report = "/run/m19/sink.report", .ce_result = "/run/m19/ce.result",
    .boot_id = "/proc/sys/kernel/random/boot_id", .osrelease = "/proc/sys/kernel/osrelease", .guard_marker = "/run/m19/guard-tripped",
    .sink_unit = "marble-sink.service", .pulse_unit = "marble-pulse.service", .ce_unit = "marble-ce.service",
    .keys_unit = "m17-volkeys.service", .guard_unit = "m19-r3-guard.service", .sink_name = "marble_speaker",
    .panel_comm = "xfce4-panel", .desktop_comm = "xfdesktop", .log = "/var/lib/m19/m17-session.log", .pulse_env = pulse_env,
    .desktop_ms = 180000, .sink_ms = 60000, .pulse_ms = 60000, .ce_ms = 300000, .command_ms = 30000, .poll_ms = 200,
};

static const struct m17_volkeys volkeys = {
    .sys = "/sys", .dev = "/dev/m17", .pactl = "/usr/bin/pactl", .shooter = "/usr/bin/xfce4-screenshooter", .shots = "/root/Pictures",
    .log = "/var/lib/m19/m17-keys.log", .kmsg = "/dev/kmsg", .pulse_env = pulse_env, .x_env = x_env,
    .session_bus = "/run/m19/session-bus", .find_ms = 30000, .command_ms = 2000, .make_nodes = 1,
};

static int finit(int fd, const char *params)
{
    return syscall(SYS_finit_module, fd, params, 0) ? -errno : 0;
}

static void load_log(const char *line)
{
    fprintf(stderr, "%s\n", line);
    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        char text[300];
        int n = snprintf(text, sizeof(text), "<6>%s\n", line);
        (void)!write(fd, text, (size_t)(n < (int)sizeof(text) ? n : (int)sizeof(text) - 1));
        close(fd);
    }
}

static void hold(void)
{
    /* PID 1 must never exit, and nothing here restarts the phone. Long-press ends the run, and the selector's window
     * then times out to Android. */
    for (;;) {
        while (waitpid(-1, NULL, WNOHANG) > 0) {
        }
        (void)poll(NULL, 0, 100);
    }
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "guard"))
        return getpid() == 1 ? 64 : m19_guard_main(&guard);
    if (argc == 2 && !strcmp(argv[1], "session")) {
        struct m17_session_result r;
        return getpid() == 1 ? 64 : m17_session_main(&session, &r);
    }
    if (argc == 2 && !strcmp(argv[1], "volkeys"))
        return getpid() == 1 ? 64 : m17_volkeys_main(&volkeys);
    if (argc == 4 && !strcmp(argv[1], "load")) {
        struct m17_load l = {.closure = argv[2], .list = argv[3], .proc_modules = "/proc/modules", .lib = "/lib/modules",
                             .rows = M17_LOAD_ROWS, .total = M17_LOAD_TOTAL, .finit = finit, .log = load_log};
        return getpid() == 1 ? 64 : m17_load_run(&l);
    }
    if (getpid() != 1 || argc != 1)
        return 64;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    enum m17_native_end end = m17_native_main(&run);
    if (end == M17_END_BOOTSTRAP) {
        /* The bootstrap or the audio stage held, before the ADSP. Nothing touched the TEE. */
        char *argv_red[] = {"/sbin/m16-display", "00ff0000", "600000", NULL};
        if (fork() == 0) {
            execv(argv_red[0], argv_red);
            _exit(127);
        }
    }
    if (end == M17_END_PASS) {
        /* R7: the TEE island stays, for the CE broker and the services it calls. No tty: nothing listens. */
        struct m19_handoff handoff = {.proc = "/proc", .kmsg = "/dev/kmsg", .android = "/tee", .newroot = "/newroot",
                                      .init = "/usr/lib/systemd/systemd", .keep_root = "/tee", .self = getpid(), .settle_ms = 10000,
                                      .poll_ms = 20, .pace_ms = 20, .signal = kill};
        int moved = 0;
        (void)m19_handoff(-1, &handoff, &moved);
        /* Only a failed hand-off returns. The sweep stopped the GREEN painter, so YELLOW can take the panel. */
        char *argv_display[] = {moved ? "/run/m19/m16-display" : "/sbin/m16-display", "00ffff00", "600000", NULL};
        if (fork() == 0) {
            execv(argv_display[0], argv_display);
            _exit(127);
        }
    }
    hold();
}
