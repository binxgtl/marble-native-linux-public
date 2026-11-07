/* M19 R4 PID 1. R3's steps and hand-off, with T9-gpu after T9-desktop: KGSL and its suppliers, the GPU
 * firmware in RAM, the GPU's nodes and glamor's configuration. Only a full PASS hands over; nothing restarts
 * the phone. Run as "m19-report report" by systemd, the same binary is the R4 reporter: R3's desktop checks,
 * then the GPU through the tree's own Mesa, glamor and the session's GPU profile. */
#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "r2.h"

static const struct m19_step steps[] = {
    {"T0-extract", "/m19/t0-extract", 120000, M19_STEP_REQUIRED},
    {"T1-services", "/m19/t1-start", 150000, M19_STEP_REQUIRED},
    {"T2-unlock", "/m19/t2-unlock", 90000, M19_STEP_REQUIRED | M19_STEP_OWNED},
    {"T5-mount", "/m19/t5-mount", 30000, M19_STEP_REQUIRED},
    {"T6-read", "/m19/t6-read", 30000, M19_STEP_REQUIRED},
    {"T9-root", "/m19/t9-root", 120000, M19_STEP_REQUIRED},
    {"T9-desktop", "/m19/t9-desktop", 60000, M19_STEP_REQUIRED},
    {"T9-gpu", "/m19/t9-gpu", 90000, M19_STEP_REQUIRED},
    {"T8-writes", "/m19/t8-writes", 30000, M19_STEP_REQUIRED | M19_STEP_ALWAYS},
};

static struct m19_run run = {
    .bootstrap = "/m19/bootstrap", .adsp = "/m19/adsp", .connector = "/sbin/m15-connector", .display = "/sbin/m16-display",
    .tty = "/dev/ttyGS0", .kmsg = "/dev/kmsg", .boot_log = "/run/m19/bootstrap.log", .logcat = "/tee/tmp/m19/logcat.txt",
    .steps = steps, .step_count = sizeof(steps) / sizeof(steps[0]),
    .bootstrap_ms = 120000, .display_ms = 20000, .blue_ms = 3000, .final_ms = 600000, .poll_ms = 5, .pace_ms = 20,
    .link_ms = 420000, .log_ms = 300000, .beat_ms = 5000,
};

/* The session's two profiles (r4plan.DRI3_ENV and COPY_ENV). The checks use dri3, the profile a glamor X
 * server gives every program: freedreno on KGSL for GL, Turnip for Vulkan, both presenting through DRI3.
 * copy, R4a's path, is run once for comparison. */
#define M19_VK_ICD "VK_DRIVER_FILES=/usr/share/vulkan/icd.d/freedreno_icd.aarch64.json"
static const char *const dri3_env[] = {"MESA_LOADER_DRIVER_OVERRIDE=kgsl", "FD_FORCE_KGSL=1", "FD_KGSL_ENABLE_DMABUF=1", M19_VK_ICD, NULL};
static const char *const copy_env[] = {M19_VK_ICD, "MESA_VK_WSI_DEBUG=sw", "MESA_LOADER_DRIVER_OVERRIDE=zink", "LIBGL_KOPPER_DRI2=1", NULL};

static const struct m19_report report = {
    .tty = "/dev/ttyGS0", .kmsg = "/dev/kmsg", .proc1_exe = "/proc/1/exe", .block = "/sys/block", .mountinfo = "/proc/self/mountinfo",
    .systemctl = "/usr/bin/systemctl", .journalctl = "/usr/bin/journalctl", .analyze = "/usr/bin/systemd-analyze",
    .display = "/run/m19/m16-display", .expected_init = "/usr/lib/systemd/systemd",
    .settle_ms = 240000, .poll_ms = 1000, .beat_ms = 5000, .pace_ms = 20, .log_ms = 300000, .command_ms = 30000, .final_ms = 600000,
    .tty_wait_ms = 30000,
    .desktop = 1, .x_wait_ms = 120000, .session_wait_ms = 120000, .touch_ms = 60000, .want_hz = 120.0,
    .xdpyinfo = "/usr/bin/xdpyinfo", .xrandr = "/usr/bin/xrandr", .xinput = "/usr/bin/xinput", .ps = "/usr/bin/ps", .proc = "/proc",
    .interrupts = "/proc/interrupts", .card = "/dev/dri/card0", .touch_name = "goodix_ts",
    .xorg_logs = {"/var/log/Xorg.0.log", "/var/log/Xorg.cpu.log"},
    .guard_unit = "m19-r3-guard.service", .guard_marker = "/run/m19/guard-tripped",
    .battery_temp = "/sys/class/power_supply/battery/temp", .thermal = "/sys/class/thermal",
    .gpu = 1, .gpu_ms = 30000, .gears_ms = 11000, .cube_frames = 300, .kgsl_node = "/dev/kgsl-3d0",
    .kgsl_model = "/sys/class/kgsl/kgsl-3d0/gpu_model", .gpu_probe = "/run/m19/m19-gpu-probe", .vulkaninfo = "/usr/bin/vulkaninfo",
    .vkcube = "/usr/bin/vkcube", .glxinfo = "/usr/bin/glxinfo", .glxgears = "/usr/bin/glxgears", .eglinfo = "/usr/bin/eglinfo",
    .vk_env = dri3_env, .gl_env = dri3_env, .egl_env = dri3_env, .glamor = 1, .xorg_unit = "marble-xorg.service",
    .gpu_profile = "/run/m19/gpu-profile", .glmark2 = "/usr/bin/glmark2", .copy_env = copy_env,
    .present_probe = "/run/m19/m19-present-probe", .present_frames = 120, .compositor = 1,
};

/* Battery 42.0 C, any thermal zone 80 C, CPU 90 % busy for a minute, or fifteen minutes in all. */
static const struct m19_guard guard = {
    .battery_temp = "/sys/class/power_supply/battery/temp", .thermal = "/sys/class/thermal", .stat = "/proc/stat", .kmsg = "/dev/kmsg",
    .systemctl = "/usr/bin/systemctl", .display = "/run/m19/m16-display", .marker = "/run/m19/guard-tripped",
    .units = {"marble-xfce.service", "marble-xorg.service", "marble-xorg-fallback.service"},
    .period_ms = 2000, .note_ms = 30000, .busy_limit = 90, .busy_ms = 60000, .session_ms = 900000, .run_ms = 0, .command_ms = 30000,
    .final_ms = 600000, .battery_limit = 420, .zone_limit = 80000,
};

static void hold(void)
{
    /* PID 1 must never exit, and nothing here restarts the phone. Long-press ends the run. */
    for (;;) {
        while (waitpid(-1, NULL, WNOHANG) > 0) {
        }
        (void)poll(NULL, 0, 100);
    }
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "report"))
        return getpid() == 1 ? 64 : m19_report_main(&report);
    if (argc == 2 && !strcmp(argv[1], "guard"))
        return getpid() == 1 ? 64 : m19_guard_main(&guard);
    if (getpid() != 1 || argc != 1)
        return 64;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    if (m19_run_main(&run) == M19_END_PASS) {
        struct m19_handoff handoff = {.proc = "/proc", .kmsg = "/dev/kmsg", .android = "/tee", .newroot = "/newroot",
                                      .init = "/usr/lib/systemd/systemd", .self = getpid(), .settle_ms = 10000, .poll_ms = 20,
                                      .pace_ms = 20, .signal = kill};
        int moved = 0;
        (void)m19_handoff(run.tty_fd, &handoff, &moved);
        /* Only a failed hand-off returns. The sweep stopped the GREEN painter, so YELLOW can take the panel. */
        char *argv_display[] = {moved ? "/run/m19/m16-display" : "/sbin/m16-display", "00ffff00", "600000", NULL};
        if (fork() == 0) {
            execv(argv_display[0], argv_display);
            _exit(127);
        }
    }
    hold();
}
