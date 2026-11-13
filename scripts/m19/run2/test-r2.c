/* The real handoff.c and report.c on synthetic trees. Never staged into an image.
 * mount, umount2, chroot, chdir, execve and stat are wrapped at link time: the hand-off is
 * recorded, never performed, and no real process is ever signalled. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "r2.h"

static int record_fd = -1;
static char proc_dir[4096], newroot_dir[4096];

__attribute__((format(printf, 1, 2)))
static void record(const char *format, ...)
{
    char text[1024];
    va_list arguments;
    va_start(arguments, format);
    int n = vsnprintf(text, sizeof(text) - 1, format, arguments);
    va_end(arguments);
    if (n < 0 || record_fd < 0)
        return;
    if ((size_t)n > sizeof(text) - 2)
        n = (int)sizeof(text) - 2;
    text[n++] = '\n';
    ssize_t put = write(record_fd, text, (size_t)n);
    (void)put;
}

static int failing(const char *name)
{
    const char *fail = getenv("M19_FAIL");
    return fail && !strcmp(fail, name);
}

int __real_stat(const char *path, struct stat *st);
int __real_ioctl(int fd, unsigned long request, void *arg);

/* DRM_IOCTL_WAIT_VBLANK answered from M19_VBLANK_HZ: one frame, then sixty frames later.
 * Without it the ioctl fails as on a CRTC that is off. Every other request is real. */
int __wrap_ioctl(int fd, unsigned long request, void *arg)
{
    static unsigned calls;
    if ((request & 0xff) != 0x3a || ((request >> 8) & 0xff) != 'd')
        return __real_ioctl(fd, request, arg);
    const char *rate = getenv("M19_VBLANK_HZ");
    if (!rate) {
        errno = EINVAL;
        return -1;
    }
    unsigned char *reply = arg;
    uint32_t sequence = 1000u + (calls % 2 ? 60u : 0u);
    double at = 100.0 + (calls % 2 ? 60.0 / strtod(rate, NULL) : 0.0);
    long sec = (long)at, usec = (long)((at - (double)sec) * 1e6);
    memcpy(reply + 4, &sequence, 4);
    memcpy(reply + 8, &sec, 8);
    memcpy(reply + 16, &usec, 8);
    calls++;
    return 0;
}
int __wrap_umount2(const char *target, int flags)
{
    record("umount2 %s %d", target, flags);
    if (failing("umount2")) {
        errno = EBUSY;
        return -1;
    }
    return 0;
}

int __wrap_mount(const char *source, const char *target, const char *type, unsigned long flags, const void *data)
{
    (void)data;
    record("mount %s %s %s %lu", source, target, type ? type : "-", flags);
    if (failing("mount")) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int __wrap_chroot(const char *path)
{
    record("chroot %s", path);
    if (failing("chroot")) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

int __wrap_chdir(const char *path)
{
    record("chdir %s", path);
    return 0;
}

int __wrap_stat(const char *path, struct stat *st)
{
    int rc = __real_stat(path, st);
    if (rc)
        return rc;
    char parent[4200];
    snprintf(parent, sizeof(parent), "%s/..", newroot_dir);
    /* The new root is a mount point unless the test says otherwise. */
    if (!strcmp(path, newroot_dir))
        st->st_dev = failing("newroot") ? 2 : 1;
    else if (!strcmp(path, parent))
        st->st_dev = 2;
    return rc;
}

int __wrap_execve(const char *path, char *const argv[], char *const envp[])
{
    record("execve %s", path);
    for (unsigned i = 0; argv[i]; i++)
        record("argv %s", argv[i]);
    for (unsigned i = 0; envp[i]; i++)
        record("envp %s", envp[i]);
    if (failing("execve")) {
        errno = ENOENT;
        return -1;
    }
    record("exec-done");
    _exit(0);
}

/* Stands in for kill(2). A "killed" synthetic process disappears from the fake /proc. */
static int fake_signal(pid_t pid, int number)
{
    record("signal %d %d", (int)pid, number);
    if (!failing("survivor")) {
        char path[4200];
        snprintf(path, sizeof(path), "%s/%d/stat", proc_dir, (int)pid);
        unlink(path);
        snprintf(path, sizeof(path), "%s/%d/root", proc_dir, (int)pid);
        unlink(path);
        snprintf(path, sizeof(path), "%s/%d", proc_dir, (int)pid);
        rmdir(path);
    }
    return 0;
}

static int kthread_mode(void)
{
    char line[2048];
    while (fgets(line, sizeof(line), stdin))
        printf("%d\n", m19_stat_is_kthread(line));
    return 0;
}

static int sweep_mode(char **argv)
{
    snprintf(proc_dir, sizeof(proc_dir), "%s", argv[2]);
    record_fd = 1;
    struct m19_handoff h = {.proc = proc_dir, .keep_root = getenv("M19_KEEP_ROOT"), .self = (pid_t)atoi(argv[3]), .signal = fake_signal};
    int count = m19_sweep(&h, atoi(argv[4]));
    printf("count %d\n", count);
    return 0;
}

static int handoff_mode(char **argv)
{
    /* proc newroot android kmsg tty record */
    snprintf(proc_dir, sizeof(proc_dir), "%s", argv[2]);
    snprintf(newroot_dir, sizeof(newroot_dir), "%s", argv[3]);
    record_fd = open(argv[7], O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    int tty = m19_wire_open(argv[6]);
    if (record_fd < 0 || tty < 0)
        return 2;
    struct m19_handoff h = {.proc = proc_dir, .kmsg = argv[5], .android = argv[4], .newroot = newroot_dir, .init = "/usr/lib/systemd/systemd",
                            .keep_root = getenv("M19_KEEP_ROOT"),
                            .self = getpid(), .settle_ms = 300, .poll_ms = 5, .pace_ms = 1, .signal = fake_signal};
    int moved = -1;
    int rc = m19_handoff(tty, &h, &moved);
    record("returned %d moved %d", rc, moved);
    return 0;
}

static int report_mode(char **argv)
{
    static char paths[12][4200];
    const char *root = argv[2];
    const char *names[] = {"test/kmsg", "proc1-exe", "block", "mountinfo", "test/systemctl", "test/journalctl", "test/analyze", "test/display"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        snprintf(paths[i], sizeof(paths[i]), "%s/%s", root, names[i]);
    struct m19_report c = {.tty = argv[3], .kmsg = paths[0], .proc1_exe = paths[1], .block = paths[2], .mountinfo = paths[3],
                           .systemctl = paths[4], .journalctl = paths[5], .analyze = paths[6], .display = paths[7],
                           .expected_init = "/usr/lib/systemd/systemd", .settle_ms = (unsigned)strtoul(argv[4], NULL, 10), .poll_ms = 5,
                           .beat_ms = 40, .pace_ms = 1, .log_ms = 20000, .command_ms = (unsigned)strtoul(argv[5], NULL, 10),
                           .final_ms = 1, .tty_wait_ms = 200};
    /* R5a/R5b's PID 1 reads the sound card and, when configured, runs the one-shot speaker gate. */
    static char audio[4][4200], speaker[7][4200];
    const char *audio_names[] = {"asound/cards", "asound/pcm", "sound-class", "snd"};
    const char *speaker_names[] = {"proc", "speaker.report", "dev-clean/m11-snd", "dev-clean/m11-heap",
                                   "dev-clean/aud_pasthru_adsp", "dev-clean/msm_audio_ion", "dev-clean/msm_audio_ion_cma"};
    for (unsigned i = 0; i < 4; i++)
        snprintf(audio[i], sizeof(audio[i]), "%s/%s", root, audio_names[i]);
    for (unsigned i = 0; i < 7; i++)
        snprintf(speaker[i], sizeof(speaker[i]), "%s/%s", root, speaker_names[i]);
    if (getenv("M19_TEST_AUDIO")) {
        c.audio = 1;
        c.asound_cards = audio[0];
        c.asound_pcm = audio[1];
        c.sound_class = audio[2];
        c.snd_dev = audio[3];
        c.audio_card = "ukee-mtp-snd-card";
    }
    if (getenv("M19_TEST_SPEAKER")) {
        c.proc = speaker[0];
        c.speaker_ms = 250;
        c.speaker_unit = "marble-speaker.service";
        c.speaker_report = speaker[1];
        for (unsigned i = 0; i < 5; i++)
            c.speaker_clean[i] = speaker[2 + i];
    }
    /* R6: the sound server's T12-audio on fakes of pactl and pacat, and T12-wifi on fakes of nmcli and getent. */
    static char sink[6][4200], wifi[7][4200];
    static const char *pulse[] = {"M19_TEST_PULSE=1", NULL};
    const char *sink_names[] = {"sink.report", "sink.status", "test/pactl", "test/pacat", "sink-tone.raw", "proc"};
    const char *wifi_names[] = {"wifi.result", "wifi.report", "test/nmcli", "test/getent", "route", "profile", "unused"};
    for (unsigned i = 0; i < 6; i++)
        snprintf(sink[i], sizeof(sink[i]), "%s/%s", root, sink_names[i]);
    for (unsigned i = 0; i < 7; i++)
        snprintf(wifi[i], sizeof(wifi[i]), "%s/%s", root, wifi_names[i]);
    if (getenv("M19_TEST_SINK")) {
        c.proc = sink[5];
        for (unsigned i = 0; i < 5; i++)
            c.speaker_clean[i] = speaker[2 + i];
        c.sink_unit = "marble-sink.service";
        c.sink_report = sink[0];
        c.sink_status = sink[1];
        c.pactl = sink[2];
        c.pacat = sink[3];
        c.tone_path = sink[4];
        c.sink_name = "marble_speaker";
        c.pulse_env = pulse;
        c.sink_ms = 1500;
        c.tone_ms = 3000;
        c.idle_wait_ms = 1500;
        c.pulse_unit = "marble-pulse.service";
        c.held_dir = speaker[2];
        c.held_uid = getenv("M19_TEST_HELD_UID") ? (unsigned)strtoul(getenv("M19_TEST_HELD_UID"), NULL, 10) : (unsigned)getuid();
    }
    if (getenv("M19_TEST_WIFI")) {
        c.wifi = 1;
        c.wifi_ms = (unsigned)strtoul(getenv("M19_TEST_WIFI"), NULL, 10);
        c.wifi_result = wifi[0];
        c.wifi_report = wifi[1];
        c.nmcli = wifi[2];
        c.getent = wifi[3];
        c.route = wifi[4];
        c.nm_profile = wifi[5];
        c.dns_name = "example.invalid";
    }
    /* R7: T12-ce on a keypad result written by the test, and a fake /data/media/0. */
    static char ce[2][4200];
    snprintf(ce[0], sizeof(ce[0]), "%s/ce.result", root);
    snprintf(ce[1], sizeof(ce[1]), "%s/android0", root);
    if (getenv("M19_TEST_CE")) {
        c.ce = 1;
        c.ce_ms = (unsigned)strtoul(getenv("M19_TEST_CE"), NULL, 10);
        c.ce_unit = "marble-ce.service";
        c.ce_result = ce[0];
        c.ce_android = ce[1];
        c.ce_entry = "Android";
    }
    return m19_report_main(&c);
}

static int report_desktop_mode(char **argv)
{
    /* root tty settle_ms command_ms touch_ms */
    static char paths[24][4200];
    const char *root = argv[2];
    const char *names[] = {"test/kmsg", "proc1-exe", "block", "mountinfo", "test/systemctl", "test/journalctl", "test/analyze", "test/display",
                           "test/xdpyinfo", "test/xrandr", "test/xinput", "test/ps", "proc", "interrupts", "card", "xorg0.log", "xorg60.log",
                           "guard-tripped", "battery-temp", "thermal"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        snprintf(paths[i], sizeof(paths[i]), "%s/%s", root, names[i]);
    struct m19_report c = {.tty = argv[3], .kmsg = paths[0], .proc1_exe = paths[1], .block = paths[2], .mountinfo = paths[3],
                           .systemctl = paths[4], .journalctl = paths[5], .analyze = paths[6], .display = paths[7],
                           .expected_init = "/usr/lib/systemd/systemd", .settle_ms = (unsigned)strtoul(argv[4], NULL, 10), .poll_ms = 5,
                           .beat_ms = 40, .pace_ms = 1, .log_ms = 20000, .command_ms = (unsigned)strtoul(argv[5], NULL, 10),
                           .final_ms = 1, .tty_wait_ms = 200, .desktop = 1, .x_wait_ms = 400, .session_wait_ms = 400,
                           .touch_ms = (unsigned)strtoul(argv[6], NULL, 10), .want_hz = 120.0, .xdpyinfo = paths[8], .xrandr = paths[9],
                           .xinput = paths[10], .ps = paths[11], .proc = paths[12], .interrupts = paths[13], .card = paths[14],
                           .touch_name = "goodix_ts", .xorg_logs = {paths[15], paths[16]}, .guard_unit = "m19-r3-guard.service",
                           .guard_marker = paths[17], .battery_temp = paths[18], .thermal = paths[19]};
    /* R6: the turned desktop. */
    c.rotation = getenv("M19_TEST_ROTATION");
    return m19_report_main(&c);
}

/* R4's GPU phase on the desktop's fakes. The variables are pid4.c's, so the fakes can check they arrive. */
#define TEST_VK_ICD "VK_DRIVER_FILES=/usr/share/vulkan/icd.d/freedreno_icd.aarch64.json"
static const char *const test_dri3_env[] = {"MESA_LOADER_DRIVER_OVERRIDE=kgsl", "FD_FORCE_KGSL=1", "FD_KGSL_ENABLE_DMABUF=1", TEST_VK_ICD, NULL};
static const char *const test_copy_env[] = {TEST_VK_ICD, "MESA_VK_WSI_DEBUG=sw", "MESA_LOADER_DRIVER_OVERRIDE=zink", "LIBGL_KOPPER_DRI2=1", NULL};
static const char *const test_soft_env[] = {"LIBGL_ALWAYS_SOFTWARE=1", NULL};
static const struct m19_show test_shows[] = {{"dri3", test_dri3_env}, {"copy", test_copy_env}, {"soft", test_soft_env}};

static int report_gpu_mode(char **argv)
{
    /* root tty settle_ms command_ms touch_ms gears_ms */
    static char paths[33][4200];
    const char *root = argv[2];
    const char *names[] = {"test/kmsg", "proc1-exe", "block", "mountinfo", "test/systemctl", "test/journalctl", "test/analyze", "test/display",
                           "test/xdpyinfo", "test/xrandr", "test/xinput", "test/ps", "proc", "interrupts", "card", "xorg0.log", "xorg60.log",
                           "guard-tripped", "battery-temp", "thermal", "kgsl-node", "gpu-model", "test/gpu-probe", "test/vulkaninfo",
                           "test/vkcube", "test/glxinfo", "test/glxgears", "test/eglinfo", "gpu-profile", "test/glmark2", "test/present-probe",
                           "test/gpu-compositor", "heap"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        snprintf(paths[i], sizeof(paths[i]), "%s/%s", root, names[i]);
    struct m19_report c = {.tty = argv[3], .kmsg = paths[0], .proc1_exe = paths[1], .block = paths[2], .mountinfo = paths[3],
                           .systemctl = paths[4], .journalctl = paths[5], .analyze = paths[6], .display = paths[7],
                           .expected_init = "/usr/lib/systemd/systemd", .settle_ms = (unsigned)strtoul(argv[4], NULL, 10), .poll_ms = 5,
                           .beat_ms = 40, .pace_ms = 1, .log_ms = 20000, .command_ms = (unsigned)strtoul(argv[5], NULL, 10),
                           .final_ms = 1, .tty_wait_ms = 200, .desktop = 1, .x_wait_ms = 400, .session_wait_ms = 400,
                           .touch_ms = (unsigned)strtoul(argv[6], NULL, 10), .want_hz = 120.0, .xdpyinfo = paths[8], .xrandr = paths[9],
                           .xinput = paths[10], .ps = paths[11], .proc = paths[12], .interrupts = paths[13], .card = paths[14],
                           .touch_name = "goodix_ts", .xorg_logs = {paths[15], paths[16]}, .guard_unit = "m19-r3-guard.service",
                           .guard_marker = paths[17], .battery_temp = paths[18], .thermal = paths[19], .gpu = 1, .gpu_ms = 5000,
                           .gears_ms = (unsigned)strtoul(argv[7], NULL, 10), .cube_frames = 300, .kgsl_node = paths[20],
                           .kgsl_model = paths[21], .gpu_probe = paths[22], .vulkaninfo = paths[23], .vkcube = paths[24], .glxinfo = paths[25],
                           .glxgears = paths[26], .eglinfo = paths[27], .vk_env = test_dri3_env, .gl_env = test_dri3_env,
                           .egl_env = test_dri3_env, .glamor = 1, .xorg_unit = "marble-xorg.service", .gpu_profile = paths[28],
                           .glmark2 = paths[29], .copy_env = test_copy_env, .present_probe = paths[30], .present_frames = 120,
                           .shell = "/bin/sh", .compositor_script = paths[31], .vblank_frames = 120, .crtc_samples = 50, .compose_ms = 500,
                           .judge_copy = 1, .shows = test_shows, .show_count = 3, .show_seconds = 0, .dmabuf_heap = paths[32],
                           .dmabuf_env = test_dri3_env};
    /* R4h's PID 1 runs without the compositor views. */
    if (getenv("M19_TEST_NO_VIEWS"))
        c.compositor_script = NULL;
    /* R4o's PID 1 judges DRI3. */
    c.judge_dri3 = getenv("M19_TEST_JUDGE_DRI3") != NULL;
    return m19_report_main(&c);
}

static int guard_mode(char **argv)
{
    /* root session_ms run_ms busy_ms */
    static char paths[8][4200];
    const char *root = argv[2];
    const char *names[] = {"battery-temp", "thermal", "stat", "test/kmsg", "test/systemctl", "test/display", "guard-tripped"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        snprintf(paths[i], sizeof(paths[i]), "%s/%s", root, names[i]);
    struct m19_guard g = {.battery_temp = paths[0], .thermal = paths[1], .stat = paths[2], .kmsg = paths[3], .systemctl = paths[4],
                          .display = paths[5], .marker = paths[6],
                          .units = {"marble-xfce.service", "marble-xorg.service", "marble-xorg-fallback.service"}, .period_ms = 10,
                          .note_ms = 50, .busy_limit = 90, .busy_ms = (unsigned)strtoul(argv[5], NULL, 10),
                          .session_ms = (unsigned)strtoul(argv[3], NULL, 10), .run_ms = (unsigned)strtoul(argv[4], NULL, 10),
                          .command_ms = 5000, .final_ms = 1, .battery_limit = 420, .zone_limit = 80000};
    return m19_guard_main(&g);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && !strcmp(argv[1], "kthread"))
        return kthread_mode();
    if (argc == 5 && !strcmp(argv[1], "sweep"))
        return sweep_mode(argv);
    if (argc == 8 && !strcmp(argv[1], "handoff"))
        return handoff_mode(argv);
    if (argc == 6 && !strcmp(argv[1], "report"))
        return report_mode(argv);
    if (argc == 7 && !strcmp(argv[1], "report-desktop"))
        return report_desktop_mode(argv);
    if (argc == 8 && !strcmp(argv[1], "report-gpu"))
        return report_gpu_mode(argv);
    if (argc == 6 && !strcmp(argv[1], "guard"))
        return guard_mode(argv);
    return 64;
}
