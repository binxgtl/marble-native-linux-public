/* M19 R2: R1's proven steps, then PID 1 hands the phone to systemd on the read-only Ubuntu root.
 * The same binary, copied into the new root's /run, is the evidence reporter that systemd starts. */
#ifndef M19_R2_H
#define M19_R2_H

#include <stddef.h>
#include <sys/types.h>

#include "../run1/r1.h"

/* Paced writes on the USB serial line, as R1 sends them. */
unsigned long long m19_now_ms(void);
int m19_wire_open(const char *tty);
int m19_wire_put(int fd, const void *data, size_t size, unsigned pace_ms, unsigned long long end_ms);
int m19_wire_line(int fd, unsigned pace_ms, const char *format, ...) __attribute__((format(printf, 3, 4)));

struct m19_handoff {
    const char *proc;    /* "/proc" */
    const char *kmsg;    /* "/dev/kmsg" */
    const char *android; /* "/tee": the Android chroot, detached once nothing runs in it */
    const char *newroot; /* "/newroot", built by T9 */
    const char *init;    /* "/usr/lib/systemd/systemd", inside the new root */
    /* R7: when set (to android), the TEE island outlives the hand-off. Processes whose root is this directory are
     * neither signalled nor counted, and it is not detached: a lazy unmount would cut its submounts away from the
     * services inside it. NULL keeps R2 to R6's behaviour. */
    const char *keep_root;
    pid_t self;          /* never signalled, besides PID 1 */
    unsigned settle_ms, poll_ms, pace_ms;
    int (*signal)(pid_t, int); /* kill(2) in production */
};

/* 1 for a kernel thread, 0 for a user process, -1 when the stat line cannot be read. */
int m19_stat_is_kthread(const char *line);
/* Counts user processes other than PID 1 and self, and sends each SIGKILL when kill_them is set.
 * Kernel threads are never counted or signalled. An unreadable entry is counted. */
int m19_sweep(const struct m19_handoff *h, int kill_them);
/* Does not return on success: systemd is PID 1. On failure it returns -1 and sets *moved when
 * the root had already changed, so the caller knows which display binary is reachable. */
int m19_handoff(int tty_fd, const struct m19_handoff *h, int *moved);

/* R4i: one way a program's frames reach the X server, as the environment that selects it. */
struct m19_show {
    const char *name;
    const char *const *env;
};

struct m19_report {
    const char *tty, *kmsg, *proc1_exe, *block, *mountinfo, *systemctl, *journalctl, *analyze, *display, *expected_init;
    unsigned settle_ms, poll_ms, beat_ms, pace_ms, log_ms, command_ms, final_ms, tty_wait_ms;
    /* R3 only, when desktop is set: Xorg and XFCE, the refresh rate and a touch window. */
    unsigned desktop, x_wait_ms, session_wait_ms, touch_ms;
    double want_hz;
    const char *xdpyinfo, *xrandr, *xinput, *ps, *proc, *interrupts, *card, *touch_name, *xorg_logs[2];
    const char *guard_unit, *guard_marker, *battery_temp, *thermal;
    /* R4 only, when gpu is set: the Adreno through the tree's own Mesa on KGSL. Each tool gets its
     * environment added in its own process; the reporter's environment never changes. */
    unsigned gpu, gpu_ms, gears_ms, cube_frames;
    const char *kgsl_node, *kgsl_model, *gpu_probe, *vulkaninfo, *vkcube, *glxinfo, *glxgears, *eglinfo;
    const char *const *vk_env, *const *gl_env, *const *egl_env;
    /* R4b: Xorg on the GPU. glamor's log lines, its unit, the profile the session chose, glmark2, and
     * GL through the copy profile for comparison. */
    unsigned glamor;
    const char *xorg_unit, *gpu_profile, *glmark2;
    const char *const *copy_env;
    /* R4c: page flips. The Present probe measures copies into a window and flips of a window covering
     * the screen, present_frames each; glxgears also runs fullscreen. */
    const char *present_probe;
    unsigned present_frames;
    /* R4e: the desktop starts as the tree's xfwm4 settings leave it. With compositor_script set, the reporter
     * reads the kernel's vblanks on card (vblank_frames waits and events), then views the screen three times:
     * as the session left it, with R4d's compositor on, and with compositing off. Each view samples the CRTC's
     * framebuffer crtc_samples times and reads the root window. The compositor gets compose_ms to come or go. */
    const char *shell, *compositor_script;
    unsigned vblank_frames, crtc_samples, compose_ms;
    /* R4h: the probe's windowed copy must take one vblank a frame (R4g's whole-rate Present). */
    unsigned judge_copy;
    /* R4i: what glxgears covering the screen shows through each path: the screen is read show_seconds after it
     * starts, with the path's environment added in the shell that runs both. */
    const struct m19_show *shows;
    unsigned show_count, show_seconds;
    /* R4j: which side loses a program's frame. The probe reads back a dma-buf from dmabuf_heap that the CPU filled
     * and the X server imported; one the GPU wrote, run with dmabuf_env; and the two together. */
    const char *dmabuf_heap;
    const char *const *dmabuf_env;
    /* R4o: DRI3 judged, now that it shows (R4n): every screen-reading path must show, and a write after the import,
     * by the CPU and by the GPU, must reach the X server whole. */
    unsigned judge_dri3;
    /* R5a/R5b, when audio is set: the card M11 Run12 registered, read from procfs and sysfs, and no sound node
     * in /dev/snd. When speaker_unit is also set (R5b), T12-audio starts the one-shot Run31 speaker holder once,
     * waits for speaker_report, and verifies the live retaining holder in proc and absence of speaker_clean. */
    unsigned audio, speaker_ms;
    const char *asound_cards, *asound_pcm, *sound_class, *snd_dev, *audio_card;
    const char *speaker_unit, *speaker_report, *speaker_clean[5];
    /* R6, when sink_unit is set: T12-audio starts the desktop sound server's speaker end once, waits for its chord and
     * the switch to the stream (sink_report), then plays tone_path through PulseAudio (pulse_env reaches the session's
     * server) and reads the stream's counters (sink_status): the tone must reach the speaker no louder than -10 dBFS,
     * the amplifier on for it and off again after the silence. */
    const char *sink_unit, *sink_report, *sink_status, *pactl, *pacat, *sink_name, *tone_path;
    const char *const *pulse_env;
    unsigned sink_ms, tone_ms, idle_wait_ms;
    /* R6b: PulseAudio is the reporter's to start (pulse_unit), once the sink streams: the tree's autostart entry is
     * for systemd user sessions, which this root session lacks (R6a). While the sink streams, Run31's private
     * directory (held_dir, one of speaker_clean) stays, empty and 0700, owned by held_uid; every other path must be
     * absent. */
    const char *pulse_unit, *held_dir;
    unsigned held_uid;
    /* R6, when wifi is set: T12-wifi waits up to wifi_ms for m19-wifi's result and NetworkManager's connection, then
     * checks the default route and pings its gateway. DNS is recorded, not judged. The report is sent with the
     * profile's SSID, MAC and IPv4 addresses blanked. */
    unsigned wifi, wifi_ms;
    const char *wifi_result, *wifi_report, *nmcli, *getent, *route, *nm_profile, *dns_name;
    /* R6, when rotation is set: xrandr's first connected output must be turned so, the screen wider than tall. */
    const char *rotation;
    /* R7, when ce is set: T12-ce starts ce_unit (the keypad) once and waits up to ce_ms for the keypad to record the
     * broker's status in ce_result. Judged by that status and by Android's own storage: in ce_android the entry
     * ce_entry has its real name only once the CE key is added. Counts only; no entry name is printed. */
    unsigned ce, ce_ms;
    const char *ce_unit, *ce_result, *ce_android, *ce_entry;
    /* R8, when data_rw is set (docs/m19-r8.md): /data is read-write and / is the tree on it. Only the partition named
     * data_part (PARTNAME in its uevent) and the dm device named data_dm may be writable and written; the disk holding
     * that partition may count its writes, read-only itself, and every other partition on it must count none. Every
     * other disk, partition and dm device stays read-only and unwritten, and no discard counts on the data path. / must
     * be the f2fs root, read-write; every other mount of a disk filesystem is read-only at the mount. */
    unsigned data_rw;
    const char *data_dm, *data_part;
    /* R8, when persist_path is set: T12-persist writes this boot's id (read from boot_id) there through a temporary
     * name, each step synced, reads it back, and checks the directory's filesystem is persist_fs (statfs's f_type).
     * Android's check after the run reads the same file from /data. The reporter's only write. */
    const char *persist_path, *boot_id;
    unsigned long persist_fs;
    /* R8, when upower is set: T12-battery. battery_unit must be active (the session started it), upower must show
     * upower_device at the percentage battery_dir/capacity holds, within two points, in a known state, and the power
     * manager (battery_pm, its comm) must run. */
    const char *upower, *upower_device, *battery_unit, *battery_dir, *battery_pm;
    /* R8, when media_view is set: T12-media, after T12-ce. media_view must be a read-only mount listing as many entries as
     * ce_android, and the first JPEG or PNG a bounded walk meets (media_walk entries, media_depth levels) must start with
     * its format's bytes: names and contents both decrypt. Counts and the format only; no name is printed. */
    const char *media_view;
    unsigned media_walk, media_depth;
};

/* R3's guard, a service of its own beside the desktop. It stops the desktop units and paints YELLOW
 * when the battery or any thermal zone runs hot, when the CPU stays busy, or when the session runs
 * long. It reads sensors and /proc only; its one action is stopping the desktop. */
struct m19_guard {
    const char *battery_temp, *thermal, *stat, *kmsg, *systemctl, *display, *marker, *units[3];
    unsigned period_ms, note_ms, busy_limit, busy_ms, session_ms, run_ms, command_ms, final_ms;
    long battery_limit; /* tenths of a degree, as power_supply reports */
    long zone_limit;    /* thousandths of a degree, as thermal zones report */
};

int m19_guard_main(const struct m19_guard *g);

/* Rate of vertical blanks on the first CRTC that answers, from the kernel's own timestamps. */
int m19_vblank_rate(const char *card, double *hz);

/* Runs under systemd, never as PID 1. Waits for the boot to settle, sends the evidence, then
 * execs the display: GREEN when every check passed, YELLOW otherwise. */
int m19_report_main(const struct m19_report *c);

#endif
