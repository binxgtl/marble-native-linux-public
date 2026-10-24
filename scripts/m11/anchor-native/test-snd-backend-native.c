/* P5 W3: snd_backend_native against fixture syscalls (no ALSA device): node discipline, controls by item name
 * with read-back, the AGM/tinyalsa HW_PARAMS and SW_PARAMS layout, and every refusal. test.sh mutants name the
 * assertion that must fail. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-snd-backend-native.c builds only in the M11_CUSTODIAN_NATIVE mode"
#endif
#define _GNU_SOURCE
#include "snd_backend_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/ioctl.h> /* _IO/_IOR/_IOW/_IOWR for the asound.h request numbers */
#include <sound/asound.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define MAXN 16
static struct { char path[160]; dev_t rdev; int live; } nodes[MAXN];
static struct { int fd; dev_t rdev; int open; } fds[MAXN];
static int next_fd, dir_live, mkdir_errno, open_rdev_skew, ignore_write, refine_period, ctl_type_int, dup_name;
static unsigned closes, unlinks, hw_calls, sw_calls, prepares, drops;
static struct snd_pcm_hw_params last_hw;
static struct snd_pcm_sw_params last_sw;
static const char *proc_text, *dev_rx, *dev_tx, *dev_ctl;

#define ELEMS 4
static const char *elem_names[ELEMS] = {"aw_dev_0_switch", "aw_dev_1_switch", "aw_dev_0_prof", "aw_dev_1_prof"};
static const char *switch_items[] = {"Disable", "Enable"};
static const char *prof_items[] = {"Music", "Voice", "Receiver"};
static unsigned elem_value[ELEMS];

static const char PROC_OK[] =
    "00-31: TDM-LPAIF-RX-TERTIARY multicodec-31 :  : playback 1\n"
    "00-32: TDM-LPAIF-RX-TERTIARY-VIRT-2 multicodec-32 :  : playback 1\n"
    "00-33: TDM-LPAIF-TX-TERTIARY multicodec-33 :  : capture 1\n";

static int fx_read_text(const char *p, char *buf, size_t cap) {
    const char *src = NULL;
    if (!strcmp(p, "/proc/asound/pcm")) src = proc_text;
    else if (!strcmp(p, "/sys/class/sound/pcmC0D32p/dev")) src = dev_rx;
    else if (!strcmp(p, "/sys/class/sound/pcmC0D33c/dev")) src = dev_tx;
    else if (!strcmp(p, "/sys/class/sound/controlC0/dev")) src = dev_ctl;
    if (!src) return -ENOENT;
    size_t n = strlen(src);
    if (n + 1 > cap) return -EFBIG;
    memcpy(buf, src, n + 1);
    return (int)n;
}
static ssize_t fx_read_text_s(const char *p, char *buf, size_t cap) { return fx_read_text(p, buf, cap); }
static int fx_mkdir(const char *p, mode_t m) {
    (void)p; assert(m == 0700);
    if (mkdir_errno) return -mkdir_errno;
    if (dir_live) return -EEXIST;
    dir_live = 1;
    return 0;
}
static int fx_rmdir(const char *p) { (void)p; if (!dir_live) return -ENOENT; dir_live = 0; return 0; }
static int fx_mknod(const char *p, mode_t m, dev_t d) {
    assert(m == (S_IFCHR | 0600) && dir_live && !strncmp(p, "/dev/m11-snd/", 13));
    for (int i = 0; i < MAXN; i++) if (!nodes[i].live) {
        snprintf(nodes[i].path, sizeof nodes[i].path, "%s", p); nodes[i].rdev = d; nodes[i].live = 1; return 0;
    }
    return -ENOSPC;
}
static int fx_unlink(const char *p) {
    for (int i = 0; i < MAXN; i++) if (nodes[i].live && !strcmp(nodes[i].path, p)) { nodes[i].live = 0; unlinks++; return 0; }
    return -ENOENT;
}
static int fx_open(const char *p, int flags) {
    assert(flags & O_CLOEXEC); assert(flags & O_NOFOLLOW);
    for (int i = 0; i < MAXN; i++) if (nodes[i].live && !strcmp(nodes[i].path, p)) {
        for (int k = 0; k < MAXN; k++) if (!fds[k].open) {
            fds[k].fd = 100 + next_fd++; fds[k].rdev = nodes[i].rdev + (dev_t)open_rdev_skew; fds[k].open = 1;
            return fds[k].fd;
        }
    }
    return -ENOENT;
}
static int slot_of(int fd) { for (int k = 0; k < MAXN; k++) if (fds[k].open && fds[k].fd == fd) return k; return -1; }
static int fx_fstat(int fd, struct stat *st) {
    int k = slot_of(fd);
    if (k < 0) return -EBADF;
    memset(st, 0, sizeof *st); st->st_mode = S_IFCHR | 0600; st->st_rdev = fds[k].rdev;
    return 0;
}
static int fx_close(int fd) { int k = slot_of(fd); if (k < 0) return -EBADF; fds[k].open = 0; closes++; return 0; }
static int is_ctl(int fd) { int k = slot_of(fd); return k >= 0 && minor(fds[k].rdev) == 1; }

static int fx_ioctl(int fd, unsigned long req, void *arg) {
    if (slot_of(fd) < 0) return -EBADF;
    if (is_ctl(fd)) {
        if (req == SNDRV_CTL_IOCTL_ELEM_LIST) {
            struct snd_ctl_elem_list *l = arg;
            unsigned n = ELEMS + (dup_name ? 1 : 0);
            l->count = n;
            if (l->space) {
                unsigned used = l->space < n ? l->space : n;
                for (unsigned i = 0; i < used; i++) {
                    memset(&l->pids[i], 0, sizeof l->pids[i]);
                    l->pids[i].numid = i + 1; l->pids[i].iface = SNDRV_CTL_ELEM_IFACE_MIXER;
                    snprintf((char *)l->pids[i].name, sizeof l->pids[i].name, "%s", elem_names[i < ELEMS ? i : 0]);
                }
                l->used = used;
            }
            return 0;
        }
        if (req == SNDRV_CTL_IOCTL_ELEM_INFO) {
            struct snd_ctl_elem_info *in = arg;
            unsigned e = in->id.numid - 1;
            if (e >= ELEMS) return -ENOENT;
            const char **names = e < 2 ? switch_items : prof_items;
            unsigned items = e < 2 ? 2 : 3;
            in->type = ctl_type_int ? SNDRV_CTL_ELEM_TYPE_INTEGER : SNDRV_CTL_ELEM_TYPE_ENUMERATED;
            in->count = 1;
            unsigned want = in->value.enumerated.item;
            in->value.enumerated.items = items;
            if (want < items) snprintf(in->value.enumerated.name, sizeof in->value.enumerated.name, "%s", names[want]);
            return 0;
        }
        if (req == SNDRV_CTL_IOCTL_ELEM_WRITE) {
            struct snd_ctl_elem_value *v = arg;
            unsigned e = v->id.numid - 1;
            if (e >= ELEMS) return -ENOENT;
            if (!ignore_write) elem_value[e] = v->value.enumerated.item[0];
            return 0;
        }
        if (req == SNDRV_CTL_IOCTL_ELEM_READ) {
            struct snd_ctl_elem_value *v = arg;
            unsigned e = v->id.numid - 1;
            if (e >= ELEMS) return -ENOENT;
            v->value.enumerated.item[0] = elem_value[e];
            return 0;
        }
        return -ENOTTY;
    }
    if (req == SNDRV_PCM_IOCTL_HW_PARAMS) {
        struct snd_pcm_hw_params *h = arg;
        hw_calls++;
        last_hw = *h;
        /* the kernel's choose step: every interval collapses to its minimum */
        for (int n = SNDRV_PCM_HW_PARAM_FIRST_INTERVAL; n <= SNDRV_PCM_HW_PARAM_LAST_INTERVAL; n++) {
            struct snd_interval *i = &h->intervals[n - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL];
            i->max = i->min;
            i->integer = 1;
        }
        if (refine_period) {
            struct snd_interval *i = &h->intervals[SNDRV_PCM_HW_PARAM_PERIOD_SIZE - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL];
            i->min += 1;
            i->max = i->min;
        }
        return 0;
    }
    if (req == SNDRV_PCM_IOCTL_SW_PARAMS) { sw_calls++; last_sw = *(struct snd_pcm_sw_params *)arg; return 0; }
    if (req == SNDRV_PCM_IOCTL_PREPARE) { prepares++; return 0; }
    if (req == SNDRV_PCM_IOCTL_DROP) { drops++; return 0; }
    return -ENOTTY;
}

static const m11_snd_sys fx = {fx_open, fx_fstat, fx_close, fx_ioctl, fx_mknod, fx_unlink, fx_mkdir, fx_rmdir, fx_read_text_s};

static void reset(void) {
    memset(nodes, 0, sizeof nodes); memset(fds, 0, sizeof fds); memset(elem_value, 0, sizeof elem_value);
    next_fd = dir_live = mkdir_errno = open_rdev_skew = ignore_write = refine_period = ctl_type_int = dup_name = 0;
    closes = unlinks = hw_calls = sw_calls = prepares = drops = 0;
    proc_text = PROC_OK; dev_rx = "116:34\n"; dev_tx = "116:35\n"; dev_ctl = "116:1\n";
}
static int live_nodes(void) { int n = 0; for (int i = 0; i < MAXN; i++) n += nodes[i].live; return n; }
static int open_fds(void) { int n = 0; for (int i = 0; i < MAXN; i++) n += fds[i].open; return n; }

static int prep(m11_snd_backend *b) {
    m11_snd_paths p = m11_snd_paths_default();
    return m11_snd_prepare(b, &fx, &p, "TDM-LPAIF-RX-TERTIARY-VIRT-2", "TDM-LPAIF-TX-TERTIARY");
}

static int full_mask(const struct snd_pcm_hw_params *h, int n) {
    const struct snd_mask *m = &h->masks[n - SNDRV_PCM_HW_PARAM_FIRST_MASK];
    return m->bits[0] == ~0u && m->bits[1] == ~0u && !m->bits[2];
}

/* Root-only, isolated Linux mount regression. No ALSA device or ioctl is used:
 * every character node is /dev/null (1:3), only metadata is fixture supplied.
 * Real VFS opens must reject the frozen Run26 path on nodev /run, then accept
 * the production default on /dev. A namespace/mount failure is a test failure,
 * never a silent skip in CI. Mounts disappear on process exit. */
static int mt_open(const char *p, int f) { int n = open(p, f); return n < 0 ? -errno : n; }
static int mt_stat(int fd, struct stat *st) { return fstat(fd, st) ? -errno : 0; }
static int mt_close(int fd) { return close(fd) ? -errno : 0; }
static int mt_ioctl(int fd, unsigned long req, void *arg) {
    (void)fd; (void)req; (void)arg;
    return -ENOTTY; /* no ioctl reaches a device; backend must preserve this error */
}
static int mt_node(const char *p, mode_t m, dev_t d) { return mknod(p, m, d) ? -errno : 0; }
static int mt_unlink(const char *p) { return unlink(p) ? -errno : 0; }
static int mt_mkdir(const char *p, mode_t m) { return mkdir(p, m) ? -errno : 0; }
static int mt_rmdir(const char *p) { return rmdir(p) ? -errno : 0; }

static int mount_contract(void) {
    assert(geteuid() == 0);
    assert(unshare(CLONE_NEWNS) == 0);
    assert(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0);
    assert(mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755,size=1m") == 0);
    assert(mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=1m") == 0);
    assert(mkdir("/run/m11", 0700) == 0);
    struct statvfs fs;
    assert(statvfs("/run", &fs) == 0 && (fs.f_flag & ST_NODEV));
    assert(statvfs("/dev", &fs) == 0 && !(fs.f_flag & ST_NODEV));
    reset();
    dev_rx = dev_tx = dev_ctl = "1:3\n";
    const m11_snd_sys real_vfs = {mt_open, mt_stat, mt_close, mt_ioctl, mt_node, mt_unlink,
                                 mt_mkdir, mt_rmdir, fx_read_text_s};
    m11_snd_backend b;
    m11_snd_paths p = m11_snd_paths_default();
    p.dir = "/run/m11/snd"; /* immutable Run26 behavior, not the repaired default */
    assert(m11_snd_prepare(&b, &real_vfs, &p, "TDM-LPAIF-RX-TERTIARY-VIRT-2", "TDM-LPAIF-TX-TERTIARY") == -EACCES);
    assert(b.ctl_fd == -1 && !b.dir_made);
    struct stat st;
    assert(lstat(p.dir, &st) == -1 && errno == ENOENT);
    puts("PASS real VFS: frozen Run26 nodev /run returns EACCES at control open; no node, directory or fd left");

    p = m11_snd_paths_default();
    assert(!strcmp(p.dir, "/dev/m11-snd"));
    assert(m11_snd_prepare(&b, &real_vfs, &p, "TDM-LPAIF-RX-TERTIARY-VIRT-2", "TDM-LPAIF-TX-TERTIARY") == 0);
    assert(b.ctl_fd >= 0 && b.dir_made);
    assert(stat(p.dir, &st) == 0 && (st.st_mode & 0777) == 0700 && st.st_uid == 0);
    char ctl[160];
    assert(snprintf(ctl, sizeof ctl, "%s/control", p.dir) > 0);
    assert(lstat(ctl, &st) == -1 && errno == ENOENT); /* unlinked after open */
    for (int i = 0; i < 2; i++) {
        assert(lstat(b.pcm[i].node, &st) == 0 && S_ISCHR(st.st_mode) &&
               (st.st_mode & 0777) == 0600 && st.st_uid == 0 && st.st_rdev == makedev(1, 3));
        /* Real PCM-node open succeeds; the deliberately refused ioctl comes next.
         * No ALSA call is sent; failure closes its fd and removes its node. */
        assert(m11_snd_pcm_open(&b, i, 96000, i ? 2 : 3, SNDRV_PCM_FORMAT_S32_LE,
                               i ? 1024 : 682, 2, 170, INT_MAX) == -ENOTTY);
        assert(b.pcm[i].fd == -1 && !b.pcm[i].node_made);
    }
    m11_snd_release(&b);
    assert(b.ctl_fd == -1 && !b.dir_made);
    assert(lstat(p.dir, &st) == -1 && errno == ENOENT);
    assert(statvfs("/run", &fs) == 0 && (fs.f_flag & ST_NODEV));
    puts("PASS real VFS: production /dev/m11-snd control/PCM opens succeed; 0700/0600 root-only; cleanup complete; /run stays nodev; no ALSA ioctl");
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "--mount-contract")) return mount_contract();
    assert(argc == 1);
    m11_snd_backend b;

    /* prepare: resolve by name, make the private nodes, control open and its entry removed */
    reset();
    assert(prep(&b) == 0);
    assert(b.pcm[0].device == 32 && b.pcm[1].device == 33 && b.ctl_fd >= 0);
    assert(dir_live && live_nodes() == 2 && open_fds() == 1);
    assert(b.pcm[0].rdev == makedev(116, 34) && b.pcm[1].rdev == makedev(116, 35));
    puts("PASS prepare: exact names, playback/capture, MAJ:MIN; private 0700 directory; control opened and its node removed");

    /* controls by item name with read-back */
    char cur[64];
    assert(m11_snd_ctl_get(&b, "aw_dev_0_switch", cur, sizeof cur) == 0 && !strcmp(cur, "Disable"));
    assert(m11_snd_ctl_set(&b, "aw_dev_0_switch", "Enable") == 0 && elem_value[0] == 1);
    assert(m11_snd_ctl_get(&b, "aw_dev_0_switch", cur, sizeof cur) == 0 && !strcmp(cur, "Enable"));
    assert(m11_snd_ctl_set(&b, "aw_dev_1_prof", "Music") == 0 && elem_value[3] == 0);
    assert(m11_snd_ctl_set(&b, "aw_dev_0_switch", "Disable") == 0 && elem_value[0] == 0);
    assert(m11_snd_ctl_set(&b, "aw_dev_0_switch", "On") == -ENOENT);
    assert(m11_snd_ctl_set(&b, "aw_dev_9_switch", "Enable") == -ENOENT);
    ignore_write = 1;
    assert(m11_snd_ctl_set(&b, "aw_dev_1_switch", "Enable") == -EIO);
    ignore_write = 0;
    ctl_type_int = 1;
    assert(m11_snd_ctl_set(&b, "aw_dev_1_switch", "Enable") == -EPROTO);
    ctl_type_int = 0;
    dup_name = 1;
    assert(m11_snd_ctl_set(&b, "aw_dev_0_switch", "Enable") == -EEXIST && elem_value[0] == 0);
    dup_name = 0;
    puts("PASS controls: enumerated item by name, written then read back; unknown item or control, a read-back that differs, a non-enumerated or duplicated control refused");

    /* the AGM device_open of the RX group back end: 96 kHz, 3 ch, S32_LE, period 682 x 2 */
    assert(m11_snd_pcm_open(&b, M11_SND_RX, 96000, 3, SNDRV_PCM_FORMAT_S32_LE, 682, 2, 170, INT_MAX) == 0);
    assert(live_nodes() == 1 && b.pcm[0].fd >= 0 && hw_calls == 1 && sw_calls == 1 && prepares == 0);
    const struct snd_pcm_hw_params *h = &last_hw;
    assert(h->masks[SNDRV_PCM_HW_PARAM_ACCESS - SNDRV_PCM_HW_PARAM_FIRST_MASK].bits[0] == 1u << SNDRV_PCM_ACCESS_RW_INTERLEAVED);
    assert(h->masks[SNDRV_PCM_HW_PARAM_FORMAT - SNDRV_PCM_HW_PARAM_FIRST_MASK].bits[0] == 1u << SNDRV_PCM_FORMAT_S32_LE);
    assert(!h->masks[SNDRV_PCM_HW_PARAM_FORMAT - SNDRV_PCM_HW_PARAM_FIRST_MASK].bits[1]);
    assert(full_mask(h, SNDRV_PCM_HW_PARAM_SUBFORMAT));
    const struct snd_interval *iv = h->intervals;
    const int I0 = SNDRV_PCM_HW_PARAM_FIRST_INTERVAL;
    assert(iv[SNDRV_PCM_HW_PARAM_RATE - I0].min == 96000 && iv[SNDRV_PCM_HW_PARAM_RATE - I0].max == 96000 && iv[SNDRV_PCM_HW_PARAM_RATE - I0].integer);
    assert(iv[SNDRV_PCM_HW_PARAM_CHANNELS - I0].min == 3 && iv[SNDRV_PCM_HW_PARAM_CHANNELS - I0].max == 3);
    assert(iv[SNDRV_PCM_HW_PARAM_PERIODS - I0].min == 2 && iv[SNDRV_PCM_HW_PARAM_PERIODS - I0].max == 2);
    assert(iv[SNDRV_PCM_HW_PARAM_PERIOD_SIZE - I0].min == 682 && iv[SNDRV_PCM_HW_PARAM_PERIOD_SIZE - I0].max == ~0u);
    assert(iv[SNDRV_PCM_HW_PARAM_BUFFER_SIZE - I0].min == 0 && iv[SNDRV_PCM_HW_PARAM_BUFFER_SIZE - I0].max == ~0u);
    assert(h->rmask == ~0u && h->cmask == 0 && h->info == ~0u && h->flags == 0);
    assert(last_sw.tstamp_mode == SNDRV_PCM_TSTAMP_ENABLE && last_sw.period_step == 1 && last_sw.avail_min == 682);
    assert(last_sw.start_threshold == 170 && last_sw.stop_threshold == (unsigned long)INT_MAX && last_sw.xfer_align == 341);
    assert(last_sw.boundary == 1364ul * 1048576ul);
    puts("PASS PCM open: node removed at open; tinyalsa HW_PARAMS (RW_INTERLEAVED, S32_LE, 96000 x 3, 2 periods, period >= 682) and SW_PARAMS (avail 682, start 170, stop INT_MAX, boundary)");
    assert(m11_snd_pcm_open(&b, M11_SND_RX, 96000, 3, SNDRV_PCM_FORMAT_S32_LE, 682, 2, 170, INT_MAX) == -EALREADY);
    assert(m11_snd_pcm_prepare(&b, M11_SND_RX) == 0 && prepares == 1 && b.pcm[0].prepared);
    assert(m11_snd_pcm_prepare(&b, M11_SND_TX) == -EBADF);
    assert(m11_snd_pcm_open(&b, M11_SND_TX, 96000, 2, SNDRV_PCM_FORMAT_S32_LE, 1024, 2, 256, INT_MAX) == 0);
    assert(live_nodes() == 0 && dir_live);
    assert(m11_snd_pcm_close(&b, M11_SND_RX) == 0 && drops == 1 && b.pcm[0].fd == -1);
    m11_snd_release(&b);
    assert(!dir_live && open_fds() == 0 && drops == 2);
    puts("PASS prepare is separate and once-open; close is DROP then close; release leaves no fd, node or directory");

    /* refusals: nothing left behind */
    const char *bad_proc[] = {
        "00-31: TDM-LPAIF-RX-TERTIARY multicodec-31 :  : playback 1\n00-33: TDM-LPAIF-TX-TERTIARY x :  : capture 1\n",
        "00-32: TDM-LPAIF-RX-TERTIARY-VIRT-2 a :  : capture 1\n00-33: TDM-LPAIF-TX-TERTIARY x :  : capture 1\n",
        ("00-32: TDM-LPAIF-RX-TERTIARY-VIRT-2 a :  : playback 1\n00-34: TDM-LPAIF-RX-TERTIARY-VIRT-2 b :  : playback 1\n"
         "00-33: TDM-LPAIF-TX-TERTIARY x :  : capture 1\n"), /* one element (parenthesized for clang) */
        "00-32: TDM-LPAIF-RX-TERTIARY-VIRT-22 a :  : playback 1\n00-33: TDM-LPAIF-TX-TERTIARY x :  : capture 1\n",
    };
    const int want[] = {-ENODEV, -ENODEV, -EEXIST, -ENODEV};
    for (unsigned i = 0; i < sizeof want / sizeof want[0]; i++) {
        reset(); proc_text = bad_proc[i];
        assert(prep(&b) == want[i] && !dir_live && live_nodes() == 0 && open_fds() == 0);
    }
    reset(); dev_rx = "116:x\n";
    assert(prep(&b) == -EPROTO && !dir_live);
    reset(); dev_tx = "117:35\n";
    assert(prep(&b) == -EPROTO && !dir_live);
    reset(); mkdir_errno = EEXIST;
    assert(prep(&b) == -EEXIST && live_nodes() == 0);
    reset(); open_rdev_skew = 7;
    assert(prep(&b) == -ENXIO && !dir_live && live_nodes() == 0 && open_fds() == 0);
    puts("PASS prepare refused: missing, wrong-direction, duplicated or prefix-only name, malformed or mixed majors, existing directory, a node that opens another device; nothing left behind");
    reset();
    assert(prep(&b) == 0);
    refine_period = 1;
    assert(m11_snd_pcm_open(&b, M11_SND_RX, 96000, 3, SNDRV_PCM_FORMAT_S32_LE, 682, 2, 170, INT_MAX) == -EPROTO);
    assert(b.pcm[0].fd == -1 && open_fds() == 1 && live_nodes() == 1);
    refine_period = 0;
    m11_snd_release(&b);
    assert(!dir_live && open_fds() == 0 && live_nodes() == 0);
    puts("PASS PCM open refused when the kernel refines the period; the fd is closed and the node gone");

    puts("PASS snd backend (fixture syscalls)");
    return 0;
}
