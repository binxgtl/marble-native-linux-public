/* P5 W3: PID1-private ALSA back ends and amplifier controls (snd_backend_native.h has the rules). */
#ifndef M11_CUSTODIAN_NATIVE
#error "snd_backend_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#define _GNU_SOURCE
#include "snd_backend_native.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sound/asound.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define CTL_MAX_ELEMS 8192u

static int l_open(const char *p, int f) { int fd = open(p, f); return fd < 0 ? -errno : fd; }
static int l_fstat(int fd, struct stat *st) { return fstat(fd, st) ? -errno : 0; }
static int l_close(int fd) { return close(fd) ? -errno : 0; }
static int l_ioctl(int fd, unsigned long req, void *arg) { return ioctl(fd, req, arg) < 0 ? -errno : 0; }
static int l_mknod(const char *p, mode_t m, dev_t d) { return mknod(p, m, d) ? -errno : 0; }
static int l_unlink(const char *p) { return unlink(p) ? -errno : 0; }
static int l_mkdir(const char *p, mode_t m) { return mkdir(p, m) ? -errno : 0; }
static int l_rmdir(const char *p) { return rmdir(p) ? -errno : 0; }
static ssize_t l_read_text(const char *p, char *buf, size_t cap) {
    if (!cap) return -EINVAL;
    int fd = open(p, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = read(fd, buf + n, cap - 1 - n);
        if (r < 0) { if (errno == EINTR) continue; int e = -errno; (void)close(fd); return e; }
        if (!r) break;
        n += (size_t)r;
    }
    (void)close(fd);
    if (n + 1 >= cap) return -EFBIG; /* a truncated file is never parsed */
    buf[n] = '\0';
    return (ssize_t)n;
}
static const m11_snd_sys libc_sys = {l_open, l_fstat, l_close, l_ioctl, l_mknod, l_unlink, l_mkdir, l_rmdir, l_read_text};

m11_snd_paths m11_snd_paths_default(void) {
    m11_snd_paths p = {"/proc/asound/pcm", "/sys/class/sound", "/run/m11/snd", 0};
    return p;
}

/* "MAJ:MIN\n" exactly */
static int parse_devnum(const char *s, dev_t *out) {
    char *end;
    errno = 0;
    unsigned long ma = strtoul(s, &end, 10);
    if (end == s || *end != ':' || errno || ma > 4095) return -EPROTO;
    const char *m = end + 1;
    unsigned long mi = strtoul(m, &end, 10);
    if (end == m || errno || mi > 1048575 || (*end && strcmp(end, "\n"))) return -EPROTO;
    if (!ma) return -EPROTO;
    *out = makedev((unsigned)ma, (unsigned)mi);
    return 0;
}

static int read_devnum(const m11_snd_sys *sys, const char *path, dev_t *out) {
    char buf[32];
    ssize_t n = sys->read_text_fn(path, buf, sizeof buf);
    if (n < 0) return (int)n;
    return parse_devnum(buf, out);
}

/* Exactly one line "CC-DD: <name> ..." whose first token is name; it must carry " : playback " (capture
 * 0) or " : capture " (capture 1). The device number is written to *dev. */
static int find_pcm(const char *text, unsigned card, const char *name, int capture, unsigned *dev) {
    int hits = 0;
    const char *line = text;
    while (*line) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        char buf[256];
        if (len < sizeof buf) {
            memcpy(buf, line, len);
            buf[len] = '\0';
            unsigned c, d;
            char tok[80];
            int used = 0;
            if (sscanf(buf, "%u-%u: %79s%n", &c, &d, tok, &used) == 3 && c == card && !strcmp(tok, name)) {
                const char *want = capture ? " : capture " : " : playback ";
                if (!strstr(buf + used, want)) return -ENODEV;
                *dev = d;
                hits++;
            }
        } else {
            return -EPROTO; /* an over-long line is never skipped */
        }
        line += len + (nl ? 1 : 0);
    }
    return hits == 1 ? 0 : hits ? -EEXIST : -ENODEV;
}

static void drop_nodes(m11_snd_backend *b) {
    for (int i = 0; i < 2; i++) {
        if (b->pcm[i].node_made) { (void)b->sys->unlink_fn(b->pcm[i].node); b->pcm[i].node_made = 0; }
    }
    if (b->dir_made) { (void)b->sys->rmdir_fn(b->paths.dir); b->dir_made = 0; }
}

/* make "<dir>/<leaf>" as a 0600 character node with rdev */
static int make_node(m11_snd_backend *b, char *path, size_t cap, const char *leaf, dev_t rdev) {
    int n = snprintf(path, cap, "%s/%s", b->paths.dir, leaf);
    if (n < 0 || (size_t)n >= cap) return -ENAMETOOLONG;
    return b->sys->mknod_fn(path, S_IFCHR | 0600, rdev);
}

/* open a node just made, check it is the character device expected, then remove its entry */
static int open_node(m11_snd_backend *b, const char *path, dev_t rdev, int flags, int *fd_out) {
    int fd = b->sys->open_fn(path, flags | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    int urc = b->sys->unlink_fn(path); /* the entry goes whatever the open did */
    if (fd < 0) return fd;
    struct stat st;
    int rc = b->sys->fstat_fn(fd, &st);
    if (!rc && (!S_ISCHR(st.st_mode) || st.st_rdev != rdev)) rc = -ENXIO;
    if (!rc && urc) rc = urc;
    if (rc) { (void)b->sys->close_fn(fd); return rc; }
    *fd_out = fd;
    return 0;
}

int m11_snd_prepare(m11_snd_backend *b, const m11_snd_sys *sys, const m11_snd_paths *paths,
                    const char *rx_name, const char *tx_name) {
    if (!b || !paths || !paths->proc_pcm || !paths->sys_sound || !paths->dir || !rx_name || !tx_name ||
        !*rx_name || !*tx_name || strlen(rx_name) >= sizeof b->pcm[0].name || strlen(tx_name) >= sizeof b->pcm[0].name)
        return -EINVAL;
    memset(b, 0, sizeof *b);
    b->sys = sys ? sys : &libc_sys;
    b->paths = *paths;
    b->ctl_fd = -1;
    b->pcm[0].fd = b->pcm[1].fd = -1;
    char text[16384], path[160];
    ssize_t n = b->sys->read_text_fn(paths->proc_pcm, text, sizeof text);
    if (n < 0) return (int)n;
    const char *names[2] = {rx_name, tx_name};
    for (int i = 0; i < 2; i++) {
        m11_snd_pcm *p = &b->pcm[i];
        strcpy(p->name, names[i]);
        int rc = find_pcm(text, paths->card, p->name, i == M11_SND_TX, &p->device);
        if (rc) return rc;
        int k = snprintf(path, sizeof path, "%s/pcmC%uD%u%c/dev", paths->sys_sound, paths->card, p->device,
                         i == M11_SND_TX ? 'c' : 'p');
        if (k < 0 || (size_t)k >= sizeof path) return -ENAMETOOLONG;
        if ((rc = read_devnum(b->sys, path, &p->rdev))) return rc;
    }
    int k = snprintf(path, sizeof path, "%s/controlC%u/dev", paths->sys_sound, paths->card);
    if (k < 0 || (size_t)k >= sizeof path) return -ENAMETOOLONG;
    int rc = read_devnum(b->sys, path, &b->ctl_rdev);
    if (rc) return rc;
    if (major(b->ctl_rdev) != major(b->pcm[0].rdev) || major(b->pcm[0].rdev) != major(b->pcm[1].rdev))
        return -EPROTO; /* one sound major for the card */
    if ((rc = b->sys->mkdir_fn(paths->dir, 0700))) return rc; /* an existing directory is refused */
    b->dir_made = 1;
    char ctl_node[160];
    if ((rc = make_node(b, ctl_node, sizeof ctl_node, "control", b->ctl_rdev))) { drop_nodes(b); return rc; }
    if ((rc = open_node(b, ctl_node, b->ctl_rdev, O_RDWR, &b->ctl_fd))) { drop_nodes(b); return rc; }
    for (int i = 0; i < 2; i++) {
        m11_snd_pcm *p = &b->pcm[i];
        char leaf[24];
        (void)snprintf(leaf, sizeof leaf, "pcm%c", i == M11_SND_TX ? 'c' : 'p');
        if ((rc = make_node(b, p->node, sizeof p->node, leaf, p->rdev))) {
            (void)b->sys->close_fn(b->ctl_fd); b->ctl_fd = -1; drop_nodes(b); return rc;
        }
        p->node_made = 1;
    }
    return 0;
}

static int find_ctl(m11_snd_backend *b, const char *name, struct snd_ctl_elem_id *out) {
    if (!b || b->ctl_fd < 0 || !name || strlen(name) >= SNDRV_CTL_ELEM_ID_NAME_MAXLEN) return -EINVAL;
    struct snd_ctl_elem_list list;
    memset(&list, 0, sizeof list);
    int rc = b->sys->ioctl_fn(b->ctl_fd, SNDRV_CTL_IOCTL_ELEM_LIST, &list);
    if (rc) return rc;
    if (!list.count || list.count > CTL_MAX_ELEMS) return -E2BIG;
    struct snd_ctl_elem_id *ids = calloc(list.count, sizeof *ids);
    if (!ids) return -ENOMEM;
    list.space = list.count;
    list.offset = 0;
    list.pids = ids;
    rc = b->sys->ioctl_fn(b->ctl_fd, SNDRV_CTL_IOCTL_ELEM_LIST, &list);
    int hits = 0;
    if (!rc) {
        for (unsigned i = 0; i < list.used && i < list.space; i++) {
            if (ids[i].iface == SNDRV_CTL_ELEM_IFACE_MIXER && ids[i].index == 0 &&
                !strncmp((const char *)ids[i].name, name, SNDRV_CTL_ELEM_ID_NAME_MAXLEN)) {
                *out = ids[i];
                hits++;
            }
        }
    }
    free(ids);
    if (rc) return rc;
    return hits == 1 ? 0 : hits ? -EEXIST : -ENOENT;
}

/* the info of an enumerated control with 1..2 values; item names are looked up by index */
static int enum_info(m11_snd_backend *b, const struct snd_ctl_elem_id *id, unsigned *count, unsigned *items) {
    struct snd_ctl_elem_info info;
    memset(&info, 0, sizeof info);
    info.id = *id;
    int rc = b->sys->ioctl_fn(b->ctl_fd, SNDRV_CTL_IOCTL_ELEM_INFO, &info);
    if (rc) return rc;
    if (info.type != SNDRV_CTL_ELEM_TYPE_ENUMERATED || info.count < 1 || info.count > 2 ||
        !info.value.enumerated.items || info.value.enumerated.items > 64)
        return -EPROTO;
    *count = info.count;
    *items = info.value.enumerated.items;
    return 0;
}

static int item_name(m11_snd_backend *b, const struct snd_ctl_elem_id *id, unsigned item, char *out, size_t cap) {
    struct snd_ctl_elem_info info;
    memset(&info, 0, sizeof info);
    info.id = *id;
    info.value.enumerated.item = item;
    int rc = b->sys->ioctl_fn(b->ctl_fd, SNDRV_CTL_IOCTL_ELEM_INFO, &info);
    if (rc) return rc;
    size_t n = strnlen(info.value.enumerated.name, sizeof info.value.enumerated.name);
    if (n == sizeof info.value.enumerated.name || n >= cap) return -EPROTO;
    memcpy(out, info.value.enumerated.name, n + 1);
    return 0;
}

static int read_items(m11_snd_backend *b, const struct snd_ctl_elem_id *id, unsigned count, unsigned *vals) {
    struct snd_ctl_elem_value v;
    memset(&v, 0, sizeof v);
    v.id = *id;
    int rc = b->sys->ioctl_fn(b->ctl_fd, SNDRV_CTL_IOCTL_ELEM_READ, &v);
    if (rc) return rc;
    for (unsigned c = 0; c < count; c++) vals[c] = v.value.enumerated.item[c];
    return 0;
}

int m11_snd_ctl_set(m11_snd_backend *b, const char *control, const char *item) {
    if (!item || !*item) return -EINVAL;
    struct snd_ctl_elem_id id;
    unsigned count, items, want = UINT_MAX;
    int rc = find_ctl(b, control, &id);
    if (rc || (rc = enum_info(b, &id, &count, &items))) return rc;
    for (unsigned i = 0; i < items; i++) {
        char nm[64];
        if ((rc = item_name(b, &id, i, nm, sizeof nm))) return rc;
        if (!strcmp(nm, item)) {
            if (want != UINT_MAX) return -EEXIST;
            want = i;
        }
    }
    if (want == UINT_MAX) return -ENOENT;
    struct snd_ctl_elem_value v;
    memset(&v, 0, sizeof v);
    v.id = id;
    for (unsigned c = 0; c < count; c++) v.value.enumerated.item[c] = want;
    b->ctl_writes++;
    if ((rc = b->sys->ioctl_fn(b->ctl_fd, SNDRV_CTL_IOCTL_ELEM_WRITE, &v))) return rc;
    unsigned got[2] = {UINT_MAX, UINT_MAX};
    if ((rc = read_items(b, &id, count, got))) return rc;
    b->ctl_readbacks++;
    for (unsigned c = 0; c < count; c++) if (got[c] != want) return -EIO;
    return 0;
}

int m11_snd_ctl_get(m11_snd_backend *b, const char *control, char *out, size_t cap) {
    if (!out || !cap) return -EINVAL;
    struct snd_ctl_elem_id id;
    unsigned count, items, got[2] = {UINT_MAX, UINT_MAX};
    int rc = find_ctl(b, control, &id);
    if (rc || (rc = enum_info(b, &id, &count, &items)) || (rc = read_items(b, &id, count, got))) return rc;
    if (got[0] >= items || (count == 2 && got[1] != got[0])) return -EPROTO;
    return item_name(b, &id, got[0], out, cap);
}

/* tinyalsa param_init and setters */
static struct snd_mask *hw_mask(struct snd_pcm_hw_params *p, int n) {
    return &p->masks[n - SNDRV_PCM_HW_PARAM_FIRST_MASK];
}
static struct snd_interval *hw_interval(struct snd_pcm_hw_params *p, int n) {
    return &p->intervals[n - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL];
}
static void hw_init(struct snd_pcm_hw_params *p) {
    memset(p, 0, sizeof *p);
    for (int n = SNDRV_PCM_HW_PARAM_FIRST_MASK; n <= SNDRV_PCM_HW_PARAM_LAST_MASK; n++) {
        hw_mask(p, n)->bits[0] = ~0u;
        hw_mask(p, n)->bits[1] = ~0u;
    }
    for (int n = SNDRV_PCM_HW_PARAM_FIRST_INTERVAL; n <= SNDRV_PCM_HW_PARAM_LAST_INTERVAL; n++) {
        hw_interval(p, n)->min = 0;
        hw_interval(p, n)->max = ~0u;
    }
    p->rmask = ~0u;
    p->cmask = 0;
    p->info = ~0u;
}
static void hw_set_mask(struct snd_pcm_hw_params *p, int n, unsigned bit) {
    struct snd_mask *m = hw_mask(p, n);
    m->bits[0] = 0;
    m->bits[1] = 0;
    m->bits[bit >> 5] |= 1u << (bit & 31);
}
static void hw_set_int(struct snd_pcm_hw_params *p, int n, unsigned v) {
    struct snd_interval *i = hw_interval(p, n);
    i->min = v;
    i->max = v;
    i->integer = 1;
}

int m11_snd_pcm_open(m11_snd_backend *b, int which, unsigned rate, unsigned channels, unsigned format,
                     unsigned period, unsigned periods, unsigned start_threshold, unsigned stop_threshold) {
    if (!b || (which != M11_SND_RX && which != M11_SND_TX)) return -EINVAL;
    m11_snd_pcm *p = &b->pcm[which];
    if (p->fd >= 0 || !p->node_made) return -EALREADY;
    if (!rate || !channels || channels > 8 || format > 63 || !period || !periods || periods > 64 ||
        !start_threshold || !stop_threshold)
        return -EINVAL;
    int fd = -1;
    p->node_made = 0; /* open_node removes the entry whatever happens */
    int rc = open_node(b, p->node, p->rdev, O_RDWR, &fd);
    if (rc) return rc;
    struct snd_pcm_hw_params hw;
    hw_init(&hw);
    hw_set_mask(&hw, SNDRV_PCM_HW_PARAM_FORMAT, format);
    hw_interval(&hw, SNDRV_PCM_HW_PARAM_PERIOD_SIZE)->min = period;
    hw_set_int(&hw, SNDRV_PCM_HW_PARAM_CHANNELS, channels);
    hw_set_int(&hw, SNDRV_PCM_HW_PARAM_PERIODS, periods);
    hw_set_int(&hw, SNDRV_PCM_HW_PARAM_RATE, rate);
    hw_set_mask(&hw, SNDRV_PCM_HW_PARAM_ACCESS, SNDRV_PCM_ACCESS_RW_INTERLEAVED);
    if ((rc = b->sys->ioctl_fn(fd, SNDRV_PCM_IOCTL_HW_PARAMS, &hw))) { (void)b->sys->close_fn(fd); return rc; }
    /* the kernel chooses one value per parameter (snd_pcm_hw_params_choose); it must be the requested one
     * (AGM's back end has a fixed configuration) */
    const struct snd_interval *ps = hw_interval(&hw, SNDRV_PCM_HW_PARAM_PERIOD_SIZE);
    const struct snd_interval *pc = hw_interval(&hw, SNDRV_PCM_HW_PARAM_PERIODS);
    const struct snd_interval *rt = hw_interval(&hw, SNDRV_PCM_HW_PARAM_RATE);
    const struct snd_interval *ch = hw_interval(&hw, SNDRV_PCM_HW_PARAM_CHANNELS);
    if (ps->min != period || ps->max != period || pc->min != periods || pc->max != periods ||
        rt->min != rate || rt->max != rate || ch->min != channels || ch->max != channels) {
        (void)b->sys->close_fn(fd);
        return -EPROTO;
    }
    struct snd_pcm_sw_params sw;
    memset(&sw, 0, sizeof sw);
    sw.tstamp_mode = SNDRV_PCM_TSTAMP_ENABLE;
    sw.period_step = 1;
    sw.avail_min = period;
    sw.start_threshold = start_threshold;
    sw.stop_threshold = stop_threshold;
    sw.xfer_align = period / 2;
    sw.silence_size = 0;
    sw.silence_threshold = 0;
    unsigned long buffer = (unsigned long)period * periods, boundary = buffer;
    while (boundary * 2 <= (unsigned long)INT_MAX - buffer) boundary *= 2;
    sw.boundary = boundary;
    if ((rc = b->sys->ioctl_fn(fd, SNDRV_PCM_IOCTL_SW_PARAMS, &sw))) { (void)b->sys->close_fn(fd); return rc; }
    p->fd = fd;
    p->rate = rate;
    p->channels = channels;
    p->period = period;
    p->periods = periods;
    return 0;
}

int m11_snd_pcm_prepare(m11_snd_backend *b, int which) {
    if (!b || (which != M11_SND_RX && which != M11_SND_TX)) return -EINVAL;
    m11_snd_pcm *p = &b->pcm[which];
    if (p->fd < 0) return -EBADF;
    int rc = b->sys->ioctl_fn(p->fd, SNDRV_PCM_IOCTL_PREPARE, NULL);
    if (!rc) p->prepared = 1;
    return rc;
}

int m11_snd_pcm_close(m11_snd_backend *b, int which) {
    if (!b || (which != M11_SND_RX && which != M11_SND_TX)) return -EINVAL;
    m11_snd_pcm *p = &b->pcm[which];
    if (p->fd < 0) return 0;
    int rc = b->sys->ioctl_fn(p->fd, SNDRV_PCM_IOCTL_DROP, NULL);
    int crc = b->sys->close_fn(p->fd);
    p->fd = -1;
    p->prepared = 0;
    return rc ? rc : crc;
}

void m11_snd_release(m11_snd_backend *b) {
    if (!b || !b->sys) return;
    for (int i = 0; i < 2; i++) (void)m11_snd_pcm_close(b, i);
    if (b->ctl_fd >= 0) { (void)b->sys->close_fn(b->ctl_fd); b->ctl_fd = -1; }
    drop_nodes(b);
}
