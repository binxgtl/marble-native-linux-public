/* M19 R5b synthetic test driver for m19-speaker:
 *  - scan-snd <path>: exercises m19_speaker_scan_snd on arbitrary directory/symlink/node trees;
 *  - prechecks <work_dir>: exercises production defaults, invalid configurations, single-run lock
 *    preservation of speaker.report, pre-open /dev cleanliness, system-wide /proc foreign audio holder
 *    refusal, SHA256/M11SPK01/safety-cap plan verification, and pre-boot m11_entry_run refusals
 *    (non-kmsg journal, non-strict cmdline, SERVREG PD never UP, reboot_fn refusal);
 *  - session <work_dir>: as root in an isolated mount namespace, exercises the full Run31 speaker
 *    session over stand-in endpoint/ION/heap nodes, seccomp-sealed anchor/pool fds, SERVREG QRTR,
 *    private unlinked ALSA nodes, raw-PTY ADSP GPR responder, Re readback failure, playback WR_DONE
 *    error with Disable-first teardown, and SERVREG PD DOWN during MAP with deferred ACK.
 * No phone, no real audio driver, no hardware, no reboot. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-speaker.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "speaker.h"
#include "../unlock/core.h"
#include "gpr_transport_native.h"
#include "intent_journal_native.h"
#include "m11_anchor_linux.h"
#include "shmem_backend_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sound/asound.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* ---------------- event log inside the session child ---------------- */
#define FMT_CHK(buf, ...) do { \
    _Static_assert(sizeof(buf) > sizeof(char *), "FMT_CHK requires a char array"); \
    int _n = snprintf((buf), sizeof(buf), __VA_ARGS__); \
    if (_n < 0 || (size_t)_n >= sizeof(buf)) abort(); \
} while (0)

#define EV_MAX 512
static char ev[EV_MAX][48];
static unsigned nev;
static void evlog(const char *s) {
    size_t len = strlen(s);
    assert(len < sizeof ev[0]);
    if (nev < EV_MAX) memcpy(ev[nev++], s, len + 1u);
}

/* ---------------- filesystem helpers ---------------- */
static int rm_one(const char *p, const struct stat *st, int flag, struct FTW *f) {
    (void)st; (void)f;
    return flag == FTW_DP ? rmdir(p) : unlink(p);
}

static void clean_dir(const char *p) {
    struct stat st;
    if (lstat(p, &st) == 0) (void)nftw(p, rm_one, 16, FTW_DEPTH | FTW_PHYS);
}

static void put_bytes(const char *root, const char *rel, const void *data, size_t len) {
    char path[PATH_MAX], dir[PATH_MAX];
    FMT_CHK(path, "%s/%s", root, rel);
    FMT_CHK(dir, "%s", path);
    for (char *s = dir + strlen(root) + 1; (s = strchr(s, '/')); s++) {
        *s = '\0';
        (void)mkdir(dir, 0755);
        *s = '/';
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    assert(fd >= 0);
    const uint8_t *p = data;
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(fd, p + done, len - done);
        assert(w > 0);
        done += (size_t)w;
    }
    assert(close(fd) == 0);
}

static void put_text(const char *root, const char *rel, const char *text) {
    put_bytes(root, rel, text, strlen(text));
}

static size_t slurp(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    size_t got = 0;
    while (got + 1 < cap) {
        ssize_t r = read(fd, buf + got, cap - 1 - got);
        assert(r >= 0);
        if (r == 0) break;
        got += (size_t)r;
    }
    assert(close(fd) == 0);
    buf[got] = '\0';
    return got;
}

static int path_is_absent(const char *p) {
    struct stat st;
    return lstat(p, &st) != 0 && errno == ENOENT;
}

static long kv_long(const char *rep, const char *key) {
    char pat[64];
    int n = snprintf(pat, sizeof pat, "%s=", key);
    assert(n > 0 && (size_t)n < sizeof pat);
    for (const char *l = rep; *l;) {
        const char *nl = strchr(l, '\n');
        size_t len = nl ? (size_t)(nl - l) : strlen(l);
        if (len > (size_t)n && !memcmp(l, pat, (size_t)n)) {
            char val[64];
            size_t vl = len - (size_t)n;
            assert(vl < sizeof val);
            memcpy(val, l + n, vl);
            val[vl] = '\0';
            char *end = NULL;
            long v = strtol(val, &end, 10);
            assert(end && *end == '\0');
            return v;
        }
        l += len + (nl ? 1 : 0);
    }
    fprintf(stderr, "missing key %s in report:\n%s\n", key, rep);
    abort();
}

static void kv_str(const char *rep, const char *key, char *out, size_t cap) {
    char pat[64];
    int n = snprintf(pat, sizeof pat, "%s=", key);
    assert(n > 0 && (size_t)n < sizeof pat);
    for (const char *l = rep; *l;) {
        const char *nl = strchr(l, '\n');
        size_t len = nl ? (size_t)(nl - l) : strlen(l);
        if (len > (size_t)n && !memcmp(l, pat, (size_t)n)) {
            size_t vl = len - (size_t)n;
            assert(vl < cap);
            memcpy(out, l + n, vl);
            out[vl] = '\0';
            return;
        }
        l += len + (nl ? 1 : 0);
    }
    fprintf(stderr, "missing string key %s in report:\n%s\n", key, rep);
    abort();
}

/* ---------------- synthetic M11SPK01 plan builder ---------------- */
static uint8_t plan_buf[262144];
static size_t pl_at;
static void put32(uint32_t v) { memcpy(plan_buf + pl_at, &v, 4); pl_at += 4; }
static void putb(const void *p, size_t n) {
    memcpy(plan_buf + pl_at, p, n);
    pl_at += n;
    for (; n % 8; n++) plan_buf[pl_at++] = 0;
}
static size_t sec_begin(uint32_t type) { put32(type); size_t at = pl_at; put32(0); return at; }
static void sec_end(size_t at) {
    uint32_t n = (uint32_t)(pl_at - at - 4);
    memcpy(plan_buf + at, &n, 4);
    while (pl_at % 8) plan_buf[pl_at++] = 0;
}
static void param(uint8_t *out, size_t *len, uint32_t miid, uint32_t pid, uint32_t v) {
    uint32_t w[6] = {miid, pid, 4, 0, v, 0};
    memcpy(out + *len, w, sizeof w);
    *len += sizeof w;
}
static void put_graph(uint32_t id, const uint32_t *sgs, uint32_t nsg, uint32_t ncfg) {
    size_t s = sec_begin(1);
    put32(id); put32(nsg);
    for (uint32_t i = 0; i < nsg; i++) put32(sgs[i]);
    uint8_t blob[96]; size_t bl = 0;
    param(blob, &bl, 1, 0x08001001, id); param(blob, &bl, 1, 0x08001002, id);
    put32((uint32_t)bl); putb(blob, bl);
    bl = 0; param(blob, &bl, 0x4008, 0x08001035, 0x2000);
    put32((uint32_t)bl); putb(blob, bl);
    put32(ncfg);
    for (uint32_t i = 0; i < ncfg; i++) {
        bl = 0; param(blob, &bl, 0x428F, 0x08001017 + i, i);
        put32((uint32_t)bl); putb(blob, bl);
    }
    sec_end(s);
}

static size_t build_plan_custom(uint32_t duration_ms, int32_t peak_mdbfs, uint32_t volume_level) {
    memset(plan_buf, 0, sizeof plan_buf);
    pl_at = 64;
    static const uint32_t vi_sgs[] = {0xB00000D5, 0xB00000CE};
    static const uint32_t rx_sgs[] = {0xB0000002, 0xB0000025, 0xB0000024, 0xB0000023};
    put_graph(1, vi_sgs, 2, 3);
    put_graph(2, rx_sgs, 4, 6);
    size_t s = sec_begin(2);
    uint32_t ids[14] = {0x40BD, 0x4547, 0x42D3, 0x42D4, 0x428F, 0x4308, 0x4008, 48000, 2, 2, 48000, 2, 2, volume_level};
    for (int i = 0; i < 14; i++) put32(ids[i]);
    sec_end(s);
    s = sec_begin(3);
    uint32_t be0[6] = {0, 96000, 3, SNDRV_PCM_FORMAT_S32_LE, 682, 2};
    uint32_t be1[6] = {1, 96000, 2, SNDRV_PCM_FORMAT_S32_LE, 1024, 2};
    char nm[64];
    for (int i = 0; i < 6; i++) put32(be0[i]);
    memset(nm, 0, sizeof nm); strcpy(nm, "TDM-LPAIF-RX-TERTIARY-VIRT-2"); memcpy(plan_buf + pl_at, nm, 64); pl_at += 64;
    for (int i = 0; i < 6; i++) put32(be1[i]);
    memset(nm, 0, sizeof nm); strcpy(nm, "TDM-LPAIF-TX-TERTIARY"); memcpy(plan_buf + pl_at, nm, 64); pl_at += 64;
    sec_end(s);
    s = sec_begin(4);
    for (int i = 0; i < 2; i++) {
        char c[64]; memset(c, 0, sizeof c);
        int cn = snprintf(c, 44, "aw_dev_%d_prof", i);
        assert(cn > 0 && cn < 44);
        strcpy(c + 44, "Music");
        memcpy(plan_buf + pl_at, c, 64); pl_at += 64;
    }
    sec_end(s);
    s = sec_begin(5); put32(6372); put32(7003); sec_end(s);
    s = sec_begin(6);
    put32(duration_ms); put32(10); put32(1); put32((uint32_t)peak_mdbfs);
    put32(0); put32(440); sec_end(s);
    s = sec_begin(7);
    uint32_t bytes = 48000u * duration_ms / 1000u * 4u;
    for (uint32_t i = 0; i < bytes; i++) plan_buf[pl_at++] = (uint8_t)(i * 7u);
    sec_end(s);
    memcpy(plan_buf, "M11SPK01", 8);
    uint32_t hdr[4] = {1, (uint32_t)pl_at, 8, 64};
    memcpy(plan_buf + 8, hdr, sizeof hdr);
    return pl_at;
}

static void sha_hex_of(const void *data, size_t len, char out[65]) {
    static const char hex[] = "0123456789abcdef";
    uint8_t d[32];
    m19_sha256(data, len, d);
    for (unsigned i = 0; i < 32u; i++) {
        out[2u * i] = hex[d[i] >> 4];
        out[2u * i + 1u] = hex[d[i] & 0x0fu];
    }
    out[64] = '\0';
}

static void write_plan_files(const char *root, uint32_t duration_ms, int32_t peak_mdbfs, uint32_t volume_level, char sha_out[65]) {
    size_t len = build_plan_custom(duration_ms, peak_mdbfs, volume_level);
    char hex[65], sha_line[80];
    sha_hex_of(plan_buf, len, hex);
    if (sha_out) memcpy(sha_out, hex, 65);
    FMT_CHK(sha_line, "%s  plan.bin\n", hex);
    put_bytes(root, "speaker/plan.bin", plan_buf, len);
    put_text(root, "speaker/plan.sha256", sha_line);
}

/* ---------------- ALSA fixture (private directory + virtual char nodes) ---------------- */
static struct { char path[PATH_MAX]; dev_t rdev; int live; } nodes[8];
static struct { int fd; dev_t rdev; int open; } afd[8];
static int a_next;
static const char *elem_names[4] = {"aw_dev_0_switch", "aw_dev_1_switch", "aw_dev_0_prof", "aw_dev_1_prof"};
static unsigned elem_value[4];

static ssize_t a_read_text(const char *p, char *buf, size_t cap) {
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
    if (n + 1 >= cap) return -EFBIG;
    buf[n] = '\0';
    return (ssize_t)n;
}
static int a_mkdir(const char *p, mode_t m) { return mkdir(p, m) ? -errno : 0; }
static int a_rmdir(const char *p) {
    for (int i = 0; i < 8; i++) if (nodes[i].live) return -ENOTEMPTY;
    return rmdir(p) ? -errno : 0;
}
static int a_mknod(const char *p, mode_t m, dev_t d) {
    (void)m;
    for (int i = 0; i < 8; i++) {
        if (!nodes[i].live) {
            FMT_CHK(nodes[i].path, "%s", p);
            nodes[i].rdev = d;
            nodes[i].live = 1;
            return 0;
        }
    }
    return -ENOSPC;
}
static int a_unlink(const char *p) {
    for (int i = 0; i < 8; i++) {
        if (nodes[i].live && !strcmp(nodes[i].path, p)) {
            nodes[i].live = 0;
            return 0;
        }
    }
    return -ENOENT;
}
static int a_open(const char *p, int f) {
    (void)f;
    for (int i = 0; i < 8; i++) {
        if (nodes[i].live && !strcmp(nodes[i].path, p)) {
            for (int k = 0; k < 8; k++) {
                if (!afd[k].open) {
                    afd[k].fd = 500 + a_next++;
                    afd[k].rdev = nodes[i].rdev;
                    afd[k].open = 1;
                    return afd[k].fd;
                }
            }
        }
    }
    return -ENOENT;
}
static int a_slot(int fd) {
    for (int k = 0; k < 8; k++) if (afd[k].open && afd[k].fd == fd) return k;
    return -1;
}
static int a_fstat(int fd, struct stat *st) {
    int k = a_slot(fd);
    if (k < 0) return -EBADF;
    memset(st, 0, sizeof *st);
    st->st_mode = S_IFCHR | 0600;
    st->st_rdev = afd[k].rdev;
    return 0;
}
static int a_close(int fd) {
    int k = a_slot(fd);
    if (k < 0) return -EBADF;
    afd[k].open = 0;
    return 0;
}
static const char *pcm_tag(int fd) {
    int k = a_slot(fd);
    return k >= 0 && minor(afd[k].rdev) == 34 ? "rx" : "tx";
}
static int a_ioctl(int fd, unsigned long req, void *arg) {
    int k = a_slot(fd);
    if (k < 0) return -EBADF;
    char e[48];
    if (minor(afd[k].rdev) == 1) {
        if (req == SNDRV_CTL_IOCTL_ELEM_LIST) {
            struct snd_ctl_elem_list *l = arg;
            l->count = 4;
            if (l->space) {
                for (unsigned i = 0; i < 4 && i < l->space; i++) {
                    memset(&l->pids[i], 0, sizeof l->pids[i]);
                    l->pids[i].numid = i + 1;
                    l->pids[i].iface = SNDRV_CTL_ELEM_IFACE_MIXER;
                    int nm = snprintf((char *)l->pids[i].name, sizeof l->pids[i].name, "%s", elem_names[i]);
                    assert(nm > 0 && (size_t)nm < sizeof l->pids[i].name);
                }
                l->used = 4;
            }
            return 0;
        }
        if (req == SNDRV_CTL_IOCTL_ELEM_INFO) {
            struct snd_ctl_elem_info *in = arg;
            unsigned el = in->id.numid - 1, it = in->value.enumerated.item;
            static const char *sw[] = {"Disable", "Enable"}, *pf[] = {"Music", "Voice"};
            in->type = SNDRV_CTL_ELEM_TYPE_ENUMERATED;
            in->count = 1;
            in->value.enumerated.items = 2;
            if (it < 2) FMT_CHK(in->value.enumerated.name, "%s", el < 2 ? sw[it] : pf[it]);
            return 0;
        }
        if (req == SNDRV_CTL_IOCTL_ELEM_WRITE) {
            struct snd_ctl_elem_value *v = arg;
            unsigned el = v->id.numid - 1, val = v->value.enumerated.item[0];
            if (el < 2) {
                FMT_CHK(e, "sw%u=%s", el, val ? "Enable" : "Disable");
                evlog(e);
            }
            elem_value[el] = val;
            return 0;
        }
        if (req == SNDRV_CTL_IOCTL_ELEM_READ) {
            struct snd_ctl_elem_value *v = arg;
            v->value.enumerated.item[0] = elem_value[v->id.numid - 1];
            return 0;
        }
        return -ENOTTY;
    }
    const char *t = pcm_tag(fd);
    if (req == SNDRV_PCM_IOCTL_HW_PARAMS) {
        struct snd_pcm_hw_params *h = arg;
        for (int n = SNDRV_PCM_HW_PARAM_FIRST_INTERVAL; n <= SNDRV_PCM_HW_PARAM_LAST_INTERVAL; n++) {
            struct snd_interval *i = &h->intervals[n - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL];
            i->max = i->min;
            i->integer = 1;
        }
        FMT_CHK(e, "%s_hw", t);
        evlog(e);
        return 0;
    }
    if (req == SNDRV_PCM_IOCTL_SW_PARAMS) return 0;
    if (req == SNDRV_PCM_IOCTL_PREPARE) { FMT_CHK(e, "%s_prepare", t); evlog(e); return 0; }
    if (req == SNDRV_PCM_IOCTL_DROP) { FMT_CHK(e, "%s_drop", t); evlog(e); return 0; }
    return -ENOTTY;
}
static const m11_snd_sys asys = {a_open, a_fstat, a_close, a_ioctl, a_mknod, a_unlink, a_mkdir, a_rmdir, a_read_text};

/* ---------------- shmem fixture over memfd + stand-in rdevs ---------------- */
static int rdev_is(int fd, dev_t d) {
    struct stat st;
    return !fstat(fd, &st) && S_ISCHR(st.st_mode) && st.st_rdev == d;
}
static int fx_ioctl(int fd, unsigned long req, void *arg) {
    if (req == M11_DMA_HEAP_IOCTL_ALLOC) {
        m11_dma_heap_allocation_data *d = arg;
        if (!rdev_is(fd, makedev(1, 7))) { errno = EBADF; return -1; }
        int m = memfd_create("m19-spk-pool", MFD_CLOEXEC);
        if (m < 0 || ftruncate(m, (off_t)d->len) != 0) return -1;
        d->fd = (uint32_t)m;
        return 0;
    }
    if (req == M11_DMA_BUF_IOCTL_SYNC) return 0;
    if (req == M11_MSM_AUDIO_ION_MAP_PHYS || req == M11_MSM_AUDIO_ION_UNMAP)
        return rdev_is(fd, makedev(1, 3)) ? 0 : (errno = EBADF, -1);
    errno = ENOTTY;
    return -1;
}
static int fx_munmap(void *a, size_t l) { return munmap(a, l); }
static const m11_shmem_native_sys fx_sys = {fx_ioctl, mmap, fx_munmap, close};

/* ---------------- QRTR SERVREG + raw-PTY ADSP GPR responder ---------------- */
#define LOCAL_NODE 1u
#define LOCAL_PORT 0x4001u
#define PEER_NODE 5u
#define PEER_PORT 0x40u
static int qs[2] = {-1, -1};

struct peer_sync {
    unsigned reads_seen;
};
static struct peer_sync *g_peer_sync;
static m11_entry *g_active_entry;
static int g_peer_notify_w = -1;

static void sync_peer_reads(void) {
    if (!g_peer_sync || !g_active_entry) return;
    unsigned rd = g_active_entry->runner.link.reads;
    if (__atomic_load_n(&g_peer_sync->reads_seen, __ATOMIC_RELAXED) != rd) {
        __atomic_store_n(&g_peer_sync->reads_seen, rd, __ATOMIC_RELEASE);
        if (g_peer_notify_w >= 0) {
            ssize_t nw = write(g_peer_notify_w, "R", 1);
            (void)nw;
        }
    }
}

static void isolate_stdio_pipes(void) {
    for (int fd = 0; fd < 3; fd++) {
        int p[2];
        assert(pipe(p) == 0);
        int want = fd == 0 ? p[0] : p[1];
        if (want != fd) assert(dup2(want, fd) == fd);
        if (p[0] != fd) (void)close(p[0]);
        if (p[1] != fd) (void)close(p[1]);
    }
}

static void p16(unsigned char *p, uint16_t n) { p[0] = (unsigned char)n; p[1] = (unsigned char)(n >> 8); }
static void p32(unsigned char *p, uint32_t n) { p16(p, (uint16_t)n); p16(p + 2, (uint16_t)(n >> 16)); }
static uint16_t g16(const unsigned char *p) { return (uint16_t)(p[0] | (unsigned)p[1] << 8); }
static uint32_t g32(const unsigned char *p) { return (uint32_t)g16(p) | ((uint32_t)g16(p + 2) << 16); }

static int f_socket(void *u) { (void)u; return qs[0]; }
static int f_getsockname(void *u, int fd, uint32_t *n, uint32_t *p) {
    (void)u; assert(fd == qs[0]); *n = LOCAL_NODE; *p = LOCAL_PORT; return 0;
}
static int f_sendto(void *u, int fd, uint32_t node, uint32_t port, const void *b, size_t n) {
    (void)u;
    sync_peer_reads();
    unsigned char m[8 + 160];
    if (fd != qs[0] || n > 160) return -EINVAL;
    p32(m, node); p32(m + 4, port); memcpy(m + 8, b, n);
    return send(fd, m, n + 8, MSG_DONTWAIT) == (ssize_t)(n + 8) ? 0 : -EIO;
}
static ssize_t f_recvfrom(void *u, int fd, void *b, size_t cap, uint32_t *node, uint32_t *port) {
    (void)u;
    sync_peer_reads();
    unsigned char m[8 + 256];
    ssize_t r = recv(fd, m, sizeof m, MSG_DONTWAIT);
    if (r < 0) return errno == EAGAIN ? -EAGAIN : -errno;
    if (r < 8 || (size_t)(r - 8) > cap) return -EMSGSIZE;
    *node = g32(m); *port = g32(m + 4); memcpy(b, m + 8, (size_t)r - 8);
    return r - 8;
}
static int f_close(void *u, int fd) { (void)u; return close(fd) ? -errno : 0; }
static const m11_qrtr_sys fxq = {f_socket, f_getsockname, f_sendto, f_recvfrom, f_close, NULL};

enum pmode { P_UP, P_NEVER_UP };
struct adsp_cfg {
    enum pmode pm;
    int bad_re;
    unsigned wr_status_nth;
    int down_on_map;
    char journal_path[PATH_MAX];
};

static void q_send(int q, uint32_t node, uint32_t port, const unsigned char *b, size_t n) {
    unsigned char m[8 + 160];
    p32(m, node); p32(m + 4, port); memcpy(m + 8, b, n);
    if (send(q, m, n + 8, 0) != (ssize_t)(n + 8)) _exit(130);
}
static void q_ctrl(int q, uint32_t cmd, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    unsigned char m[20];
    p32(m, cmd); p32(m + 4, a); p32(m + 8, b); p32(m + 12, c); p32(m + 16, d);
    q_send(q, LOCAL_NODE, M11_PDS_CTRL_PORT, m, sizeof m);
}
static size_t tlv(unsigned char *b, unsigned char t, const void *v, size_t n) {
    b[0] = t; p16(b + 1, (uint16_t)n); memcpy(b + 3, v, n); return n + 3;
}
static void q_qmi(int q, unsigned char type, uint16_t txn, uint16_t id, unsigned char *b, size_t n) {
    b[0] = type; p16(b + 1, txn); p16(b + 3, id); p16(b + 5, (uint16_t)(n - 7));
    q_send(q, PEER_NODE, PEER_PORT, b, n);
}
static void q_down(int q) {
    unsigned char b[96] = {0}, s[4], t[2];
    p32(s, M11_PDS_DOWN); p16(t, 0x0102);
    size_t n = 7;
    n += tlv(b + n, 1, s, 4);
    n += tlv(b + n, 2, M11_PDS_PATH, sizeof(M11_PDS_PATH) - 1);
    n += tlv(b + n, 3, t, 2);
    q_qmi(q, 4, 0x0101, 0x22, b, n);
}
static void qrtr_in(int q, enum pmode pm) {
    unsigned char m[8 + 256];
    ssize_t r = recv(q, m, sizeof m, MSG_DONTWAIT);
    if (r < 8) return;
    uint32_t port = g32(m + 4);
    const unsigned char *pl = m + 8;
    size_t n = (size_t)r - 8;
    if (port == M11_PDS_CTRL_PORT) {
        if (n == 20 && g32(pl) == 10) {
            q_ctrl(q, 4, M11_PDS_SERVICE, M11_PDS_INSTANCE, PEER_NODE, PEER_PORT);
            q_ctrl(q, 4, 0, 0, 0, 0);
        }
        return;
    }
    if (port != PEER_PORT || n < 7) return;
    uint16_t txn = g16(pl + 1), id = g16(pl + 3);
    unsigned char b[64] = {0}, res[4] = {0}, st[4];
    if (id == 0x20 && n > 10 && pl[7] == 1 && pl[10] == 0) {
        size_t k = 7; k += tlv(b + k, 2, res, 4);
        q_qmi(q, 2, txn, 0x20, b, k);
    } else if (id == 0x20) {
        p32(st, pm != P_NEVER_UP ? M11_PDS_UP : M11_PDS_DOWN);
        size_t k = 7; k += tlv(b + k, 2, res, 4); k += tlv(b + k, 16, st, 4);
        q_qmi(q, 2, txn, 0x20, b, k);
    } else if (id == 0x23) {
        size_t k = 7; k += tlv(b + k, 2, res, 4);
        q_qmi(q, 2, txn, 0x23, b, k);
    }
}

static int journal_has(const char *jpath, const char *want) {
    static char seen[131072];
    int fd = open(jpath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, seen, sizeof seen - 1);
    (void)close(fd);
    if (n <= 0) return 0;
    seen[n] = '\0';
    return strstr(seen, want) != NULL;
}

static void pty_send(int pty_fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(pty_fd, p + done, len - done);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) _exit(128);
        done += (size_t)w;
    }
}

#define PKT_Q_CAP 64u
struct pkt_queue {
    struct {
        uint8_t bytes[160];
        size_t len;
    } items[PKT_Q_CAP];
    unsigned head;
    unsigned count;
    unsigned sent;
};

static void pq_push(struct pkt_queue *pq, const void *buf, size_t len) {
    if (!len || len > sizeof pq->items[0].bytes || pq->count >= PKT_Q_CAP) _exit(129);
    unsigned idx = (pq->head + pq->count) % PKT_Q_CAP;
    memcpy(pq->items[idx].bytes, buf, len);
    pq->items[idx].len = len;
    pq->count++;
}

static void pq_reply(struct pkt_queue *pq, const m11_gpr_hdr_t *h, uint32_t opcode, const void *pl, size_t n) {
    uint8_t tx[160];
    size_t txl = 0;
    if (m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0,
                               h->src_port, h->dst_port, h->token, opcode, pl, n) < 0)
        _exit(104);
    pq_push(pq, tx, txl);
}

static void pq_try_flush_one(struct pkt_queue *pq, int peer_pty, const struct peer_sync *sync) {
    if (peer_pty < 0 || pq->count == 0) return;
    if (__atomic_load_n(&sync->reads_seen, __ATOMIC_ACQUIRE) != pq->sent) return;
    pty_send(peer_pty, pq->items[pq->head].bytes, pq->items[pq->head].len);
    pq->head = (pq->head + 1u) % PKT_Q_CAP;
    pq->count--;
    pq->sent++;
}

static void peer_loop(int q, int ctl, int ack, int ntf, const struct peer_sync *sync, struct adsp_cfg ac) {
    int peer_pty = -1;
    uint8_t buf[8192];
    size_t len = 0;
    unsigned maps = 0, wr_seen = 0;
    uint32_t q12[2] = {0, 0};
    int read_ch = -1;
    struct pkt_queue pq;
    memset(&pq, 0, sizeof pq);

    for (;;) {
        pq_try_flush_one(&pq, peer_pty, sync);
        struct pollfd p[4] = {
            {.fd = q, .events = POLLIN},
            {.fd = ctl, .events = POLLIN},
            {.fd = ntf, .events = POLLIN},
            {.fd = peer_pty, .events = POLLIN},
        };
        int timeout_ms = (peer_pty >= 0 && pq.count > 0) ? 2 : -1;
        int n = poll(p, peer_pty >= 0 ? 4 : 3, timeout_ms);
        if (n < 0) { if (errno == EINTR) continue; _exit(120); }
        if (q >= 0 && (p[0].revents & POLLIN)) qrtr_in(q, ac.pm);
        if (q >= 0 && (p[0].revents & (POLLHUP | POLLERR | POLLNVAL))) q = -1;
        if (ntf >= 0 && (p[2].revents & POLLIN)) {
            char drain[64];
            while (read(ntf, drain, sizeof drain) > 0) {}
        }
        if (ntf >= 0 && (p[2].revents & (POLLHUP | POLLERR | POLLNVAL))) ntf = -1;
        if (p[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            char c[256];
            ssize_t r = read(ctl, c, sizeof c - 1);
            if (r <= 0) _exit(0);
            c[r] = '\0';
            if (c[0] == 'S') {
                struct termios t;
                peer_pty = open(c + 1, O_RDWR | O_NOCTTY | O_CLOEXEC);
                if (peer_pty < 0 || tcgetattr(peer_pty, &t)) _exit(121);
                cfmakeraw(&t);
                if (tcsetattr(peer_pty, TCSANOW, &t)) _exit(121);
            }
            if (write(ack, "k", 1) != 1) _exit(122);
        }
        if (peer_pty >= 0 && (p[3].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = read(peer_pty, buf + len, sizeof buf - len);
            if (r <= 0) { (void)close(peer_pty); peer_pty = -1; continue; }
            len += (size_t)r;
            while (len >= 4) {
                uint32_t w;
                memcpy(&w, buf, 4);
                size_t size = w >> 8;
                if (size < M11_GPR_HDR_BYTES || size > M11_GPR_MAX_PKT_BYTES) _exit(124);
                if (len < size) break;
                m11_gpr_hdr_t h;
                const uint8_t *pl = NULL;
                size_t pll = 0;
                if (m11_gpr_validate_packet(buf, size, &h, &pl, &pll) < 0) _exit(125);
                char want[48];
                FMT_CHK(want, "op=%08x tok=%08x", h.opcode, h.token);
                if (!journal_has(ac.journal_path, want)) _exit(110);

                if (h.opcode == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS || h.opcode == M11_APM_CMD_CLOSE_ALL ||
                    h.opcode == M11_DATA_CMD_WR_SH_MEM_EP_EOS)
                    _exit(108);

                if (h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
                    if (ac.down_on_map) {
                        q_down(q);
                    } else {
                        m11_apm_rsp_shared_mem_map_t rsp = {.mem_map_handle = 0xA0000001u + maps++};
                        pq_reply(&pq, &h, M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &rsp, sizeof rsp);
                    }
                } else if (h.opcode == M11_APM_CMD_GET_CFG) {
                    m11_aw_msg_kind_t kind = 0;
                    if (m11_aw_classify_cfg_pkt(buf, size, &kind, NULL, NULL) < 0 || kind != M11_AW_MSG_READ || read_ch < 0)
                        _exit(105);
                    uint8_t out[160];
                    size_t ol = 0;
                    uint32_t v = q12[read_ch] + (ac.bad_re ? 2048u : 0u);
                    read_ch = -1;
                    if (m11_aw_pack_read_rsp_pkt(out, sizeof out, &ol, h.src_port, h.token, 0u, 0u, 4u, v) < 0)
                        _exit(106);
                    pq_push(&pq, out, ol);
                } else if (h.opcode == M11_APM_CMD_SET_CFG && h.dst_port == 0x42D3u) {
                    m11_aw_msg_kind_t kind = 0;
                    uint32_t ch = 0, v = 0;
                    if (m11_aw_classify_cfg_pkt(buf, size, &kind, &ch, &v) < 0 || kind == M11_AW_MSG_READ || ch > 1)
                        _exit(107);
                    if (kind == M11_AW_MSG_WRITE) q12[ch] = v;
                    else read_ch = (int)ch;
                    m11_gpr_ibasic_rsp_t rsp = {.cmd_opcode = h.opcode, .status = 0};
                    pq_reply(&pq, &h, M11_GPR_IBASIC_RSP_RESULT, &rsp, sizeof rsp);
                } else if (h.opcode == M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2) {
                    uint32_t dw[8] = {0};
                    memcpy(dw, pl, 12);
                    if (ac.wr_status_nth && ++wr_seen == ac.wr_status_nth) dw[3] = 5;
                    pq_reply(&pq, &h, M11_DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE_V2, dw, sizeof dw);
                } else if (h.opcode == M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2) {
                    uint32_t dw[14] = {0};
                    pq_reply(&pq, &h, M11_DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE_V2, dw, sizeof dw);
                } else {
                    m11_gpr_ibasic_rsp_t rsp = {.cmd_opcode = h.opcode, .status = 0};
                    pq_reply(&pq, &h, M11_GPR_IBASIC_RSP_RESULT, &rsp, sizeof rsp);
                }
                memmove(buf, buf + size, len - size);
                len -= size;
            }
            pq_try_flush_one(&pq, peer_pty, sync);
        }
    }
}

struct peer_handle {
    int ctl_w;
    int ack_r;
    int notify_w;
    pid_t pid;
    struct peer_sync *sync;
};

static struct peer_handle start_peer(struct adsp_cfg ac) {
    int c[2], a[2], ntf[2];
    struct peer_sync *sync = mmap(NULL, sizeof *sync, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert(sync != MAP_FAILED);
    sync->reads_seen = 0;
    assert(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, qs) == 0);
    assert(pipe2(c, O_CLOEXEC) == 0 && pipe2(a, O_CLOEXEC) == 0);
    assert(pipe2(ntf, O_CLOEXEC | O_NONBLOCK) == 0);
    pid_t ppid = getpid();
    pid_t p = fork();
    assert(p >= 0);
    if (p == 0) {
        alarm(30);
        (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != ppid) _exit(0);
        (void)close(qs[0]);
        (void)close(c[1]);
        (void)close(a[0]);
        (void)close(ntf[1]);
        isolate_stdio_pipes();
        const int keep[3] = {c[0], a[1], ntf[0]};
        (void)m11_anchor_linux_close_unlisted(qs[1], keep, 3u);
        if (write(a[1], "r", 1) != 1) _exit(127);
        peer_loop(qs[1], c[0], a[1], ntf[0], sync, ac);
    }
    (void)close(qs[1]);
    (void)close(c[0]);
    (void)close(a[1]);
    (void)close(ntf[0]);
    char rdy = 0;
    assert(read(a[0], &rdy, 1) == 1 && rdy == 'r');
    g_peer_sync = sync;
    g_peer_notify_w = ntf[1];
    g_active_entry = NULL;
    return (struct peer_handle){.ctl_w = c[1], .ack_r = a[0], .notify_w = ntf[1], .pid = p, .sync = sync};
}

static void stop_peer(struct peer_handle *ph) {
    g_active_entry = NULL;
    g_peer_sync = NULL;
    g_peer_notify_w = -1;
    if (ph->ctl_w >= 0) { (void)close(ph->ctl_w); ph->ctl_w = -1; }
    if (ph->ack_r >= 0) { (void)close(ph->ack_r); ph->ack_r = -1; }
    if (ph->notify_w >= 0) { (void)close(ph->notify_w); ph->notify_w = -1; }
    if (ph->pid > 0) {
        (void)kill(ph->pid, SIGKILL);
        int st = 0;
        while (waitpid(ph->pid, &st, 0) < 0 && errno == EINTR) {}
        ph->pid = -1;
    }
    if (ph->sync && ph->sync != MAP_FAILED) {
        (void)munmap(ph->sync, sizeof *ph->sync);
        ph->sync = NULL;
    }
}

static void session_ready_handshake(void *user, m11_entry *e) {
    struct peer_handle *ph = user;
    g_active_entry = e;
    __atomic_store_n(&ph->sync->reads_seen, e->runner.link.reads, __ATOMIC_RELEASE);
    int fd = e->runner.cfg.endpoint->anchor_fd;
    char slave[128], msg[160];
    assert(unlockpt(fd) == 0 && ptsname_r(fd, slave, sizeof slave) == 0);
    int n = snprintf(msg, sizeof msg, "S%s", slave);
    assert(n > 0 && write(ph->ctl_w, msg, (size_t)n) == n);
    char k = 0;
    assert(read(ph->ack_r, &k, 1) == 1 && k == 'k');
}

/* ---------------- synthetic world builder ---------------- */
struct world {
    char root[512];
    char started[640], plan[640], plan_sha[640], report[640];
    char dev[640], holder_proc[640], sys[640], proc_devs[640];
    char cmdline[640], journal[640], panic[640];
    char ep[640], ion[640], cma[640], hdir[640], hnode[640];
    char proc_pcm[640], sys_sound[640], snd_dir[640];
    char sha_hex[65];
};

static const char *PROC_DEVS_OK =
    "Character devices:\n"
    "  1 msm_audio_ion\n"
    "  1 msm_audio_ion_cma\n"
    "  1 dma_heap\n"
    "  5 aud_pasthru_adsp\n"
    "116 alsa\n\n"
    "Block devices:\n"
    "  7 loop\n";

static const char *CMDLINE_OK = "console=ttyMSM0 iommu.strict=1 rdinit=/init\n";

static void make_world(struct world *w, const char *base, const char *tag) {
    static unsigned seq;
    memset(w, 0, sizeof *w);
    FMT_CHK(w->root, "%s/%s-%ld-%u", base, tag, (long)getpid(), seq++);
    assert(mkdir(w->root, 0700) == 0);

    put_text(w->root, "sys/class/aud_pasthru_adsp/aud_pasthru_adsp/dev", "5:2\n");
    put_text(w->root, "sys/dev/char/5:2/uevent", "MAJOR=5\nMINOR=2\nDEVNAME=aud_pasthru_adsp\n");
    put_text(w->root, "sys/class/msm_audio_ion/msm_audio_ion/dev", "1:3\n");
    put_text(w->root, "sys/dev/char/1:3/uevent", "MAJOR=1\nMINOR=3\nDEVNAME=msm_audio_ion\n");
    put_text(w->root, "sys/class/msm_audio_ion_cma/msm_audio_ion_cma/dev", "1:5\n");
    put_text(w->root, "sys/dev/char/1:5/uevent", "MAJOR=1\nMINOR=5\nDEVNAME=msm_audio_ion_cma\n");
    put_text(w->root, "sys/class/dma_heap/system/dev", "1:7\n");
    put_text(w->root, "sys/dev/char/1:7/uevent", "MAJOR=1\nMINOR=7\nDEVNAME=dma_heap/system\n");

    /* card0 container directory has no dev attribute; the three sound cdevs do */
    put_text(w->root, "sys/class/sound/card0/id", "ukeemtpsndcard\n");
    put_text(w->root, "sys/class/sound/controlC0/dev", "116:1\n");
    put_text(w->root, "sys/class/sound/pcmC0D32p/dev", "116:34\n");
    put_text(w->root, "sys/class/sound/pcmC0D33c/dev", "116:35\n");
    put_text(w->root, "proc/asound/pcm",
             "00-32: TDM-LPAIF-RX-TERTIARY-VIRT-2 m :  : playback 1\n"
             "00-33: TDM-LPAIF-TX-TERTIARY m :  : capture 1\n");
    put_text(w->root, "proc_devices", PROC_DEVS_OK);
    put_text(w->root, "cmdline", CMDLINE_OK);
    put_text(w->root, "journal", "");
    put_text(w->root, "panic", "0\n");

    FMT_CHK(w->dev, "%s/dev", w->root);
    FMT_CHK(w->holder_proc, "%s/holder-proc", w->root);
    assert(mkdir(w->dev, 0755) == 0 && chmod(w->dev, 0755) == 0);
    assert(mkdir(w->holder_proc, 0755) == 0);
    /* clean non-audio process entry in holder-proc */
    put_text(w->root, "holder-proc/100/comm", "systemd\n");
    char reg_fd_dir[768], reg_link[896], reg_target[768];
    FMT_CHK(reg_fd_dir, "%s/100/fd", w->holder_proc);
    assert(mkdir(reg_fd_dir, 0755) == 0);
    FMT_CHK(reg_target, "%s/panic", w->root);
    FMT_CHK(reg_link, "%s/3", reg_fd_dir);
    assert(symlink(reg_target, reg_link) == 0);

    write_plan_files(w->root, 500u, -10000, 8u, w->sha_hex);

    FMT_CHK(w->started, "%s/speaker.started", w->root);
    FMT_CHK(w->plan, "%s/speaker/plan.bin", w->root);
    FMT_CHK(w->plan_sha, "%s/speaker/plan.sha256", w->root);
    FMT_CHK(w->report, "%s/speaker.report", w->root);
    FMT_CHK(w->sys, "%s/sys", w->root);
    FMT_CHK(w->proc_devs, "%s/proc_devices", w->root);
    FMT_CHK(w->cmdline, "%s/cmdline", w->root);
    FMT_CHK(w->journal, "%s/journal", w->root);
    FMT_CHK(w->panic, "%s/panic", w->root);
    FMT_CHK(w->ep, "%s/dev/ep_node", w->root);
    FMT_CHK(w->ion, "%s/dev/ion_node", w->root);
    FMT_CHK(w->cma, "%s/dev/cma_node", w->root);
    FMT_CHK(w->hdir, "%s/dev/heap", w->root);
    FMT_CHK(w->hnode, "%s/dev/heap/system", w->root);
    FMT_CHK(w->proc_pcm, "%s/proc/asound/pcm", w->root);
    FMT_CHK(w->sys_sound, "%s/sys/class/sound", w->root);
    FMT_CHK(w->snd_dir, "%s/dev/priv-snd", w->root);
}

static struct m19_speaker_config cfg_for_world(const struct world *w) {
    struct m19_speaker_config c = m19_speaker_config_default();
    c.started_path = w->started;
    c.plan_path = w->plan;
    c.plan_sha_path = w->plan_sha;
    c.report_path = w->report;
    c.dev_root = w->dev;
    c.proc_root = "/proc";
    c.holder_proc_root = w->holder_proc;
    c.sys_root = w->sys;
    c.proc_devices = w->proc_devs;
    c.cmdline_path = w->cmdline;
    c.journal_path = w->journal;
    c.panic_path = w->panic;
    c.endpoint_node = w->ep;
    c.ion_node = w->ion;
    c.ion_cma_node = w->cma;
    c.heap_dir = w->hdir;
    c.heap_node = w->hnode;
    c.spawner_bin = "/bin/true";
    c.snd_paths = (m11_snd_paths){w->proc_pcm, w->sys_sound, w->snd_dir, 0};
    c.qrtr = &fxq;
    c.shmem_sys = &fx_sys;
    c.snd_sys = &asys;
    c.require_root = geteuid() == 0;
    c.spawner_require_drop = geteuid() == 0;
    c.journal_require_kmsg = 0;
    c.cdev_require_minor0 = 0;
    c.heap_require_kernel_fs = 0;
    c.journal_rotate = 9u;
    c.pool_count = 2u;
    c.pool_len = 65536u;
    c.pool_base = 200;
    c.pd_ready_budget_ms = 300u;
    c.timeout_ms = 400u;
    c.recovery_budget_ms = 1200u;
    c.hold_idle_ms = 50u;
    c.wait_timeout_ms = 400u;
    c.amp_window_ms = 5000u;
    c.write_buffers = 4u;
    c.buffer_ms = 40u;
    c.boot_epoch = 55u;
    c.return_from_hold = 1;
    return c;
}

/* ---------------- unprivileged prechecks ---------------- */
static void test_session_qualification_gates(void) {
    m11_speaker_plan plan;
    m11_speaker_report rep;
    memset(&plan, 0, sizeof plan);
    memset(&rep, 0, sizeof rep);

    plan.volume_level = 8u;
    plan.duration_ms = 4000u;
    plan.pcm.len = 768000u;

    rep.stage = M11_SPK_PLAYED;
    rep.fail_step = 0;
    rep.rc = 0;
    rep.regions_mapped = 2u;
    rep.re.pair_re_readback_verified = 1;
    rep.re.ch[0].readback_q12 = 26099u;
    rep.re.ch[1].readback_q12 = 28684u;
    rep.buffers_sent = 100u;
    rep.buffers_done = 100u;
    rep.bytes_played = 768000u;
    rep.amp_on = 1;
    rep.amp_off_verified = 1;
    rep.teardown_rc = 0;
    rep.pdr_seen = 0;

    const int act = (int)M11_TERMINAL_RESET_RETAINING_ANCHORS;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 1);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, NULL, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, NULL, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_SESSION, 0, 0, 1, 0, &plan, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 1, 0, 1, 0, &plan, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, -EIO, 1, 0, &plan, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 0, 0, &plan, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, -EIO, &plan, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &rep, -1, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &rep, 0, 1u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &rep, 0, 0u, 0, act, 2u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &rep, 0, 0u, 1, 0, 2u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &rep, 0, 0u, 1, act, 1u, 4u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &rep, 0, 0u, 1, act, 2u, 3u, 1, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &rep, 0, 0u, 1, act, 2u, 4u, 0, 2u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &rep, 0, 0u, 1, act, 2u, 4u, 1, 1u, 0) == 0);
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 1) == 0);

    m11_speaker_report r2;
    r2 = rep; r2.stage = 0;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.fail_step = 1;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.rc = -EIO;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.regions_mapped = 1u;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.re.pair_re_readback_verified = 0;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.re.ch[0].readback_q12 = 0u;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.re.ch[1].readback_q12 = 0u;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.buffers_sent = 0u; r2.buffers_done = 0u;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.buffers_done = 99u;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.bytes_played = plan.pcm.len - 4u;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.amp_on = 0;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.amp_off_verified = 0;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.teardown_rc = -EIO;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    r2 = rep; r2.pdr_seen = 1;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &plan, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);

    m11_speaker_plan p2;
    p2 = plan; p2.volume_level = 0u;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &p2, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    p2 = plan; p2.volume_level = 9u;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &p2, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    p2 = plan; p2.duration_ms = 0u;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &p2, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    p2 = plan; p2.duration_ms = 5001u;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &p2, &rep, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
    p2 = plan; p2.pcm.len = 0u; r2 = rep; r2.bytes_played = 0u;
    assert(m19_speaker_qualify_session(M11_ENTRY_END, 0, 0, 1, 0, &p2, &r2, 0, 0u, 1, act, 2u, 4u, 1, 2u, 0) == 0);
}
static void test_defaults_and_cfg_bounds(const char *base) {
    struct m19_speaker_config d = m19_speaker_config_default();
    assert(!strcmp(d.started_path, "/run/m19/speaker.started"));
    assert(!strcmp(d.plan_path, "/run/m19/speaker/plan.bin"));
    assert(!strcmp(d.plan_sha_path, "/run/m19/speaker/plan.sha256"));
    assert(!strcmp(d.report_path, "/run/m19/speaker.report"));
    assert(!strcmp(d.dev_root, "/dev") && !strcmp(d.proc_root, "/proc") && !strcmp(d.holder_proc_root, "/proc"));
    assert(!strcmp(d.sys_root, "/sys") && !strcmp(d.proc_devices, "/proc/devices"));
    assert(!strcmp(d.cmdline_path, "/proc/cmdline") && !strcmp(d.journal_path, "/dev/kmsg"));
    assert(!strcmp(d.endpoint_node, "/dev/aud_pasthru_adsp"));
    assert(!strcmp(d.ion_node, "/dev/msm_audio_ion"));
    assert(!strcmp(d.ion_cma_node, "/dev/msm_audio_ion_cma"));
    assert(!strcmp(d.heap_dir, "/dev/m11-heap") && !strcmp(d.heap_node, "/dev/m11-heap/system"));
    assert(!strcmp(d.snd_paths.dir, "/dev/m11-snd") && d.snd_paths.card == 0u);
    assert(d.require_root == 1 && d.spawner_require_drop == 1 && d.journal_require_kmsg == 1);
    assert(d.cdev_require_minor0 == 1 && d.heap_require_kernel_fs == 1);
    assert(d.journal_rotate == 9u && d.pool_count == 2u && d.pool_len == 65536u && d.pool_base == 200);
    assert(d.pd_ready_budget_ms == 10000u && d.return_from_hold == 0);

    struct world w;
    make_world(&w, base, "cfg");
    assert(m19_speaker_run(NULL) == -EINVAL);
    struct m19_speaker_config bad = cfg_for_world(&w);
    bad.pool_count = 1u;
    assert(m19_speaker_run(&bad) == -EINVAL);
    bad = cfg_for_world(&w); bad.pool_len = 2048u;
    assert(m19_speaker_run(&bad) == -EINVAL);
    bad = cfg_for_world(&w); bad.pd_ready_budget_ms = 10001u;
    assert(m19_speaker_run(&bad) == -EINVAL);
    bad = cfg_for_world(&w); bad.journal_rotate = 10u;
    assert(m19_speaker_run(&bad) == -EINVAL);
    bad = cfg_for_world(&w); bad.write_buffers = 9u;
    assert(m19_speaker_run(&bad) == -EINVAL);
    bad = cfg_for_world(&w); bad.buffer_ms = 5u;
    assert(m19_speaker_run(&bad) == -EINVAL);
    assert(path_is_absent(w.started) && path_is_absent(w.report));
    clean_dir(w.root);
}

static void test_single_run_lock(const char *base) {
    struct world w;
    make_world(&w, base, "lock");
    put_text(w.root, "speaker.started", "999\n");
    put_text(w.root, "speaker.report", "ok=1\nsentinel=keep\n");
    struct m19_speaker_config c = cfg_for_world(&w);
    assert(m19_speaker_run(&c) == -EALREADY);
    char rep[256];
    slurp(w.report, rep, sizeof rep);
    assert(!strcmp(rep, "ok=1\nsentinel=keep\n"));

    /* symlink at started_path is also refused without overwriting target */
    assert(unlink(w.started) == 0);
    char target[768];
    FMT_CHK(target, "%s/target", w.root);
    put_text(w.root, "target", "untouched\n");
    assert(symlink(target, w.started) == 0);
    int rc = m19_speaker_run(&c);
    assert(rc < 0 && rc != 0);
    slurp(target, rep, sizeof rep);
    assert(!strcmp(rep, "untouched\n"));
    clean_dir(w.root);
}

static void test_dev_clean_checks(const char *base) {
    const char *dirty_rels[] = {
        "dev/ep_node", "dev/ion_node", "dev/cma_node", "dev/heap/system", "dev/priv-snd/x", "dev/snd/pcmC0D0p"
    };
    for (size_t i = 0; i < sizeof dirty_rels / sizeof dirty_rels[0]; i++) {
        struct world w;
        make_world(&w, base, "dirty");
        put_text(w.root, dirty_rels[i], "x");
        struct m19_speaker_config c = cfg_for_world(&w);
        assert(m19_speaker_run(&c) == -EEXIST);
        char rep[2048];
        slurp(w.report, rep, sizeof rep);
        assert(kv_long(rep, "ok") == 0 && kv_long(rep, "entry_phase") == 0);
        assert(kv_long(rep, "fail_step") == M19_SPK_PRE_DEV && kv_long(rep, "rc") == -EEXIST);
        clean_dir(w.root);
    }

    /* Live symlink inside /dev/snd/by-path also fails M19_SPK_PRE_DEV */
    struct world w;
    make_world(&w, base, "livesym");
    char sndd[768], bypath[896], linkp[1024];
    FMT_CHK(bypath, "%s/snd/by-path", w.dev);
    assert(mkdir(w.dev, 0755) == -1 && errno == EEXIST);
    FMT_CHK(sndd, "%s/snd", w.dev);
    assert(mkdir(sndd, 0755) == 0 && mkdir(bypath, 0755) == 0);
    FMT_CHK(linkp, "%s/live", bypath);
    assert(symlink(w.panic, linkp) == 0);
    struct m19_speaker_config c = cfg_for_world(&w);
    assert(m19_speaker_run(&c) == -EEXIST);
    clean_dir(w.root);
}

static void test_foreign_holder_checks(const char *base) {
    struct stat ur;
    assert(stat("/dev/urandom", &ur) == 0 && S_ISCHR(ur.st_mode));
    char dev_txt[32];
    FMT_CHK(dev_txt, "%u:%u\n", major(ur.st_rdev), minor(ur.st_rdev));

    /* 1. Foreign holder of an ALSA PCM char device in holder-proc -> -EBUSY at M19_SPK_PRE_HOLDERS */
    struct world w;
    make_world(&w, base, "holder-alsa");
    put_text(w.root, "sys/class/sound/pcmC0D32p/dev", dev_txt);
    /* Empty /dev/snd/by-path + dangling udev symlink is allowed by check_dev_clean */
    char sndd[768], bypath[896], dlink[1024];
    FMT_CHK(sndd, "%s/snd", w.dev);
    FMT_CHK(bypath, "%s/by-path", sndd);
    FMT_CHK(dlink, "%s/platform-sound", bypath);
    assert(mkdir(sndd, 0755) == 0 && mkdir(bypath, 0755) == 0);
    assert(symlink("../controlC0", dlink) == 0);

    char pdir[768], fddir[896], fdlink[1024];
    FMT_CHK(pdir, "%s/4242", w.holder_proc);
    FMT_CHK(fddir, "%s/fd", pdir);
    FMT_CHK(fdlink, "%s/7", fddir);
    assert(mkdir(pdir, 0755) == 0 && mkdir(fddir, 0755) == 0);
    assert(symlink("/dev/urandom", fdlink) == 0);

    struct m19_speaker_config c = cfg_for_world(&w);
    assert(m19_speaker_run(&c) == -EBUSY);
    char rep[2048];
    slurp(w.report, rep, sizeof rep);
    assert(kv_long(rep, "ok") == 0 && kv_long(rep, "entry_phase") == 0);
    assert(kv_long(rep, "fail_step") == M19_SPK_PRE_HOLDERS && kv_long(rep, "rc") == -EBUSY);
    clean_dir(w.root);

    /* 2. Foreign holder of aud_pasthru_adsp -> -EBUSY at M19_SPK_PRE_HOLDERS */
    make_world(&w, base, "holder-ep");
    put_text(w.root, "sys/class/aud_pasthru_adsp/aud_pasthru_adsp/dev", dev_txt);
    char uev_rel[128], uev_body[128], pdevs[320];
    FMT_CHK(uev_rel, "sys/dev/char/%u:%u/uevent", major(ur.st_rdev), minor(ur.st_rdev));
    FMT_CHK(uev_body, "MAJOR=%u\nMINOR=%u\nDEVNAME=aud_pasthru_adsp\n", major(ur.st_rdev), minor(ur.st_rdev));
    put_text(w.root, uev_rel, uev_body);
    FMT_CHK(pdevs,
            "Character devices:\n  1 msm_audio_ion\n  1 msm_audio_ion_cma\n  1 dma_heap\n%3u aud_pasthru_adsp\n\nBlock devices:\n  7 loop\n",
            major(ur.st_rdev));
    put_text(w.root, "proc_devices", pdevs);
    FMT_CHK(pdir, "%s/5150", w.holder_proc);
    FMT_CHK(fddir, "%s/fd", pdir);
    FMT_CHK(fdlink, "%s/4", fddir);
    assert(mkdir(pdir, 0755) == 0 && mkdir(fddir, 0755) == 0);
    assert(symlink("/dev/urandom", fdlink) == 0);
    c = cfg_for_world(&w);
    assert(m19_speaker_run(&c) == -EBUSY);
    clean_dir(w.root);

    /* 3. Fewer than 3 sound cdevs in /sys/class/sound -> -ENODEV at M19_SPK_PRE_HOLDERS */
    make_world(&w, base, "holder-short");
    char pcm33[768];
    FMT_CHK(pcm33, "%s/pcmC0D33c/dev", w.sys_sound);
    assert(unlink(pcm33) == 0);
    c = cfg_for_world(&w);
    assert(m19_speaker_run(&c) == -ENODEV);
    slurp(w.report, rep, sizeof rep);
    assert(kv_long(rep, "fail_step") == M19_SPK_PRE_HOLDERS && kv_long(rep, "rc") == -ENODEV);
    clean_dir(w.root);
}

static void assert_plan_refused(struct world *w) {
    struct m19_speaker_config c = cfg_for_world(w);
    int rc = m19_speaker_run(&c);
    assert(rc < 0);
    char rep[2048];
    slurp(w->report, rep, sizeof rep);
    assert(kv_long(rep, "ok") == 0 && kv_long(rep, "entry_phase") == 0);
    assert(kv_long(rep, "fail_step") == M19_SPK_PRE_PLAN && kv_long(rep, "rc") == rc);
}

static void test_plan_verification(const char *base) {
    struct world w;

    /* 1. Wrong SHA256 */
    make_world(&w, base, "plan-badsha");
    put_text(w.root, "speaker/plan.sha256", "0000000000000000000000000000000000000000000000000000000000000000  plan.bin\n");
    assert_plan_refused(&w);
    clean_dir(w.root);

    /* 2. Uppercase hex in plan.sha256 */
    make_world(&w, base, "plan-upper");
    char upper[80];
    FMT_CHK(upper, "%s  plan.bin\n", w.sha_hex);
    for (int i = 0; i < 64; i++) if (upper[i] >= 'a' && upper[i] <= 'f') upper[i] = (char)(upper[i] - 'a' + 'A');
    put_text(w.root, "speaker/plan.sha256", upper);
    assert_plan_refused(&w);
    clean_dir(w.root);

    /* 3. Symlink plan.bin */
    make_world(&w, base, "plan-sym");
    char copy_p[768];
    FMT_CHK(copy_p, "%s/plan.copy", w.root);
    assert(rename(w.plan, copy_p) == 0 && symlink(copy_p, w.plan) == 0);
    assert_plan_refused(&w);
    clean_dir(w.root);

    /* 4. Corrupt magic with matching SHA256 */
    make_world(&w, base, "plan-magic");
    size_t len = build_plan_custom(500u, -10000, 8u);
    plan_buf[0] ^= 0xffu;
    char hex[65], line[80];
    sha_hex_of(plan_buf, len, hex);
    FMT_CHK(line, "%s  plan.bin\n", hex);
    put_bytes(w.root, "speaker/plan.bin", plan_buf, len);
    put_text(w.root, "speaker/plan.sha256", line);
    assert_plan_refused(&w);
    clean_dir(w.root);

    /* 5. duration_ms > 5000 (5001 ms) with matching SHA256 */
    make_world(&w, base, "plan-dur");
    write_plan_files(w.root, 5001u, -10000, 8u, NULL);
    assert_plan_refused(&w);
    clean_dir(w.root);

    /* 6. peak_mdbfs > -10000 (-9999 mdBFS) with matching SHA256 */
    make_world(&w, base, "plan-peak");
    write_plan_files(w.root, 500u, -9999, 8u, NULL);
    assert_plan_refused(&w);
    clean_dir(w.root);

    /* 7. volume_level > 8 (9) and volume_level == 0 with matching SHA256 */
    make_world(&w, base, "plan-vol9");
    write_plan_files(w.root, 500u, -10000, 9u, NULL);
    assert_plan_refused(&w);
    clean_dir(w.root);

    make_world(&w, base, "plan-vol0");
    write_plan_files(w.root, 500u, -10000, 0u, NULL);
    assert_plan_refused(&w);
    clean_dir(w.root);
}

static void run_early_entry_child(struct world *w, int require_kmsg, enum pmode pm) {
    fflush(stdout);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        alarm(20);
        isolate_stdio_pipes();
        struct adsp_cfg ac = {.pm = pm};
        FMT_CHK(ac.journal_path, "%s", w->journal);
        struct peer_handle ph = start_peer(ac);
        struct m19_speaker_config c = cfg_for_world(w);
        c.journal_require_kmsg = require_kmsg;
        c.pd_ready_budget_ms = 120u;
        int rc = m19_speaker_run(&c);
        stop_peer(&ph);
        _exit(rc == -ECANCELED ? 0 : 91);
    }
    int st = 0;
    assert(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static void test_preboot_entry_refusals(const char *base) {
    struct world w;
    char rep[2048], jbuf[8192];

    /* 1. journal_require_kmsg = 1 on regular file -> entry_phase=0, fail_step=2, rc=-ENODEV */
    make_world(&w, base, "entry-kmsg");
    run_early_entry_child(&w, 1, P_UP);
    slurp(w.report, rep, sizeof rep);
    assert(kv_long(rep, "ok") == 0 && kv_long(rep, "entry_phase") == 0 && kv_long(rep, "fail_step") == 2);
    assert(kv_long(rep, "anchors_held") == 0 && kv_long(rep, "anchor_fds_open") == 0);
    clean_dir(w.root);

    /* 2. Non-strict /proc/cmdline -> entry_phase=1 (M11_ENTRY_JOURNAL), fail_step=3, reboot refused */
    make_world(&w, base, "entry-cmdline");
    put_text(w.root, "cmdline", "console=ttyMSM0 iommu.passthrough=1\n");
    run_early_entry_child(&w, 0, P_UP);
    slurp(w.report, rep, sizeof rep);
    slurp(w.journal, jbuf, sizeof jbuf);
    assert(kv_long(rep, "ok") == 0 && kv_long(rep, "entry_phase") == 1 && kv_long(rep, "fail_step") == 3);
    assert(kv_long(rep, "anchors_held") == 0 && kv_long(rep, "anchor_fds_open") == 0);
    assert(strstr(jbuf, "phase=reboot_failed rc=-1\n") != NULL);
    assert(strstr(jbuf, "<6>M19SPK v=1 ") != NULL);
    assert(path_is_absent(w.ep) && path_is_absent(w.ion) && path_is_absent(w.snd_dir));
    clean_dir(w.root);

    /* 3. SERVREG PD never UP -> entry_phase=2 (M11_ENTRY_CMDLINE), fail_step=4, reboot refused */
    make_world(&w, base, "entry-pddown");
    run_early_entry_child(&w, 0, P_NEVER_UP);
    slurp(w.report, rep, sizeof rep);
    slurp(w.journal, jbuf, sizeof jbuf);
    assert(kv_long(rep, "ok") == 0 && kv_long(rep, "entry_phase") == 2 && kv_long(rep, "fail_step") == 4);
    assert(kv_long(rep, "anchors_held") == 0 && kv_long(rep, "anchor_fds_open") == 0);
    assert(strstr(jbuf, "phase=reboot_failed rc=-1\n") != NULL);
    assert(path_is_absent(w.ep) && path_is_absent(w.ion) && path_is_absent(w.snd_dir));
    clean_dir(w.root);
}

/* ---------------- root end-to-end session cases ---------------- */
static int count_open_fds_self(void) {
    int n = 0;
    for (int fd = 0; fd < 512; fd++) {
        if (fcntl(fd, F_GETFD) != -1) n++;
    }
    return n;
}

static int ev_first(const char *s) {
    for (unsigned i = 0; i < nev; i++) if (!strcmp(ev[i], s)) return (int)i;
    return -1;
}
static int ev_last(const char *s) {
    for (unsigned i = nev; i-- > 0;) if (!strcmp(ev[i], s)) return (int)i;
    return -1;
}

static void run_root_session_case(const char *base, const char *tag, struct adsp_cfg ac, int want_ok) {
    struct world w;
    make_world(&w, base, tag);
    /* Dangling udev symlink inside /dev/snd/by-path must not block session bring-up */
    char sndd[768], bypath[896], dlink[1024];
    FMT_CHK(sndd, "%s/snd", w.dev);
    FMT_CHK(bypath, "%s/by-path", sndd);
    FMT_CHK(dlink, "%s/platform-sound", bypath);
    assert(mkdir(sndd, 0755) == 0 && mkdir(bypath, 0755) == 0 && symlink("../controlC0", dlink) == 0);

    int ev_pipe[2];
    assert(pipe2(ev_pipe, O_CLOEXEC) == 0);
    fflush(stdout);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        alarm(30);
        (void)close(ev_pipe[0]);
        isolate_stdio_pipes();
        assert(unshare(CLONE_NEWNS) == 0);
        assert(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0);
        char pts[768];
        FMT_CHK(pts, "%s/pts", w.dev);
        assert(mkdir(pts, 0755) == 0 && mount("/dev/pts", pts, NULL, MS_BIND, NULL) == 0);

        nev = 0;
        a_next = 0;
        memset(nodes, 0, sizeof nodes);
        memset(afd, 0, sizeof afd);
        memset(elem_value, 0, sizeof elem_value);
        elem_value[2] = elem_value[3] = 1; /* start at Voice; session switches to Music */

        FMT_CHK(ac.journal_path, "%s", w.journal);
        struct peer_handle ph = start_peer(ac);

        struct m19_speaker_config c = cfg_for_world(&w);
        c.session_ready_fn = session_ready_handshake;
        c.session_ready_user = &ph;
        int rc = m19_speaker_run(&c);
        stop_peer(&ph);
        (void)umount2(pts, MNT_DETACH);

        /* Verify no ALSA fds or private nodes remain, while pool + anchor fds remain open */
        for (int k = 0; k < 8; k++) assert(!afd[k].open);
        for (int i = 0; i < 8; i++) assert(!nodes[i].live);
        assert(path_is_absent(w.snd_dir));
        assert(path_is_absent(w.ep) && path_is_absent(w.ion) && path_is_absent(w.cma) && path_is_absent(w.hdir));
        for (int pfd = 200; pfd < 204; pfd++) assert(fcntl(pfd, F_GETFD) != -1);
        assert(count_open_fds_self() >= 8);

        /* Ship ALSA event log to parent before exiting */
        for (unsigned i = 0; i < nev; i++) {
            char line[64];
            int ln = snprintf(line, sizeof line, "%s\n", ev[i]);
            assert(ln > 0 && write(ev_pipe[1], line, (size_t)ln) == ln);
        }
        (void)close(ev_pipe[1]);

        if (want_ok) _exit(rc == 0 ? 0 : 81);
        _exit(rc == -ECANCELED ? 0 : 82);
    }
    (void)close(ev_pipe[1]);
    nev = 0;
    char ebuf[8192];
    size_t egot = 0;
    while (egot + 1 < sizeof ebuf) {
        ssize_t r = read(ev_pipe[0], ebuf + egot, sizeof ebuf - 1 - egot);
        assert(r >= 0);
        if (!r) break;
        egot += (size_t)r;
    }
    (void)close(ev_pipe[0]);
    ebuf[egot] = '\0';
    for (char *l = ebuf; *l;) {
        char *nl = strchr(l, '\n');
        if (!nl) break;
        *nl = '\0';
        evlog(l);
        l = nl + 1;
    }

    int st = 0;
    assert(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    char rep[4096], jbuf[131072], got_sha[80];
    slurp(w.report, rep, sizeof rep);
    slurp(w.journal, jbuf, sizeof jbuf);
    kv_str(rep, "plan_sha256", got_sha, sizeof got_sha);
    assert(!strcmp(got_sha, w.sha_hex));
    assert(kv_long(rep, "entry_phase") == M11_ENTRY_END);
    assert(kv_long(rep, "terminal_action") == (long)M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(kv_long(rep, "anchors_held") == 2 && kv_long(rep, "anchor_fds_open") == 4);
    assert(kv_long(rep, "pool_held") == 1);
    assert(kv_long(rep, "unmap_attempted") == 0);
    assert(kv_long(rep, "resources_busy") == 1);
    assert(strstr(jbuf, "op=0100100d") == NULL && strstr(jbuf, "op=01001005") == NULL);

    if (want_ok) {
        assert(kv_long(rep, "ok") == 1);
        assert(kv_long(rep, "fail_step") == 0 && kv_long(rep, "rc") == 0 && kv_long(rep, "session_rc") == 0);
        assert(kv_long(rep, "spk_stage") == M11_SPK_PLAYED && kv_long(rep, "spk_fail_step") == 0);
        assert(kv_long(rep, "regions_mapped") == 2 && kv_long(rep, "regions_in_pool") == 2);
        assert(kv_long(rep, "re_verified") == 1 && kv_long(rep, "re0_q12") == 26099 && kv_long(rep, "re1_q12") == 28684);
        assert(kv_long(rep, "volume_level") == 8 && kv_long(rep, "duration_ms") == 500 && kv_long(rep, "pcm_bytes") == 96000);
        assert(kv_long(rep, "buffers_sent") == 13 && kv_long(rep, "buffers_done") == 13 && kv_long(rep, "bytes_played") == 96000);
        assert(kv_long(rep, "amp_on") == 1 && kv_long(rep, "amp_off_verified") == 1);
        assert(kv_long(rep, "teardown_rc") == 0 && kv_long(rep, "pdr_seen") == 0);
        assert(kv_long(rep, "census_rc") == 0 && kv_long(rep, "census_why") == 0);
        assert(kv_long(rep, "ctl_writes") >= 6 && kv_long(rep, "ctl_readbacks") >= 6);
        assert(kv_long(rep, "ack_deferred") == 0);
        /* ALSA order: Disable -> backend hw/prepare -> Enable -> Disable -> backend drop */
        int dis0 = ev_first("sw0=Disable"), dis1 = ev_first("sw1=Disable");
        int rx_hw = ev_first("rx_hw"), tx_hw = ev_first("tx_hw");
        int en0 = ev_first("sw0=Enable"), en1 = ev_first("sw1=Enable");
        int off0 = ev_last("sw0=Disable"), off1 = ev_last("sw1=Disable");
        int rx_drop = ev_first("rx_drop"), tx_drop = ev_first("tx_drop");
        assert(dis0 >= 0 && dis1 >= 0 && dis0 < tx_hw && dis1 < rx_hw);
        assert(en0 > rx_hw && en1 > rx_hw);
        assert(off0 > en0 && off1 > en1);
        assert(rx_drop > off0 && rx_drop > off1 && tx_drop > off0 && tx_drop > off1);
        assert(strstr(jbuf, "<6>M11SPK v=1 boot=55 phase=spk plan ") != NULL);
        assert(strstr(jbuf, "<6>M11TERMINAL v=2 boot=55 action=RESET_RETAINING_ANCHORS end=pid1_exit ") != NULL);
        assert(strstr(jbuf, "<6>M19SPK v=1 boot=55 ok=1 ") != NULL);
    } else if (ac.bad_re) {
        assert(kv_long(rep, "ok") == 0);
        assert(kv_long(rep, "re_verified") == 0);
        assert(kv_long(rep, "amp_on") == 0);
        assert(ev_first("sw0=Enable") < 0 && ev_first("sw1=Enable") < 0);
    } else if (ac.wr_status_nth) {
        assert(kv_long(rep, "ok") == 0);
        assert(kv_long(rep, "amp_on") == 1 && kv_long(rep, "amp_off_verified") == 1);
        assert(kv_long(rep, "bytes_played") < kv_long(rep, "pcm_bytes"));
        int off0 = ev_last("sw0=Disable"), off1 = ev_last("sw1=Disable");
        int rx_drop = ev_first("rx_drop"), tx_drop = ev_first("tx_drop");
        assert(off0 > ev_first("sw0=Enable") && off1 > ev_first("sw1=Enable"));
        assert(rx_drop > off0 && tx_drop > off1);
    } else if (ac.down_on_map) {
        assert(kv_long(rep, "ok") == 0);
        assert(kv_long(rep, "amp_on") == 0);
        assert(kv_long(rep, "ack_deferred") == 1);
        assert(ev_first("sw0=Enable") < 0 && ev_first("sw1=Enable") < 0);
    }

    clean_dir(w.root);
}

int main(int argc, char **argv) {
    struct rlimit rl = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &rl);
    sigset_t empty;
    sigemptyset(&empty);
    (void)sigprocmask(SIG_SETMASK, &empty, NULL);
    alarm(60);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    if (argc != 3) {
        fprintf(stderr, "usage: test-speaker <scan-snd|prechecks|session> <path>\n");
        return 2;
    }
    if (!strcmp(argv[1], "scan-snd")) {
        printf("%d\n", m19_speaker_scan_snd(argv[2]));
        return 0;
    }
    if (!strcmp(argv[1], "prechecks")) {
        test_session_qualification_gates();
        test_defaults_and_cfg_bounds(argv[2]);
        test_single_run_lock(argv[2]);
        test_dev_clean_checks(argv[2]);
        test_foreign_holder_checks(argv[2]);
        test_plan_verification(argv[2]);
        test_preboot_entry_refusals(argv[2]);
        puts("PASS m19-speaker prechecks");
        return 0;
    }
    if (!strcmp(argv[1], "session")) {
        if (geteuid() != 0) {
            fprintf(stderr, "test-speaker session requires root\n");
            return 3;
        }
        run_root_session_case(argv[2], "happy", (struct adsp_cfg){.pm = P_UP}, 1);
        run_root_session_case(argv[2], "badre", (struct adsp_cfg){.pm = P_UP, .bad_re = 1}, 0);
        run_root_session_case(argv[2], "wrerr", (struct adsp_cfg){.pm = P_UP, .wr_status_nth = 2}, 0);
        run_root_session_case(argv[2], "pdrdown", (struct adsp_cfg){.pm = P_UP, .down_on_map = 1}, 0);
        puts("PASS m19-speaker root session");
        return 0;
    }
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}
