/* M19 R6 marble-sink, the desktop sound server's speaker end (sink.h). Generated from R5b's speaker.c: the same
 * entry, checks, report and hold; the session runs stream.c after the chord. */
#ifndef M11_CUSTODIAN_NATIVE
#error "m19 sink requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#define _GNU_SOURCE
#include "sink.h"
#include <signal.h>
#include "../unlock/core.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_AUDIO_RDEVS 128u

struct speaker_ctx {
    struct m19_sink_config cfg;
    const char *spawner_argv[2];
    const char *const *spawner_jobs[1];
    uint8_t plan_buf[M19_SPK_PLAN_MAX];
    size_t plan_len;
    char plan_sha[65];
    m11_speaker_plan plan;
    m11_snd_backend snd;
    m11_speaker_report spk;
    m11_entry entry;
    int census_rc;
    unsigned ctl_writes, ctl_readbacks;
    int session_ran;
    int report_ok;
    m19_stream_status sst;   /* M19 R6 */
    int fifo_fd, chord_ok, streaming_census;
    const char *state;
    uint8_t carry[4]; /* R9: a frame the fill deadline split, for the next buffer */
    size_t carry_len;
};

static volatile sig_atomic_t terminate_requested;
void m19_sink_terminate(void) { terminate_requested = 1; }

struct m19_sink_config m19_sink_config_default(void) {
    struct m19_sink_config c;
    memset(&c, 0, sizeof c);
    c.started_path = "/run/m19/sink.started";
    c.plan_path = "/run/m19/sink/plan.bin";
    c.plan_sha_path = "/run/m19/sink/plan.sha256";
    c.report_path = "/run/m19/sink.report";
    c.status_path = "/run/m19/sink.status";
    c.fifo_path = "/run/m19/sink/fifo";
    c.stop_path = "/run/m19/guard-tripped";
    c.dev_root = "/dev";
    c.proc_root = "/proc";
    c.holder_proc_root = "/proc";
    c.sys_root = "/sys";
    c.proc_devices = "/proc/devices";
    c.cmdline_path = "/proc/cmdline";
    c.journal_path = "/dev/kmsg";
    c.panic_path = "/proc/sys/kernel/panic";
    c.endpoint_node = "/dev/aud_pasthru_adsp";
    c.ion_node = "/dev/msm_audio_ion";
    c.ion_cma_node = "/dev/msm_audio_ion_cma";
    c.heap_dir = "/dev/m11-heap";
    c.heap_node = "/dev/m11-heap/system";
    c.spawner_bin = "/bin/true";
    c.snd_paths = m11_snd_paths_default();
    c.require_root = 1;
    c.spawner_require_drop = 1;
    c.journal_require_kmsg = 1;
    c.cdev_require_minor0 = 1;
    c.heap_require_kernel_fs = 1;
    c.journal_rotate = 9u;
    c.pool_count = 2u;
    c.pool_len = 65536u;
    c.pool_base = 200;
    c.pd_ready_budget_ms = 10000u;
    c.timeout_ms = 1000u;
    c.recovery_budget_ms = 5000u;
    c.hold_idle_ms = 1000u;
    c.wait_timeout_ms = 1000u;
    c.amp_window_ms = 12000u;
    c.idle_off_ms = 3000u;
    c.status_ms = 1000u;
    c.pipe_bytes = 32768;
    c.fill_wait_ms = 15u;
    c.write_buffers = 4u;
    c.buffer_ms = 40u;
    return c;
}

static int fd_is_open(int fd) { return fd >= 0 && fcntl(fd, F_GETFD) != -1; }

static int write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(fd, p + done, len - done);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -EIO;
        done += (size_t)w;
    }
    return 0;
}

static int read_whole_reg(const char *path, uint8_t *buf, size_t cap, size_t *len_out) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -errno;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int e = -errno;
        (void)close(fd);
        return e;
    }
    if (!S_ISREG(st.st_mode) || st.st_size <= 0 || (uintmax_t)st.st_size > (uintmax_t)cap) {
        (void)close(fd);
        return !S_ISREG(st.st_mode) ? -EINVAL : st.st_size <= 0 ? -ENODATA : -EFBIG;
    }
    size_t want = (size_t)st.st_size, got = 0;
    while (got < want) {
        ssize_t r = read(fd, buf + got, want - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) {
            (void)close(fd);
            return -EIO;
        }
        got += (size_t)r;
    }
    uint8_t extra;
    ssize_t tail;
    do tail = read(fd, &extra, 1); while (tail < 0 && errno == EINTR);
    (void)close(fd);
    if (tail != 0) return -EIO;
    *len_out = got;
    return 0;
}

static int scan_snd_rec(const char *path, int depth) {
    if (depth > 8) return 1;
    struct stat st;
    if (lstat(path, &st) != 0) return errno == ENOENT ? 0 : 1;
    if (depth == 0 && !S_ISDIR(st.st_mode)) return 1;
    if (S_ISLNK(st.st_mode)) {
        struct stat target;
        if (stat(path, &target) == 0) return 1;
        return errno == ENOENT ? 0 : 1;
    }
    if (!S_ISDIR(st.st_mode)) return 1;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 1;
    DIR *dir = fdopendir(fd);
    if (!dir) {
        (void)close(fd);
        return 1;
    }
    int nodes = 0;
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(dir);
        if (!de) {
            if (errno != 0) nodes++;
            break;
        }
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char child[PATH_MAX];
        int n = snprintf(child, sizeof child, "%s/%s", path, de->d_name);
        if (n <= 0 || (size_t)n >= sizeof child) nodes++;
        else nodes += scan_snd_rec(child, depth + 1);
    }
    (void)closedir(dir);
    return nodes;
}

int m19_sink_scan_snd(const char *path) {
    if (!path || !*path) return 1;
    return scan_snd_rec(path, 0);
}

static int path_absent(const char *path) {
    struct stat st;
    if (lstat(path, &st) == 0) return -EEXIST;
    return errno == ENOENT ? 0 : -errno;
}

static int check_dev_clean(const struct m19_sink_config *c) {
    const char *const must_absent[] = {
        c->endpoint_node, c->ion_node, c->ion_cma_node, c->heap_dir, c->heap_node, c->snd_paths.dir};
    for (size_t i = 0; i < sizeof must_absent / sizeof must_absent[0]; i++) {
        int rc = path_absent(must_absent[i]);
        if (rc) return rc;
    }
    char snd_path[PATH_MAX];
    int n = snprintf(snd_path, sizeof snd_path, "%s/snd", c->dev_root);
    if (n <= 0 || (size_t)n >= sizeof snd_path) return -ENAMETOOLONG;
    return m19_sink_scan_snd(snd_path) == 0 ? 0 : -EEXIST;
}

static int is_digits(const char *s) {
    if (!s || !*s) return 0;
    for (; *s; s++) if (*s < '0' || *s > '9') return 0;
    return 1;
}

static int parse_dev_attr(const char *text, dev_t *out) {
    char *end = NULL;
    errno = 0;
    unsigned long maj = strtoul(text, &end, 10);
    if (end == text || *end != ':' || errno || maj == 0 || maj > 4095ul) return -EPROTO;
    const char *mp = end + 1;
    unsigned long min = strtoul(mp, &end, 10);
    if (end == mp || errno || min > 1048575ul || (*end && strcmp(end, "\n"))) return -EPROTO;
    *out = makedev((unsigned)maj, (unsigned)min);
    return 0;
}

static int add_rdev(dev_t *list, size_t *count, dev_t rdev) {
    for (size_t i = 0; i < *count; i++) if (list[i] == rdev) return 0;
    if (*count >= MAX_AUDIO_RDEVS) return -E2BIG;
    list[(*count)++] = rdev;
    return 0;
}

static m11_boot_config make_boot_cfg(struct speaker_ctx *ctx);

/* System-wide read-only /proc scan before m11_entry_run opens any audio device: no process in the
 * Ubuntu session may already hold aud_pasthru_adsp, msm_audio_ion, msm_audio_ion_cma, or any ALSA
 * character device registered under /sys/class/sound. */
static int check_no_foreign_audio_holders(struct speaker_ctx *ctx) {
    dev_t rdevs[MAX_AUDIO_RDEVS];
    size_t nrdevs = 0;
    m11_boot_config bc = make_boot_cfg(ctx);
    dev_t rdev = 0;
    int rc;
    if ((rc = m11_boot_cdev_meta(&bc, &bc.endpoint, &rdev)) || (rc = add_rdev(rdevs, &nrdevs, rdev)) ||
        (rc = m11_boot_cdev_meta(&bc, &bc.ion, &rdev)) || (rc = add_rdev(rdevs, &nrdevs, rdev)) ||
        (rc = m11_boot_cdev_meta(&bc, &bc.ion_cma, &rdev)) || (rc = add_rdev(rdevs, &nrdevs, rdev)))
        return rc;

    DIR *sdir = opendir(ctx->cfg.snd_paths.sys_sound);
    if (!sdir) return -errno;
    unsigned snd_devs = 0;
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(sdir);
        if (!de) {
            if (errno != 0) rc = -errno;
            break;
        }
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char dev_path[PATH_MAX], text[32];
        int k = snprintf(dev_path, sizeof dev_path, "%s/%s/dev", ctx->cfg.snd_paths.sys_sound, de->d_name);
        if (k <= 0 || (size_t)k >= sizeof dev_path) { rc = -ENAMETOOLONG; break; }
        int fd = open(dev_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            if (errno == ENOENT) continue; /* cardN container directory has no dev attribute */
            rc = -errno;
            break;
        }
        ssize_t n = read(fd, text, sizeof text - 1);
        int saved = errno;
        (void)close(fd);
        if (n <= 0 || (size_t)n >= sizeof text - 1) { rc = n < 0 ? -saved : -EPROTO; break; }
        text[n] = '\0';
        if ((rc = parse_dev_attr(text, &rdev)) || (rc = add_rdev(rdevs, &nrdevs, rdev))) break;
        snd_devs++;
    }
    (void)closedir(sdir);
    if (rc) return rc;
    if (snd_devs < 3u) return -ENODEV;

    DIR *proc = opendir(ctx->cfg.holder_proc_root);
    if (!proc) return -errno;
    for (;;) {
        errno = 0;
        struct dirent *pe = readdir(proc);
        if (!pe) {
            if (errno != 0) rc = -errno;
            break;
        }
        if (!is_digits(pe->d_name)) continue;
        char fd_dir_path[PATH_MAX];
        int k = snprintf(fd_dir_path, sizeof fd_dir_path, "%s/%s/fd", ctx->cfg.holder_proc_root, pe->d_name);
        if (k <= 0 || (size_t)k >= sizeof fd_dir_path) { rc = -ENAMETOOLONG; break; }
        DIR *fdir = opendir(fd_dir_path);
        if (!fdir) {
            if (errno == ENOENT || errno == ESRCH) continue;
            rc = -errno;
            break;
        }
        for (;;) {
            errno = 0;
            struct dirent *fe = readdir(fdir);
            if (!fe) {
                if (errno != 0 && errno != ENOENT && errno != ESRCH) rc = -errno;
                break;
            }
            if (!is_digits(fe->d_name)) continue;
            char item[PATH_MAX];
            int m = snprintf(item, sizeof item, "%s/%s", fd_dir_path, fe->d_name);
            if (m <= 0 || (size_t)m >= sizeof item) { rc = -ENAMETOOLONG; break; }
            struct stat st;
            if (stat(item, &st) != 0) {
                if (errno == ENOENT || errno == ESRCH) continue;
                rc = -errno;
                break;
            }
            if (!S_ISCHR(st.st_mode)) continue;
            for (size_t i = 0; i < nrdevs; i++) {
                if (st.st_rdev == rdevs[i]) {
                    rc = -EBUSY;
                    break;
                }
            }
            if (rc) break;
        }
        (void)closedir(fdir);
        if (rc) break;
    }
    (void)closedir(proc);
    return rc;
}

static void hex_digest(const uint8_t d[32], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32u; i++) {
        out[2u * i] = hex[d[i] >> 4];
        out[2u * i + 1u] = hex[d[i] & 0x0fu];
    }
    out[64] = '\0';
}

static int load_and_verify_plan(struct speaker_ctx *ctx) {
    uint8_t sha_raw[192];
    size_t sha_len = 0;
    int rc = read_whole_reg(ctx->cfg.plan_path, ctx->plan_buf, sizeof ctx->plan_buf, &ctx->plan_len);
    if (rc) return rc;
    rc = read_whole_reg(ctx->cfg.plan_sha_path, sha_raw, sizeof sha_raw - 1u, &sha_len);
    if (rc) return rc;
    if (sha_len < 65u || (sha_raw[64] != '\n' && sha_raw[64] != ' ')) return -EBADMSG;
    for (size_t i = 0; i < 64u; i++) {
        uint8_t c = sha_raw[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return -EBADMSG;
    }
    uint8_t digest[32];
    m19_sha256(ctx->plan_buf, ctx->plan_len, digest);
    hex_digest(digest, ctx->plan_sha);
    if (memcmp(ctx->plan_sha, sha_raw, 64u) != 0) return -EBADMSG;
    if ((rc = m11_speaker_plan_parse(ctx->plan_buf, ctx->plan_len, &ctx->plan)) != 0) return rc;
    if (ctx->plan.duration_ms == 0u || ctx->plan.duration_ms > M19_SPK_MAX_DURATION_MS) return -EINVAL;
    if (ctx->plan.peak_mdbfs > M19_SPK_MAX_PEAK_MDBFS) return -EINVAL;
    if (ctx->plan.volume_level == 0u || ctx->plan.volume_level > M19_SPK_MAX_VOLUME_LEVEL) return -EINVAL;
    if (ctx->plan.pcm.len == 0u) return -EINVAL;
    /* PulseAudio's pipe sink is configured for this format (r6plan.PULSE_SINK) */
    if (ctx->plan.stream_rate != 48000u || ctx->plan.stream_channels != 2u) return -EINVAL;
    return 0;
}

static unsigned count_anchor_fds(const m11_entry *e) {
    if (e->runner.term.saved)
        return (unsigned)fd_is_open(e->runner.term.saved_fd[0][0]) +
               (unsigned)fd_is_open(e->runner.term.saved_fd[0][1]) +
               (unsigned)fd_is_open(e->runner.term.saved_fd[1][0]) +
               (unsigned)fd_is_open(e->runner.term.saved_fd[1][1]);
    unsigned n = 0;
    if (e->boot.endpoint.state != M11_ANCHOR_UNBOUND)
        n += (unsigned)fd_is_open(e->boot.endpoint.anchor_fd) + (unsigned)fd_is_open(e->boot.endpoint.guard_fd);
    if (e->boot.ion.state != M11_ANCHOR_UNBOUND)
        n += (unsigned)fd_is_open(e->boot.ion.anchor_fd) + (unsigned)fd_is_open(e->boot.ion.guard_fd);
    return n;
}

static unsigned count_anchors_held(const m11_entry *e) {
    if (e->phase == M11_ENTRY_END) return e->runner.term.anchors_held;
    return (unsigned)(e->boot.endpoint.state == M11_ANCHOR_HELD) +
           (unsigned)(e->boot.ion.state == M11_ANCHOR_HELD);
}

int m19_sink_qualify_session(int phase, int fail_step, int rc, int session_ran, int session_rc,
                                const m11_speaker_plan *plan, const m11_speaker_report *r,
                                int census_rc, unsigned census_why, int resources_busy,
                                int terminal_action, unsigned anchors_held, unsigned anchor_fds_open,
                                int pool_held, unsigned regions_in_pool, int unmap_attempted) {
    if (!plan || !r) return 0;
    const int re_verified = r->re.pair_re_readback_verified ? 1 : 0;
    const uint32_t re0_q12 = r->re.ch[0].readback_q12;
    const uint32_t re1_q12 = r->re.ch[1].readback_q12;

    return phase == M11_ENTRY_END &&
           fail_step == 0 && rc == 0 &&
           session_ran == 1 && session_rc == 0 &&
           r->stage == M19_SPK_STREAMED && r->fail_step == 0 && r->rc == 0 &&
           r->regions_mapped == 2u &&
           re_verified == 1 && re0_q12 > 0u && re1_q12 > 0u &&
           plan->volume_level > 0u && plan->volume_level <= M19_SPK_MAX_VOLUME_LEVEL &&
           plan->duration_ms > 0u && plan->duration_ms <= M19_SPK_MAX_DURATION_MS &&
           plan->pcm.len > 0u &&
           r->buffers_sent >= 1u && r->buffers_done == r->buffers_sent &&
           r->bytes_played == plan->pcm.len &&
           r->amp_on == 1 && r->amp_off_verified == 1 &&
           r->teardown_rc == 0 && r->pdr_seen == 0 &&
           census_rc == 0 && census_why == 0u &&
           resources_busy == 1 &&
           terminal_action == (int)M11_TERMINAL_RESET_RETAINING_ANCHORS &&
           anchors_held == 2u && anchor_fds_open == 4u &&
           pool_held == 1 && regions_in_pool == 2u &&
           unmap_attempted == 0;
}

int m19_sink_qualify_chord(const m11_speaker_plan *plan, const m11_speaker_report *r, int census_rc, unsigned census_why,
                           int resources_busy, int unmap_attempted, const m19_stream_status *st) {
    if (!plan || !r || !st) return 0;
    return r->stage == M11_SPK_PLAYED && r->fail_step == 0 && r->rc == 0 && r->regions_mapped == 2u &&
           r->re.pair_re_readback_verified && r->re.ch[0].readback_q12 > 0u && r->re.ch[1].readback_q12 > 0u &&
           plan->volume_level > 0u && plan->volume_level <= M19_SPK_MAX_VOLUME_LEVEL &&
           plan->duration_ms > 0u && plan->duration_ms <= M19_SPK_MAX_DURATION_MS && plan->pcm.len > 0u &&
           r->buffers_sent >= 1u && r->buffers_done == r->buffers_sent && r->bytes_played == plan->pcm.len &&
           r->amp_on == 1 && r->amp_off_verified == 0 && r->pdr_seen == 0 &&
           census_rc == 0 && census_why == 0u && resources_busy == 1 && unmap_attempted == 0 &&
           st->streaming == 1 && st->amp_on == 1;
}

static int write_report_file(struct speaker_ctx *ctx, int pre_step, int pre_rc) {
    const m11_entry *e = &ctx->entry;
    const m11_speaker_report *r = &ctx->spk;
    const int phase = e->phase;
    const int fail_step = phase == 0 && pre_step ? pre_step : e->fail_step;
    const int rc = phase == 0 && pre_rc ? pre_rc : e->fail_rc;
    const unsigned anchors_held = count_anchors_held(e);
    const unsigned anchor_fds_open = count_anchor_fds(e);
    const int pool_held = e->phase == M11_ENTRY_END ? e->runner.term.pool_held : 0;
    const unsigned regions_in_pool = e->phase == M11_ENTRY_END ? e->runner.term.regions_in_pool : 0u;
    const int unmap_attempted = e->runner.boot.dsp_unmap_attempted ? 1 : 0;
    const int terminal_action = e->phase == M11_ENTRY_END ? (int)e->runner.term.action : -1;
    const int re_verified = r->re.pair_re_readback_verified ? 1 : 0;
    const uint32_t re0_q12 = r->re.ch[0].readback_q12;
    const uint32_t re1_q12 = r->re.ch[1].readback_q12;
    const int census_rc = ctx->session_ran ? ctx->census_rc : -1;

    const int ok = m19_sink_qualify_session(phase, fail_step, rc, ctx->session_ran ? 1 : 0, e->session_rc,
                                               &ctx->plan, r, census_rc, e->runner.census_why,
                                               e->pdmon.pds.resources_busy, terminal_action,
                                               anchors_held, anchor_fds_open, pool_held, regions_in_pool,
                                               unmap_attempted);
    ctx->report_ok = ok;

    if (e->journal_fd >= 0 && e->sink.append_fn) {
        char krec[224];
        int kn = snprintf(krec, sizeof krec,
                          "<6>M19SINK v=1 boot=%llu ok=%d pid=%ld phase=%d step=%d rc=%d spk=%d/%d "
                          "played=%u/%u re=%d/%u/%u anchors=%u/%u pool=%d/%u\n",
                          (unsigned long long)e->boot_epoch, ok, (long)getpid(), phase, fail_step, rc,
                          r->stage, e->session_rc, r->bytes_played, ctx->plan.pcm.len,
                          re_verified, re0_q12, re1_q12, anchors_held, anchor_fds_open,
                          pool_held, regions_in_pool);
        if (kn > 0 && (size_t)kn < sizeof krec) (void)e->sink.append_fn(e->sink.user, krec, (size_t)kn);
    }

    char body[2048];
    int n = snprintf(body, sizeof body,
                     "state=%s\n"
                     "chord_ok=%d\n"
                     "ok=%d\n"
                     "pid=%ld\n"
                     "entry_phase=%d\n"
                     "fail_step=%d\n"
                     "rc=%d\n"
                     "session_rc=%d\n"
                     "spk_stage=%d\n"
                     "spk_fail_step=%d\n"
                     "regions_mapped=%u\n"
                     "re_verified=%d\n"
                     "re0_q12=%u\n"
                     "re1_q12=%u\n"
                     "volume_level=%u\n"
                     "duration_ms=%u\n"
                     "pcm_bytes=%u\n"
                     "buffers_sent=%u\n"
                     "buffers_done=%u\n"
                     "bytes_played=%u\n"
                     "amp_on=%d\n"
                     "amp_off_verified=%d\n"
                     "teardown_rc=%d\n"
                     "pdr_seen=%d\n"
                     "census_rc=%d\n"
                     "census_why=%u\n"
                     "ctl_writes=%u\n"
                     "ctl_readbacks=%u\n"
                     "resources_busy=%d\n"
                     "ack_deferred=%d\n"
                     "terminal_action=%d\n"
                     "anchors_held=%u\n"
                     "anchor_fds_open=%u\n"
                     "pool_held=%d\n"
                     "regions_in_pool=%u\n"
                     "unmap_attempted=%d\n"
                     "plan_sha256=%s\n"
                     "streaming=%d\n"
                     "stream_amp_on=%d\n"
                     "stopped=%d\n"
                     "stream_buffers=%llu\n"
                     "bytes_in=%llu\n"
                     "bytes_loud=%llu\n"
                     "underruns=%llu\n"
                     "gaps=%llu\n"
                     "amp_enables=%u\n"
                     "amp_disables=%u\n"
                     "peak_in=%d\n"
                     "peak_out=%d\n",
                     ctx->state ? ctx->state : "pre", ctx->chord_ok, ok, (long)getpid(), phase, fail_step, rc, e->session_rc,
                     r->stage, r->fail_step, r->regions_mapped,
                     re_verified, re0_q12, re1_q12,
                     ctx->plan.volume_level, ctx->plan.duration_ms, ctx->plan.pcm.len,
                     r->buffers_sent, r->buffers_done, r->bytes_played,
                     r->amp_on, r->amp_off_verified, r->teardown_rc, r->pdr_seen,
                     census_rc, e->runner.census_why,
                     ctx->ctl_writes, ctx->ctl_readbacks,
                     e->pdmon.pds.resources_busy, e->pdmon.pds.ack_deferred,
                     terminal_action, anchors_held, anchor_fds_open,
                     pool_held, regions_in_pool, unmap_attempted,
                     ctx->plan_sha[0] ? ctx->plan_sha : "-",
                     ctx->sst.streaming, ctx->sst.amp_on, ctx->sst.stopped, (unsigned long long)ctx->sst.buffers,
                     (unsigned long long)ctx->sst.bytes_in, (unsigned long long)ctx->sst.bytes_loud,
                     (unsigned long long)ctx->sst.underruns, (unsigned long long)ctx->sst.gaps, ctx->sst.amp_enables, ctx->sst.amp_disables,
                     ctx->sst.peak_in, ctx->sst.peak_out);
    if (n <= 0 || (size_t)n >= sizeof body) return -EOVERFLOW;

    char tmp[PATH_MAX];
    int tn = snprintf(tmp, sizeof tmp, "%s.tmp", ctx->cfg.report_path);
    if (tn <= 0 || (size_t)tn >= sizeof tmp) return -ENAMETOOLONG;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) return -errno;
    int wrc = write_all(fd, body, (size_t)n);
    if (!wrc && fsync(fd) != 0) wrc = -errno;
    if (close(fd) != 0 && !wrc) wrc = -errno;
    if (wrc) {
        (void)unlink(tmp);
        return wrc;
    }
    if (rename(tmp, ctx->cfg.report_path) != 0) {
        int e2 = -errno;
        (void)unlink(tmp);
        return e2;
    }
    return 0;
}

static int pre_seal_snd(void *user) {
    struct speaker_ctx *ctx = user;
    return m11_snd_prepare(&ctx->snd, ctx->cfg.snd_sys, &ctx->cfg.snd_paths,
                           ctx->plan.backend[0].name, ctx->plan.backend[1].name);
}

static int session_map_cb(void *user, size_t bytes, unsigned *slot) {
    m11_entry *e = user;
    return m11_crunner_map(&e->runner, bytes, m11_entry_now_ms(), slot);
}

static void session_settle_cb(void *user) {
    m11_entry *e = user;
    (void)m11_pdr_loop_settle(&e->runner.loop, m11_entry_now_ms());
}

static uint64_t session_now_cb(void *user) {
    (void)user;
    return m11_entry_now_ms();
}

static void session_record_cb(void *user, const char *line) {
    m11_entry *e = user;
    char rec[224];
    int n = snprintf(rec, sizeof rec, "<6>M11SPK v=1 boot=%llu %s\n",
                     (unsigned long long)e->boot_epoch, line);
    if (n <= 0 || (size_t)n >= sizeof rec || e->sink.append_fn(e->sink.user, rec, (size_t)n))
        e->record_failures++;
    else
        e->records++;
}

/* M19 R6: the server's PCM, nonblocking; 0 when none is waiting (the stream pads with silence).
 * R9: a buffer begun is completed. PulseAudio's pipe sink writes a few KiB at a time, and R6 to R8 padded the rest of
 * each short read with silence, which a desktop stream (R8's YouTube) heard as breaks and growing delay. A short read
 * now waits up to fill_wait_ms for the rest; a frame the deadline splits is kept for the next buffer, so the stream
 * never slips by a sample. With nothing waiting, it returns at once: silence. */
#define SINK_FRAME 4u /* s16le, two channels: the pipe sink's format (r6plan.PULSE_SINK) */
static size_t sink_source(void *user, uint8_t *out, size_t room) {
    struct speaker_ctx *ctx = user;
    if (ctx->fifo_fd < 0 || room < SINK_FRAME) return 0;
    room -= room % SINK_FRAME;
    size_t got = ctx->carry_len;
    memcpy(out, ctx->carry, got);
    ctx->carry_len = 0;
    uint64_t deadline = 0;
    while (got < room) {
        ssize_t n;
        do n = read(ctx->fifo_fd, out + got, room - got); while (n < 0 && errno == EINTR);
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        if (!got || n == 0 || errno != EAGAIN) break;
        uint64_t t = m11_entry_now_ms();
        if (!deadline) deadline = t + ctx->cfg.fill_wait_ms;
        if (t >= deadline) break;
        struct pollfd wait = {.fd = ctx->fifo_fd, .events = POLLIN};
        (void)poll(&wait, 1, (int)(deadline - t));
    }
    ctx->carry_len = got % SINK_FRAME;
    got -= ctx->carry_len;
    memcpy(ctx->carry, out + got, ctx->carry_len);
    return got;
}

static int sink_stop(void *user) {
    struct speaker_ctx *ctx = user;
    return terminate_requested || access(ctx->cfg.stop_path, F_OK) == 0;
}

static void sink_status(void *user, const m19_stream_status *st) {
    struct speaker_ctx *ctx = user;
    char body[512], tmp[PATH_MAX];
    int n = snprintf(body, sizeof body,
                     "streaming=%d\namp_on=%d\nstopped=%d\nbuffers=%llu\nbytes_in=%llu\nbytes_loud=%llu\nunderruns=%llu\ngaps=%llu\n"
                     "amp_enables=%u\namp_disables=%u\npeak_in=%d\npeak_out=%d\nlast_loud_ms=%llu\nstarted_ms=%llu\n",
                     st->streaming, st->amp_on, st->stopped, (unsigned long long)st->buffers, (unsigned long long)st->bytes_in,
                     (unsigned long long)st->bytes_loud, (unsigned long long)st->underruns, (unsigned long long)st->gaps, st->amp_enables,
                     st->amp_disables,
                     st->peak_in, st->peak_out, (unsigned long long)st->last_loud_ms, (unsigned long long)st->started_ms);
    int tn = snprintf(tmp, sizeof tmp, "%s.tmp", ctx->cfg.status_path);
    if (n <= 0 || (size_t)n >= sizeof body || tn <= 0 || (size_t)tn >= sizeof tmp) return;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) return;
    int bad = write_all(fd, body, (size_t)n);
    if (close(fd) || bad || rename(tmp, ctx->cfg.status_path)) (void)unlink(tmp);
}

/* the switch from the chord to the stream: R5b's verdict, as far as it is known now, in sink.report */
static void sink_streaming(void *user, const m11_speaker_report *r, const m19_stream_status *st) {
    struct speaker_ctx *ctx = user; /* r and st are ctx->spk and ctx->sst, as the session writes them */
    ctx->streaming_census = m11_crunner_census(&ctx->entry.runner);
    ctx->census_rc = ctx->streaming_census;
    ctx->chord_ok = m19_sink_qualify_chord(&ctx->plan, r, ctx->streaming_census, ctx->entry.runner.census_why,
                                           ctx->entry.pdmon.pds.resources_busy, ctx->entry.runner.boot.dsp_unmap_attempted ? 1 : 0, st);
    ctx->state = "streaming";
    ctx->session_ran = 1;
    (void)write_report_file(ctx, 0, 0);
    ctx->session_ran = 0;
    sink_status(user, st);
}

static int speaker_session_cb(void *user, m11_entry *e) {
    struct speaker_ctx *ctx = user;
    if (ctx->cfg.session_ready_fn) ctx->cfg.session_ready_fn(ctx->cfg.session_ready_user, e);

    char line[160];
    snprintf(line, sizeof line, "phase=sink plan sha=%.16s bytes=%zu pcm=%u level=%u",
             ctx->plan_sha, ctx->plan_len, ctx->plan.pcm.len, ctx->plan.volume_level);
    session_record_cb(e, line);

    ctx->fifo_fd = open(ctx->cfg.fifo_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    struct stat fifo;
    if (ctx->fifo_fd >= 0 && (fstat(ctx->fifo_fd, &fifo) || !S_ISFIFO(fifo.st_mode))) {
        (void)close(ctx->fifo_fd);
        ctx->fifo_fd = -1;
    }
    if (ctx->fifo_fd >= 0 && ctx->cfg.pipe_bytes > 0) (void)fcntl(ctx->fifo_fd, F_SETPIPE_SZ, ctx->cfg.pipe_bytes);
    snprintf(line, sizeof line, "phase=sink fifo=%d", ctx->fifo_fd >= 0);
    session_record_cb(e, line);
    const m19_stream_io sio = {.spk = {
        .cust = &e->runner.cust,
        .map_fn = session_map_cb,
        .user = e,
        .snd = &ctx->snd,
        .plan = &ctx->plan,
        .record_fn = session_record_cb,
        .settle_fn = session_settle_cb,
        .now_fn = session_now_cb,
        .wait_timeout_ms = ctx->cfg.wait_timeout_ms,
        .amp_window_ms = ctx->cfg.amp_window_ms,
        .region_bytes = ctx->cfg.pool_len,
        .write_buffers = ctx->cfg.write_buffers,
        .buffer_ms = ctx->cfg.buffer_ms,
    },
        .source_fn = sink_source, .stop_fn = sink_stop, .streaming_fn = sink_streaming, .status_fn = sink_status, .user = ctx,
        .idle_off_ms = ctx->cfg.idle_off_ms, .status_ms = ctx->cfg.status_ms, .gain_q15 = M19_STREAM_GAIN_Q15,
        .peak_limit = M19_STREAM_PEAK,
    };
    int rc = m19_stream_session_run(&sio, &ctx->spk, &ctx->sst);
    ctx->state = rc ? "failed" : "stopped";
    ctx->census_rc = m11_crunner_census(&e->runner);
    ctx->ctl_writes = ctx->snd.ctl_writes;
    ctx->ctl_readbacks = ctx->snd.ctl_readbacks;
    ctx->session_ran = 1;
    /* Disable readback is verified inside the stream session's (Run31's) teardown before returning;
     * release the private control fd and /dev/m11-snd directory now, leaving zero ALSA fds or nodes. */
    m11_snd_release(&ctx->snd);
    snprintf(line, sizeof line, "phase=sink session rc=%d census=%d ctl_writes=%u readbacks=%u",
             rc, ctx->census_rc, ctx->ctl_writes, ctx->ctl_readbacks);
    session_record_cb(e, line);
    return rc;
}

static int speaker_refuse_reboot(void *user) {
    (void)user;
    return -EPERM; /* A session daemon never calls reboot(2); falls through to speaker_terminal_hold. */
}

static void speaker_terminal_hold(void *user) {
    struct speaker_ctx *ctx = user;
    /* Idempotent cleanup if m11_entry_run failed after pre_seal_snd before speaker_session_cb ran. */
    m11_snd_release(&ctx->snd);
    (void)write_report_file(ctx, 0, 0);
    if (ctx->cfg.return_from_hold) {
        if (ctx->entry.boot.spawner.pid > 0 && ctx->entry.boot.spawner.sock >= 0) {
            (void)m11_spawner_stop(&ctx->entry.boot.spawner);
        }
        return;
    }
    for (;;) pause();
}

static m11_boot_config make_boot_cfg(struct speaker_ctx *ctx) {
    const struct m19_sink_config *c = &ctx->cfg;
    ctx->spawner_argv[0] = c->spawner_bin;
    ctx->spawner_argv[1] = NULL;
    ctx->spawner_jobs[0] = ctx->spawner_argv;
    return (m11_boot_config){
        .sys = c->sys_root,
        .proc_devices = c->proc_devices,
        .endpoint = {"aud_pasthru_adsp", "aud_pasthru_adsp", c->endpoint_node, c->cdev_require_minor0},
        .ion = {"msm_audio_ion", "msm_audio_ion", c->ion_node, c->cdev_require_minor0},
        .ion_cma = {"msm_audio_ion_cma", "msm_audio_ion_cma", c->ion_cma_node, c->cdev_require_minor0},
        .heap = {
            .sys = c->sys_root,
            .proc_devices = c->proc_devices,
            .dev_dir = c->heap_dir,
            .node = c->heap_node,
            .require_kernel_fs = c->heap_require_kernel_fs,
            .require_root = c->require_root,
        },
        .require_root = c->require_root,
        .census_root = (int)getpid(),
        .spawner_commands = ctx->spawner_jobs,
        .spawner_count = 1u,
        .spawner_require_drop = c->spawner_require_drop,
        .pre_seal_fn = pre_seal_snd,
        .pre_seal_user = ctx,
    };
}

static int acquire_started_lock(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return errno == EEXIST ? -EALREADY : -errno;
    char buf[32];
    int n = snprintf(buf, sizeof buf, "%ld\n", (long)getpid());
    int rc = (n > 0 && (size_t)n < sizeof buf) ? write_all(fd, buf, (size_t)n) : -EOVERFLOW;
    if (!rc && fsync(fd) != 0) rc = -errno;
    if (close(fd) != 0 && !rc) rc = -errno;
    if (rc) (void)unlink(path);
    return rc;
}

static int cfg_valid(const struct m19_sink_config *c) {
    return c && c->started_path && c->plan_path && c->plan_sha_path && c->report_path && c->status_path && c->fifo_path &&
           c->stop_path && c->idle_off_ms >= 1u && c->status_ms >= 1u &&
           c->fill_wait_ms >= 1u && c->write_buffers >= 2u && c->fill_wait_ms < c->buffer_ms * (c->write_buffers - 1u) &&
           c->dev_root && c->proc_root && c->holder_proc_root && c->sys_root &&
           c->proc_devices && c->cmdline_path && c->journal_path && c->panic_path &&
           c->endpoint_node && c->ion_node && c->ion_cma_node && c->heap_dir && c->heap_node &&
           c->spawner_bin && c->snd_paths.proc_pcm && c->snd_paths.sys_sound && c->snd_paths.dir &&
           c->pool_count == 2u && c->pool_len >= 4096u && c->pool_base >= 3 &&
           c->pd_ready_budget_ms >= 1u && c->pd_ready_budget_ms <= 10000u &&
           c->journal_rotate <= 9u && c->write_buffers >= 2u && c->write_buffers <= 8u &&
           c->buffer_ms >= 10u && c->buffer_ms <= 100u &&
           c->wait_timeout_ms >= 1u && c->amp_window_ms >= 1u && c->hold_idle_ms >= 1u;
}

int m19_sink_run(const struct m19_sink_config *cfg) {
    if (!cfg_valid(cfg)) return -EINVAL;
    if (getpid() <= 1) return -EPERM;

    int rc = acquire_started_lock(cfg->started_path);
    if (rc) return rc; /* EALREADY never overwrites an existing speaker.report */

    struct speaker_ctx *ctx = calloc(1, sizeof *ctx);
    if (!ctx) return -ENOMEM;
    ctx->cfg = *cfg;
    ctx->entry.journal_fd = -1;
    ctx->entry.pdmon.fd = -1;
    ctx->entry.boot.heap.fd = -1;
    ctx->entry.boot.spawner.sock = -1;
    ctx->entry.boot.spawner.pid = -1;
    ctx->snd.ctl_fd = -1;
    ctx->snd.pcm[0].fd = -1;
    ctx->snd.pcm[1].fd = -1;
    ctx->census_rc = -1;
    ctx->fifo_fd = -1;

    if ((rc = check_dev_clean(&ctx->cfg)) != 0) {
        (void)write_report_file(ctx, M19_SPK_PRE_DEV, rc);
        free(ctx);
        return rc;
    }
    if ((rc = check_no_foreign_audio_holders(ctx)) != 0) {
        (void)write_report_file(ctx, M19_SPK_PRE_HOLDERS, rc);
        free(ctx);
        return rc;
    }
    if ((rc = load_and_verify_plan(ctx)) != 0) {
        (void)write_report_file(ctx, M19_SPK_PRE_PLAN, rc);
        free(ctx);
        return rc;
    }

    m11_entry_config ec = m11_entry_config_default();
    ec.boot = make_boot_cfg(ctx);
    ec.qrtr = ctx->cfg.qrtr;
    ec.pd_ready_budget_ms = ctx->cfg.pd_ready_budget_ms;
    ec.cmdline_path = ctx->cfg.cmdline_path;
    ec.journal_path = ctx->cfg.journal_path;
    ec.journal_require_kmsg = ctx->cfg.journal_require_kmsg;
    ec.journal_rotate = ctx->cfg.journal_rotate;
    ec.require_pid1 = 0;
    ec.pool_count = ctx->cfg.pool_count;
    ec.pool_len = ctx->cfg.pool_len;
    ec.pool_base = ctx->cfg.pool_base;
    ec.sys = ctx->cfg.shmem_sys;
    ec.timeout_ms = ctx->cfg.timeout_ms;
    ec.recovery_budget_ms = ctx->cfg.recovery_budget_ms;
    ec.hold_idle_ms = ctx->cfg.hold_idle_ms;
    ec.boot_epoch = ctx->cfg.boot_epoch;
    ec.terminal_ops = (m11_terminal_ops){
        .exit_fn = speaker_terminal_hold,
        .reboot_fn = speaker_refuse_reboot,
        .user = ctx,
        .panic_path = ctx->cfg.panic_path,
        .teardown_fn = NULL,
        .hold_fn = speaker_terminal_hold,
    };
    ec.teardown_jobs = NULL;
    ec.teardown_count = 0u;
    ec.seal_count = 0u;
    ec.seal_settle_ms = 0u;
    ec.proc_root = ctx->cfg.proc_root;
    ec.session_fn = speaker_session_cb;
    ec.session_user = ctx;

    (void)m11_entry_run(&ctx->entry, &ec);
    if (!ctx->cfg.return_from_hold) {
        for (;;) pause();
    }
    const int ok = ctx->report_ok;
    free(ctx);
    return ok ? 0 : -ECANCELED;
}
