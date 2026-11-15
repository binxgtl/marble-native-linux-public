/* M17 G5b/G5c: the speaker protection probe and the loudness backstop (awprobe.h). */
#define _GNU_SOURCE
#include "awprobe.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct m17_probe_config m17_probe;

static void put32(uint8_t *at, uint32_t v) {
    memcpy(at, &v, 4);
}

static uint32_t get32(const uint8_t *at) {
    uint32_t v;
    memcpy(&v, at, 4);
    return v;
}

size_t m17_aw_status_cmd(uint8_t out[M17_AW_CMD_BYTES]) {
    memset(out, 0, M17_AW_CMD_BYTES);
    put32(out + 12, M17_AW_CMD_BYTES - 16u); /* the header's payload size; address and map handle zero: in band */
    put32(out + 16, M17_AW_IID);
    put32(out + 20, M17_AW_MSG_PARAM);
    put32(out + 24, 24u);
    put32(out + 32, 1u);                 /* message type 1: a command */
    put32(out + 36, M17_AW_MSG_STATUS);
    put32(out + 40, 1u);                 /* version 1 */
    return M17_AW_CMD_BYTES;
}

size_t m17_aw_status_req(uint8_t out[M17_AW_REQ_BYTES]) {
    memset(out, 0, M17_AW_REQ_BYTES);
    put32(out + 12, M17_AW_REQ_BYTES - 16u);
    put32(out + 16, M17_AW_IID);
    put32(out + 20, M17_AW_MSG_PARAM);
    put32(out + 24, M17_AW_STATUS_BYTES); /* (32 + 0x17) & ~7, less 16: libawcal's size for a 32-byte read */
    return M17_AW_REQ_BYTES;
}

int m17_aw_status_parse(const void *rsp, size_t len, struct m17_aw_status *out) {
    memset(out, 0, sizeof(*out));
    const uint8_t *p = rsp;
    if (!rsp || len < M17_AW_RSP_BYTES || get32(p) != 0u || get32(p + 4) != M17_AW_IID || get32(p + 8) != M17_AW_MSG_PARAM ||
        get32(p + 12) < M17_AW_STATUS_BYTES || get32(p + 16) != 0u)
        return -EPROTO;
    for (unsigned i = 0; i < 8; i++)
        out->raw[i] = get32(p + 20 + 4u * i);
    /* libawcal's layout: the first speaker's Re and temperature in words 0 and 2, the second's in words 4 and 6 */
    for (unsigned ch = 0; ch < 2; ch++) {
        out->re_mohm[ch] = (int32_t)(((int64_t)(int32_t)out->raw[4 * ch] * 1000) >> 12);
        out->te[ch] = (int32_t)out->raw[4 * ch + 2];
    }
    return 0;
}

int m17_aw_status_is_reference(const struct m17_aw_status *st) {
    return st->raw[0] == st->raw[1] && st->raw[4] == st->raw[5] && st->te[0] == M17_AW_REF_TE && st->te[1] == M17_AW_REF_TE;
}

int m17_backstop_valid(const struct m17_probe_config *cfg) {
    const struct m17_backstop *b = &cfg->backstop;
    return cfg->log && cfg->period_ms && cfg->period_ms <= 5000u && cfg->gain_q15 > 0 && cfg->gain_q15 <= 32768 &&
           cfg->peak_limit > 0 && cfg->peak_limit <= 32767 && b->te_limit > M17_AW_REF_TE && b->te_limit <= 80 &&
           b->re_min > 0 && b->re_min < b->re_max && b->ref_limit > 0 && b->loud_peak > 0;
}

enum m17_drop m17_backstop_step(const struct m17_backstop *cfg, struct m17_backstop_state *state, int probe_rc,
                                const struct m17_aw_status *st, int32_t recent_peak) {
    if (state->dropped)
        return M17_DROP_NONE;
    enum m17_drop why = M17_DROP_NONE;
    if (probe_rc) {
        why = M17_DROP_PROBE;
    } else if (m17_aw_status_is_reference(st)) {
        /* a reference while the sound was quiet is expected and changes nothing */
        if (recent_peak >= cfg->loud_peak && ++state->ref_streak >= cfg->ref_limit)
            why = M17_DROP_BLIND;
    } else {
        state->ref_streak = 0;
        for (unsigned ch = 0; ch < 2 && !why; ch++) {
            if (st->te[ch] >= cfg->te_limit)
                why = M17_DROP_TEMP;
            else if (st->re_mohm[ch] < cfg->re_min || st->re_mohm[ch] > cfg->re_max)
                why = M17_DROP_RE;
        }
    }
    state->dropped = why;
    return why;
}

const char *m17_drop_name(enum m17_drop why) {
    switch (why) {
    case M17_DROP_NONE: return "none";
    case M17_DROP_PROBE: return "probe";
    case M17_DROP_TEMP: return "temp";
    case M17_DROP_RE: return "re";
    case M17_DROP_BLIND: return "blind";
    }
    return "unknown";
}

int m17_aw_status_log(const char *path, unsigned limit, const struct m17_aw_status *st, int amp_on, int32_t peak_out, int rc,
                      uint32_t dsp_status, int32_t gain_q15, int live, enum m17_drop dropped) {
    struct timespec t;
    clock_gettime(CLOCK_BOOTTIME, &t);
    char line[360];
    int n = snprintf(line, sizeof(line),
                     "%lld.%03ld re=%d,%d te=%d,%d raw=%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x amp=%d peak=%d rc=%d status=%08x "
                     "gain=%d live=%d drop=%s\n",
                     (long long)t.tv_sec, t.tv_nsec / 1000000, st->re_mohm[0], st->re_mohm[1], st->te[0], st->te[1], st->raw[0],
                     st->raw[1], st->raw[2], st->raw[3], st->raw[4], st->raw[5], st->raw[6], st->raw[7], amp_on, peak_out, rc,
                     dsp_status, gain_q15, live, m17_drop_name(dropped));
    if (n < 0 || (size_t)n >= sizeof(line))
        return -EOVERFLOW;
    struct stat s;
    if (!lstat(path, &s)) {
        if (!S_ISREG(s.st_mode))
            return -EINVAL;
        if ((size_t)s.st_size >= limit) {
            char older[512];
            if ((size_t)snprintf(older, sizeof(older), "%s.1", path) >= sizeof(older))
                return -ENAMETOOLONG;
            if (rename(path, older))
                return -errno;
        }
    }
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -errno;
    int error = write(fd, line, (size_t)n) == n ? 0 : -EIO;
    if (close(fd) && !error)
        error = -errno;
    return error;
}
