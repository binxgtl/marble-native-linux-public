/* P5 W5: the speaker session plan parser (speaker_plan_native.h). */
#ifndef M11_CUSTODIAN_NATIVE
#error "speaker_plan_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#define _GNU_SOURCE
#include "speaker_plan_native.h"
#include <errno.h>
#include <string.h>

enum { SEC_GRAPH = 1, SEC_IDS, SEC_BACKEND, SEC_CONTROL, SEC_RE, SEC_SIGNAL, SEC_PCM };
static const uint32_t order[] = {SEC_GRAPH, SEC_GRAPH, SEC_IDS, SEC_BACKEND, SEC_CONTROL, SEC_RE, SEC_SIGNAL, SEC_PCM};
#define NSEC (sizeof order / sizeof order[0])
#define HEADER 64u

typedef struct { const uint8_t *p; size_t n, at; } rd;

static int u32(rd *r, uint32_t *v) {
    if (r->n - r->at < 4) return -1;
    memcpy(v, r->p + r->at, 4);
    r->at += 4;
    return 0;
}
static size_t pad8(size_t n) { return (n + 7u) & ~(size_t)7u; }

/* <len u32><len bytes, padded to 8> */
static int blob(rd *r, m11_plan_blob *b, uint32_t max) {
    uint32_t len;
    if (u32(r, &len) || len > max || pad8(len) > r->n - r->at) return -1;
    b->data = r->p + r->at;
    b->len = len;
    r->at += pad8(len);
    return 0;
}

/* a sequence of apm_module_param_data_t blocks that fills the blob exactly, each with error code 0 */
static int params_ok(const m11_plan_blob *b) {
    size_t at = 0;
    if (!b->len) return 0;
    while (at < b->len) {
        uint32_t hdr[4];
        if (b->len - at < sizeof hdr) return 0;
        memcpy(hdr, b->data + at, sizeof hdr);
        if (!hdr[0] || !hdr[1] || hdr[3] || hdr[2] > b->len - at - sizeof hdr) return 0;
        at += sizeof hdr + pad8(hdr[2]);
        if (at > b->len) return 0;
    }
    return at == b->len;
}

static int graph(rd *r, m11_plan_graph *g, uint32_t want_id) {
    if (u32(r, &g->graph_id) || g->graph_id != want_id || u32(r, &g->num_sgs) || !g->num_sgs ||
        g->num_sgs > M11_PLAN_MAX_SGS)
        return -1;
    for (uint32_t i = 0; i < g->num_sgs; i++) {
        if (u32(r, &g->sgs[i]) || (g->sgs[i] & 0xFF000000u) != 0xB0000000u) return -1;
        for (uint32_t j = 0; j < i; j++) if (g->sgs[j] == g->sgs[i]) return -1;
    }
    if (blob(r, &g->open, M11_PLAN_MAX_OOB) || !params_ok(&g->open) ||
        blob(r, &g->cal, M11_PLAN_MAX_OOB) || !params_ok(&g->cal) ||
        u32(r, &g->num_cfgs) || g->num_cfgs > M11_PLAN_MAX_CFGS)
        return -1;
    for (uint32_t i = 0; i < g->num_cfgs; i++) {
        if (blob(r, &g->cfg[i], M11_PLAN_MAX_INBAND) || !params_ok(&g->cfg[i])) return -1;
    }
    return r->at == r->n ? 0 : -1;
}

static int bounded_string(const uint8_t *src, size_t cap, char *dst) {
    size_t n = strnlen((const char *)src, cap);
    if (!n || n == cap) return -1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    for (size_t i = 0; i < n; i++) if (dst[i] < 0x21 || dst[i] > 0x7e) return -1;
    return 0;
}

int m11_speaker_plan_parse(const uint8_t *buf, size_t len, m11_speaker_plan *out) {
    if (!buf || !out || len < HEADER) return -EBADMSG;
    memset(out, 0, sizeof *out);
    uint32_t version, total, nsec, hsize;
    memcpy(&version, buf + 8, 4);
    memcpy(&total, buf + 12, 4);
    memcpy(&nsec, buf + 16, 4);
    memcpy(&hsize, buf + 20, 4);
    if (memcmp(buf, "M11SPK01", 8) || version != 1 || total != len || nsec != NSEC || hsize != HEADER)
        return -EBADMSG;
    memcpy(out->acdb_sha256, buf + 24, 32);
    size_t at = HEADER;
    for (size_t s = 0; s < NSEC; s++) {
        uint32_t type, n;
        if (len - at < 8) return -EBADMSG;
        memcpy(&type, buf + at, 4);
        memcpy(&n, buf + at + 4, 4);
        at += 8;
        if (type != order[s] || n > len - at || pad8(n) > len - at) return -EBADMSG;
        rd r = {buf + at, n, 0};
        int bad = 0;
        switch (type) {
        case SEC_GRAPH:
            bad = graph(&r, s == 0 ? &out->vi : &out->rx, s == 0 ? 1u : 2u);
            break;
        case SEC_IDS: {
            uint32_t v[14];
            if (n != sizeof v) return -EBADMSG;
            memcpy(v, r.p, sizeof v);
            out->wr_ep = v[0]; out->rd_ep = v[1]; out->sp_rx = v[2]; out->vi_tx = v[3];
            out->tdm_sink = v[4]; out->tdm_source = v[5]; out->volume = v[6];
            out->stream_rate = v[7]; out->stream_format = v[8]; out->stream_channels = v[9];
            out->vi_rate = v[10]; out->vi_format = v[11]; out->vi_channels = v[12]; out->volume_level = v[13];
            for (int i = 0; i < 7; i++) if (!v[i]) return -EBADMSG;
            if (out->volume_level > 15 || !out->stream_rate || out->stream_channels != 2 || out->vi_channels != 2)
                return -EBADMSG;
            break;
        }
        case SEC_BACKEND:
            if (n != 2 * 88u) return -EBADMSG;
            for (int i = 0; i < 2; i++) {
                m11_plan_backend *b = &out->backend[i];
                uint32_t v[6];
                memcpy(v, r.p + 88 * i, sizeof v);
                b->direction = v[0]; b->rate = v[1]; b->channels = v[2]; b->format = v[3];
                b->period = v[4]; b->periods = v[5];
                if (b->direction != (uint32_t)i || bounded_string(r.p + 88 * i + 24, 64, b->name)) return -EBADMSG;
            }
            break;
        case SEC_CONTROL:
            if (!n || n % 64u || n / 64u > M11_PLAN_MAX_CTLS) return -EBADMSG;
            out->num_controls = n / 64u;
            for (uint32_t i = 0; i < out->num_controls; i++) {
                if (bounded_string(r.p + 64 * i, 44, out->control[i].name) ||
                    bounded_string(r.p + 64 * i + 44, 20, out->control[i].value))
                    return -EBADMSG;
            }
            break;
        case SEC_RE:
            if (n != 8) return -EBADMSG;
            memcpy(out->re_mohm, r.p, 8);
            if (out->re_mohm[0] <= 0 || out->re_mohm[1] <= 0 || out->re_mohm[0] > 524287 || out->re_mohm[1] > 524287)
                return -EBADMSG;
            break;
        case SEC_SIGNAL: {
            uint32_t v[5];
            if (n < sizeof v) return -EBADMSG;
            memcpy(v, r.p, sizeof v);
            out->duration_ms = v[0]; out->fade_ms = v[1]; out->num_tones = v[2];
            memcpy(&out->peak_mdbfs, &v[3], 4);
            if (n != sizeof v + 4u * out->num_tones || !out->num_tones || out->duration_ms < 500 ||
                out->duration_ms > 10000 || out->peak_mdbfs > -6000 || out->peak_mdbfs < -40000)
                return -EBADMSG;
            break;
        }
        case SEC_PCM: {
            /* exactly duration x rate frames of 16-bit stereo, rounded down per tone by the generator */
            uint64_t max = (uint64_t)out->stream_rate * out->duration_ms / 1000u * out->stream_channels * 2u;
            if (!n || n % (2u * out->stream_channels) || n > max) return -EBADMSG;
            out->pcm.data = r.p;
            out->pcm.len = n;
            break;
        }
        }
        if (bad) return -EBADMSG;
        at += pad8(n);
    }
    return at == len ? 0 : -EBADMSG;
}
