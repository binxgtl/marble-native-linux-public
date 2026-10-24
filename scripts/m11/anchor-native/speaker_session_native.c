/* P5 W5: the native speaker session (speaker_session_native.h has the order and the rules). */
#ifndef M11_CUSTODIAN_NATIVE
#error "speaker_session_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#define _GNU_SOURCE
#include "speaker_session_native.h"
#include "../qualification/runtime-repair/m11_apm_protocol.h"
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define RD_BUFFERS 2u
#define RD_BUFFER_MS 20u
#define OOB_ALIGN 4096u
#define AW_SWITCH_0 "aw_dev_0_switch"
#define AW_SWITCH_1 "aw_dev_1_switch"

typedef struct {
    const m11_speaker_io *io;
    m11_speaker_report *rep;
    unsigned cmd, data;                     /* custodian regions */
    unsigned g_vi, g_rx;                    /* custodian graphs (UINT_MAX: never opened) */
    uint32_t oob_next;                      /* the next unused out-of-band offset of the command region */
    int vi_be_open, rx_be_open;
    uint32_t wr_tok[8], rd_tok[RD_BUFFERS];
} sess;

static void rec(sess *s, const char *fmt, ...) {
    if (!s->io->record_fn) return;
    char line[160];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n > 0) s->io->record_fn(s->io->user, line);
}

static uint64_t now(sess *s) { return s->io->now_fn(s->io->user); }
static m11_gpr_engine_t *eng(sess *s) { return s->io->cust->mgr->gpr; }
/* after every custodian call and wait: the caller's settle (a PD DOWN reaches the custodian), then the note */
static void pdr_note(sess *s) {
    if (s->io->settle_fn) s->io->settle_fn(s->io->user);
    if (eng(s)->pdr_down) s->rep->pdr_seen = 1;
}
static m11_custodian_graph_state gstate(sess *s, unsigned g) {
    return g < M11_CUSTODIAN_GRAPHS ? s->io->cust->graphs[g].state : M11_GRAPH_FREE;
}

/* a step that succeeded */
static void done(sess *s, int stage, const char *name) {
    s->rep->stage = stage;
    rec(s, "phase=spk step=%d %s rc=0", stage, name);
}
/* the first failure; later failures (teardown) keep the first */
static int fail(sess *s, int stage, const char *name, int rc) {
    if (!rc) rc = -EPROTO;
    if (!s->rep->rc) { s->rep->rc = rc; s->rep->fail_step = stage; }
    rec(s, "phase=spk step=%d %s rc=%d", stage, name, rc);
    return rc;
}

/* the next out-of-band offset: each payload its own OOB_ALIGN-aligned place, never reused in the boot */
static int oob_place(sess *s, uint32_t len, uint32_t *off) {
    const size_t cap = s->io->cust->regions[s->cmd].aligned_bytes;
    if (!len || (size_t)s->oob_next + len > cap) return -E2BIG;
    *off = s->oob_next;
    s->oob_next = (uint32_t)(((size_t)s->oob_next + len + OOB_ALIGN - 1u) / OOB_ALIGN * OOB_ALIGN);
    return 0;
}

/* SET_CFG in band: <header, payload size> then the parameters. Stock gsl_graph_set_custom_config (libar-gsl
 * 0x1180a4) addresses a payload of exactly one parameter to that parameter's module instance and anything else to
 * APM, in band up to 256 bytes. */
static int inband(sess *s, unsigned g, const m11_plan_blob *b) {
    uint8_t pkt[sizeof(m11_apm_cmd_header_t) + M11_PLAN_MAX_INBAND];
    if (b->len > 256u || b->len < 16u) return -E2BIG;
    uint32_t first[3];
    memcpy(first, b->data, sizeof first);
    const uint32_t dst = (((first[2] + 7u) & ~7u) + 16u == b->len) ? first[0] : M11_APM_MODULE_IID;
    m11_apm_cmd_header_t h = {0u, 0u, 0u, b->len};
    memcpy(pkt, &h, sizeof h);
    memcpy(pkt + sizeof h, b->data, b->len);
    int rc = m11_custodian_cfg(s->io->cust, g, dst, M11_APM_CMD_SET_CFG, pkt, (uint32_t)(sizeof h + b->len), now(s),
                               NULL, 0, NULL, NULL);
    pdr_note(s);
    return rc;
}

static int mgmt(sess *s, unsigned g, uint32_t opcode) {
    int rc = m11_custodian_graph_cmd(s->io->cust, g, opcode, now(s));
    pdr_note(s);
    return rc;
}

/* GRAPH_OPEN with the plan's payload, its calibration out of band, then the in-band configurations */
static int graph_bring_up(sess *s, const m11_plan_graph *g, unsigned *gi, int base, const char *tag) {
    char nm[24];
    uint32_t off = 0;
    int rc;
    snprintf(nm, sizeof nm, "%s_open", tag);
    if ((rc = oob_place(s, g->open.len, &off))) return fail(s, base, nm, rc);
    rc = m11_custodian_graph_open_blob(s->io->cust, s->cmd, off, g->open.data, g->open.len, g->sgs, g->num_sgs,
                                       now(s), gi);
    pdr_note(s);
    if (*gi != UINT_MAX) { if (g->graph_id == 1) s->rep->vi_opened = 1; else s->rep->rx_opened = 1; }
    if (rc) return fail(s, base, nm, rc);
    done(s, base, nm);
    snprintf(nm, sizeof nm, "%s_cal", tag);
    if (g->cal.len) {
        if (!(rc = oob_place(s, g->cal.len, &off)))
            rc = m11_custodian_cfg_oob(s->io->cust, *gi, s->cmd, off, g->cal.data, g->cal.len, now(s));
        pdr_note(s);
        if (rc) return fail(s, base + 1, nm, rc);
    }
    done(s, base + 1, nm);
    snprintf(nm, sizeof nm, "%s_cfg", tag);
    for (uint32_t i = 0; i < g->num_cfgs; i++) {
        if ((rc = inband(s, *gi, &g->cfg[i]))) {
            rec(s, "phase=spk cfg=%s index=%u rc=%d", tag, i, rc);
            return fail(s, base + 2, nm, rc);
        }
    }
    done(s, base + 2, nm);
    return 0;
}

/* the AW Re SET/GET round trip, through the custodian (its budget, not timeout_ms) */
static int aw_round_trip(void *user, uint32_t dst, uint32_t opcode, const void *pkt, size_t len, uint32_t timeout_ms,
                         void *rsp, size_t cap, size_t *rsp_len, bool *handed) {
    sess *s = user;
    (void)timeout_ms;
    int rc = m11_custodian_cfg(s->io->cust, s->g_rx, dst, opcode, pkt, (uint32_t)len, now(s), rsp, cap, rsp_len, handed);
    pdr_note(s);
    return rc;
}

static int region_write(sess *s, uint32_t off, const void *src, uint32_t len) {
    return m11_custodian_region_write(s->io->cust, s->data, off, src, len, now(s));
}

static int submit_write(sess *s, unsigned i, uint32_t off, uint32_t len) {
    uint32_t cmd[11] = {off, 0u, s->io->cust->regions[s->data].mem_map_handle, len, 0u, 0u, 0u, 0u, 0u, 0u, 0u};
    int rc = m11_custodian_data_submit(s->io->cust, s->g_rx, s->io->plan->wr_ep, M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2,
                                       cmd, sizeof cmd, now(s), &s->wr_tok[i]);
    pdr_note(s);
    if (!rc) s->rep->buffers_sent++;
    return rc;
}

/* the PCM through write_buffers buffers; each completed buffer is refilled with the next chunk */
static int play(sess *s, uint32_t chunk) {
    const m11_speaker_io *io = s->io;
    const m11_plan_blob *pcm = &io->plan->pcm;
    uint32_t next = 0;
    unsigned inflight = 0, head = 0;
    uint32_t sent_len[8] = {0};
    for (unsigned i = 0; i < io->write_buffers && next < pcm->len; i++) {
        uint32_t len = pcm->len - next < chunk ? pcm->len - next : chunk;
        int rc = region_write(s, i * chunk, pcm->data + next, len);
        if (!rc) rc = submit_write(s, i, i * chunk, len);
        if (rc) return rc;
        sent_len[i] = len;
        next += len;
        inflight++;
    }
    while (inflight) {
        if (now(s) - s->rep->amp_on_ms > io->amp_window_ms) return -ETIME;
        uint32_t dsp = UINT32_MAX;
        int rc = m11_gpr_engine_wait_token(eng(s), s->wr_tok[head], io->wait_timeout_ms, &dsp, NULL, 0, NULL);
        pdr_note(s);
        if (rc) return rc;
        if (dsp) return -EREMOTEIO;
        s->rep->buffers_done++;
        s->rep->bytes_played += sent_len[head];
        inflight--;
        if (next < pcm->len) {
            uint32_t len = pcm->len - next < chunk ? pcm->len - next : chunk;
            if ((rc = region_write(s, head * chunk, pcm->data + next, len)) ||
                (rc = submit_write(s, head, head * chunk, len)))
                return rc;
            sent_len[head] = len;
            next += len;
            inflight++;
        }
        head = (head + 1) % io->write_buffers;
    }
    return 0;
}

static int set_switches(sess *s, const char *item) {
    int a = m11_snd_ctl_set(s->io->snd, AW_SWITCH_0, item);
    int b = m11_snd_ctl_set(s->io->snd, AW_SWITCH_1, item);
    return a ? a : b;
}

static int switches_read(sess *s, const char *want) {
    char v0[64], v1[64];
    int rc = m11_snd_ctl_get(s->io->snd, AW_SWITCH_0, v0, sizeof v0);
    if (!rc) rc = m11_snd_ctl_get(s->io->snd, AW_SWITCH_1, v1, sizeof v1);
    if (rc) return rc;
    return strcmp(v0, want) || strcmp(v1, want) ? -EIO : 0;
}

static void td_graph(sess *s, unsigned g, uint32_t opcode, const char *name) {
    int rc = mgmt(s, g, opcode);
    rec(s, "phase=spk teardown=%s rc=%d", name, rc);
    if (rc && !s->rep->teardown_rc) s->rep->teardown_rc = rc;
}

static void teardown(sess *s) {
    const m11_speaker_io *io = s->io;
    m11_speaker_report *r = s->rep;
    int rc;
    if (r->amp_touched) {
        rc = set_switches(s, "Disable");
        if (!rc) rc = switches_read(s, "Disable");
        r->amp_off_verified = !rc;
        r->amp_off_ms = now(s);
        rec(s, "phase=spk teardown=amp_off rc=%d ms=%llu", rc, (unsigned long long)(r->amp_off_ms - r->amp_on_ms));
        if (rc && !r->teardown_rc) r->teardown_rc = rc;
    }
    /* the graphs as the ledger stands: STOP a STARTED one, CLOSE an OPEN or PREPARED one; an UNKNOWN one is
     * never commanded again (it stays pinned; the boot ends retaining) */
    const int dsp_ok = !eng(s)->pdr_down;
    if (dsp_ok && gstate(s, s->g_rx) == M11_GRAPH_STARTED) td_graph(s, s->g_rx, M11_APM_CMD_GRAPH_STOP, "rx_stop");
    if (s->rx_be_open) {
        rc = m11_snd_pcm_close(io->snd, M11_SND_RX);
        rec(s, "phase=spk teardown=rx_be_close rc=%d", rc);
        if (rc && !r->teardown_rc) r->teardown_rc = rc;
    }
    if (dsp_ok && gstate(s, s->g_vi) == M11_GRAPH_STARTED) td_graph(s, s->g_vi, M11_APM_CMD_GRAPH_STOP, "vi_stop");
    if (s->vi_be_open) {
        rc = m11_snd_pcm_close(io->snd, M11_SND_TX);
        rec(s, "phase=spk teardown=vi_be_close rc=%d", rc);
        if (rc && !r->teardown_rc) r->teardown_rc = rc;
    }
    const unsigned gs[2] = {s->g_rx, s->g_vi};
    static const char *const close_nm[2] = {"rx_close", "vi_close"};
    for (int i = 0; i < 2; i++) {
        const m11_custodian_graph_state st = gstate(s, gs[i]);
        if (dsp_ok && (st == M11_GRAPH_OPEN || st == M11_GRAPH_PREPARED)) td_graph(s, gs[i], M11_APM_CMD_GRAPH_CLOSE, close_nm[i]);
        if (gstate(s, gs[i]) == M11_GRAPH_UNKNOWN) {
            rec(s, "phase=spk teardown=%s graph=unknown", close_nm[i]);
            if (!r->teardown_rc) r->teardown_rc = -EOWNERDEAD;
        }
    }
    /* the read buffers: collect what completed (their slots), never re-queue */
    for (unsigned i = 0; i < r->rd_queued && dsp_ok; i++) {
        uint32_t dsp = 0;
        if (!m11_gpr_engine_wait_token(eng(s), s->rd_tok[i], 1u, &dsp, NULL, 0, NULL) && !dsp) r->rd_done++;
    }
    rec(s, "phase=spk end rc=%d step=%d sent=%u done=%u bytes=%u eos=%d amp_off=%d teardown=%d pdr=%d",
        r->rc, r->fail_step, r->buffers_sent, r->buffers_done, r->bytes_played, r->eos_rc, r->amp_off_verified,
        r->teardown_rc, r->pdr_seen);
}

static int run(sess *s) {
    const m11_speaker_io *io = s->io;
    const m11_speaker_plan *p = io->plan;
    m11_speaker_report *r = s->rep;
    int rc;

    /* 1. plan and amplifier pre-checks */
    if (p->sp_rx != M11_AW_SP_RX_MODULE_IID || p->vi_tx != M11_AW_VI_TX_MODULE_IID ||
        p->backend[0].direction != 0 || p->backend[1].direction != 1 || !io->snd || io->snd->ctl_fd < 0 ||
        p->vi.graph_id != 1 || p->rx.graph_id != 2 ||
        io->write_buffers < 2 || io->write_buffers > 8 || io->buffer_ms < 10 || io->buffer_ms > 100)
        return fail(s, M11_SPK_PLAN, "plan", -EINVAL);
    const uint32_t frame = p->stream_channels * 2u;
    const uint32_t chunk = p->stream_rate / 1000u * io->buffer_ms * frame;
    const uint32_t rd_chunk = p->vi_rate / 1000u * RD_BUFFER_MS * p->vi_channels * 2u;
    if (!chunk || (size_t)chunk * io->write_buffers + (size_t)rd_chunk * RD_BUFFERS > io->region_bytes)
        return fail(s, M11_SPK_PLAN, "plan", -E2BIG);
    done(s, M11_SPK_PLAN, "plan");
    if ((rc = set_switches(s, "Disable")) || (rc = switches_read(s, "Disable")))
        return fail(s, M11_SPK_AMP_OFF, "amp_off", rc);
    for (uint32_t i = 0; i < p->num_controls; i++) {
        if ((rc = m11_snd_ctl_set(io->snd, p->control[i].name, p->control[i].value)))
            return fail(s, M11_SPK_AMP_OFF, "amp_off", rc);
    }
    done(s, M11_SPK_AMP_OFF, "amp_off");

    /* 2. the two regions, through the custodian */
    unsigned slot[2];
    for (int i = 0; i < 2; i++) {
        if ((rc = io->map_fn(io->user, io->region_bytes, &slot[i]))) return fail(s, M11_SPK_MAPPED, "map", rc);
        r->regions_mapped++;
    }
    for (int i = 0; i < 2; i++) {
        const m11_shmem_region_t *reg = slot[i] < M11_CUSTODIAN_REGIONS ? &io->cust->regions[slot[i]] : NULL;
        if (!reg || !io->cust->occupied[slot[i]] || reg->state != M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED || !reg->vaddr ||
            !reg->mem_map_handle || reg->aligned_bytes < io->region_bytes)
            return fail(s, M11_SPK_MAPPED, "map", -EPROTO);
    }
    s->cmd = slot[0];
    s->data = slot[1];
    done(s, M11_SPK_MAPPED, "map");

    /* 3. VI feedback graph */
    const m11_plan_backend *tx = &p->backend[1], *rxb = &p->backend[0];
    if ((rc = m11_snd_pcm_open(io->snd, M11_SND_TX, tx->rate, tx->channels, tx->format, tx->period, tx->periods,
                               tx->period / 4u, INT_MAX)))
        return fail(s, M11_SPK_VI_BE_OPEN, "vi_be_open", rc);
    s->vi_be_open = 1;
    done(s, M11_SPK_VI_BE_OPEN, "vi_be_open");
    if ((rc = graph_bring_up(s, &p->vi, &s->g_vi, M11_SPK_VI_OPEN, "vi"))) return rc;
    if ((rc = mgmt(s, s->g_vi, M11_APM_CMD_GRAPH_PREPARE))) return fail(s, M11_SPK_VI_PREPARE, "vi_prepare", rc);
    done(s, M11_SPK_VI_PREPARE, "vi_prepare");
    if ((rc = mgmt(s, s->g_vi, M11_APM_CMD_GRAPH_START))) return fail(s, M11_SPK_VI_START, "vi_start", rc);
    r->vi_started = 1;
    done(s, M11_SPK_VI_START, "vi_start");
    const uint32_t rd_base = chunk * io->write_buffers;
    for (unsigned i = 0; i < RD_BUFFERS; i++) {
        uint32_t cmd[8] = {rd_base + i * rd_chunk, 0u, io->cust->regions[s->data].mem_map_handle, rd_chunk, 0u, 0u, 0u, 0u};
        rc = m11_custodian_data_submit(io->cust, s->g_vi, p->rd_ep, M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2, cmd,
                                       sizeof cmd, now(s), &s->rd_tok[i]);
        pdr_note(s);
        if (rc) return fail(s, M11_SPK_VI_READS, "vi_reads", rc);
        r->rd_queued++;
    }
    done(s, M11_SPK_VI_READS, "vi_reads");
    if ((rc = m11_snd_pcm_prepare(io->snd, M11_SND_TX))) return fail(s, M11_SPK_VI_BE_PREPARE, "vi_be_prepare", rc);
    done(s, M11_SPK_VI_BE_PREPARE, "vi_be_prepare");

    /* 4. RX speaker graph */
    if ((rc = m11_snd_pcm_open(io->snd, M11_SND_RX, rxb->rate, rxb->channels, rxb->format, rxb->period,
                               rxb->periods, rxb->period / 4u, INT_MAX)))
        return fail(s, M11_SPK_RX_BE_OPEN, "rx_be_open", rc);
    s->rx_be_open = 1;
    done(s, M11_SPK_RX_BE_OPEN, "rx_be_open");
    if ((rc = graph_bring_up(s, &p->rx, &s->g_rx, M11_SPK_RX_OPEN, "rx"))) return rc;
    /* the VI graph as the custodian's ledger has it (STARTED here: opened and prepared) */
    const m11_custodian_graph_state vst = gstate(s, s->g_vi);
    const m11_aw_safety_context_t ctx = {.aw_dev_0_switch = 0, .aw_dev_1_switch = 0, .amp_enable_requested = false,
        .vi_tx_subgraph_opened = vst == M11_GRAPH_OPEN || vst == M11_GRAPH_PREPARED || vst == M11_GRAPH_STARTED,
        .vi_tx_subgraph_prepared = vst == M11_GRAPH_PREPARED || vst == M11_GRAPH_STARTED,
        .vi_tx_module_iid = M11_AW_VI_TX_MODULE_IID, .sp_rx_module_iid = M11_AW_SP_RX_MODULE_IID};
    m11_aw_cal_pair_t cal = {{p->re_mohm[0], p->re_mohm[1]},
                             {m11_aw_mohm_to_q12(p->re_mohm[0]), m11_aw_mohm_to_q12(p->re_mohm[1])}};
    rc = m11_aw_apply_and_verify_re_via(aw_round_trip, s, &ctx, &cal, io->cust->mgr->timeout_ms, &r->re);
    /* per channel: stage, value written, value read back (0 unless a structurally valid GET_CFG came) */
    rec(s, "phase=spk re ch0=%d/%u/%u ch1=%d/%u/%u", (int)r->re.ch[0].stage, r->re.ch[0].requested_q12,
        r->re.ch[0].readback_q12, (int)r->re.ch[1].stage, r->re.ch[1].requested_q12, r->re.ch[1].readback_q12);
    if (rc || !r->re.pair_re_readback_verified) return fail(s, M11_SPK_RX_RE, "rx_re", rc ? rc : -EIO);
    done(s, M11_SPK_RX_RE, "rx_re");
    if ((rc = mgmt(s, s->g_rx, M11_APM_CMD_GRAPH_PREPARE))) return fail(s, M11_SPK_RX_PREPARE, "rx_prepare", rc);
    done(s, M11_SPK_RX_PREPARE, "rx_prepare");
    if ((rc = mgmt(s, s->g_rx, M11_APM_CMD_GRAPH_START))) return fail(s, M11_SPK_RX_START, "rx_start", rc);
    r->rx_started = 1;
    done(s, M11_SPK_RX_START, "rx_start");

    /* 5. gate (a switch found not Disable is driven Disable by the teardown, whoever set it) */
    if (eng(s)->pdr_down) return fail(s, M11_SPK_GATE, "gate", -ENETRESET);
    if ((rc = switches_read(s, "Disable"))) { r->amp_touched = 1; return fail(s, M11_SPK_GATE, "gate", rc); }
    done(s, M11_SPK_GATE, "gate");

    /* 6. amplifier on, then the RX back end prepare */
    r->amp_touched = 1;
    r->amp_on_ms = now(s);
    if ((rc = set_switches(s, "Enable")) || (rc = switches_read(s, "Enable"))) return fail(s, M11_SPK_AMP_ON, "amp_on", rc);
    r->amp_on = 1;
    done(s, M11_SPK_AMP_ON, "amp_on");
    if ((rc = m11_snd_pcm_prepare(io->snd, M11_SND_RX))) return fail(s, M11_SPK_RX_BE_PREPARE, "rx_be_prepare", rc);
    done(s, M11_SPK_RX_BE_PREPARE, "rx_be_prepare");

    /* 7. play, then EOS */
    if ((rc = play(s, chunk))) return fail(s, M11_SPK_PLAYED, "play", rc);
    done(s, M11_SPK_PLAYED, "play");
    uint32_t policy = 1u, eos_tok = 0u, dsp = UINT32_MAX;
    rc = m11_custodian_data_submit(io->cust, s->g_rx, p->wr_ep, M11_DATA_CMD_WR_SH_MEM_EP_EOS, &policy, sizeof policy,
                                   now(s), &eos_tok);
    if (!rc) rc = m11_gpr_engine_wait_token(eng(s), eos_tok, io->eos_timeout_ms, &dsp, NULL, 0, NULL);
    pdr_note(s);
    if (!rc && dsp) rc = -EREMOTEIO;
    r->eos_rc = rc;
    if (rc) return fail(s, M11_SPK_EOS, "eos", rc);
    done(s, M11_SPK_EOS, "eos");
    return 0;
}

int m11_speaker_session_run(const m11_speaker_io *io, m11_speaker_report *rep) {
    if (!io || !rep || !io->cust || !io->cust->mgr || !io->cust->mgr->gpr || !io->map_fn || !io->plan || !io->now_fn ||
        !io->wait_timeout_ms || !io->eos_timeout_ms || !io->amp_window_ms || !io->region_bytes)
        return -EINVAL;
    memset(rep, 0, sizeof *rep);
    sess s = {.io = io, .rep = rep, .cmd = UINT_MAX, .data = UINT_MAX, .g_vi = UINT_MAX, .g_rx = UINT_MAX};
    int rc = run(&s);
    teardown(&s);
    if (!rc && rep->teardown_rc) rc = rep->teardown_rc;
    if (!rc && !rep->amp_off_verified) rc = -EIO;
    return rc;
}
