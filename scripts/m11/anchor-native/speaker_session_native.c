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
#define AW_SWITCH_0 "aw_dev_0_switch"
#define AW_SWITCH_1 "aw_dev_1_switch"

typedef struct {
    const m11_speaker_io *io;
    m11_speaker_report *rep;
    m11_shmem_region_t *cmd, *data;
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

/* a command with a DSP status: 0 only for transaction 0 and status 0 */
static int cmd_to(sess *s, uint32_t dst, uint32_t opcode, const void *pl, size_t len) {
    uint32_t dsp = UINT32_MAX;
    int rc = m11_gpr_engine_transact(s->io->eng, dst, opcode, pl, len, s->io->cmd_timeout_ms, &dsp, NULL, 0, NULL);
    if (s->io->eng->pdr_down) s->rep->pdr_seen = 1;
    if (rc) return rc;
    return dsp ? -EREMOTEIO : 0;
}
static int apm(sess *s, uint32_t opcode, const void *pl, size_t len) {
    return cmd_to(s, M11_APM_MODULE_IID, opcode, pl, len);
}

/* GRAPH_OPEN or SET_CFG out of band: the blob at offset 0 of the command region, CPU bracket around the copy */
static int oob(sess *s, uint32_t opcode, const m11_plan_blob *b) {
    if (!b->len) return 0;
    if (b->len > s->cmd->aligned_bytes) return -E2BIG;
    int rc = m11_shmem_begin_cpu_access(s->io->mgr, s->cmd);
    if (rc) return rc;
    memcpy(s->cmd->vaddr, b->data, b->len);
    if ((rc = m11_shmem_end_cpu_access(s->io->mgr, s->cmd))) return rc;
    m11_apm_cmd_header_t h = {0u, 0u, s->cmd->mem_map_handle, b->len};
    return apm(s, opcode, &h, sizeof h);
}

/* SET_CFG in band: <header, payload size> then the parameters. Stock gsl_graph_set_custom_config (libar-gsl
 * 0x1180a4) addresses a payload of exactly one parameter to that parameter's module instance and anything else to
 * APM, in band up to 256 bytes. */
static int inband(sess *s, const m11_plan_blob *b) {
    uint8_t pkt[sizeof(m11_apm_cmd_header_t) + M11_PLAN_MAX_INBAND];
    if (b->len > 256u || b->len < 16u) return -E2BIG;
    uint32_t first[3];
    memcpy(first, b->data, sizeof first);
    const uint32_t dst = (((first[2] + 7u) & ~7u) + 16u == b->len) ? first[0] : M11_APM_MODULE_IID;
    m11_apm_cmd_header_t h = {0u, 0u, 0u, b->len};
    memcpy(pkt, &h, sizeof h);
    memcpy(pkt + sizeof h, b->data, b->len);
    return cmd_to(s, dst, M11_APM_CMD_SET_CFG, pkt, sizeof h + b->len);
}

static int mgmt(sess *s, uint32_t opcode, const m11_plan_graph *g) {
    uint32_t dsp = UINT32_MAX;
    int rc = m11_apm_transact_graph_mgmt(s->io->eng, opcode, g->sgs, g->num_sgs, s->io->cmd_timeout_ms, &dsp);
    if (s->io->eng->pdr_down) s->rep->pdr_seen = 1;
    if (rc) return rc;
    return dsp ? -EREMOTEIO : 0;
}

static int graph_bring_up(sess *s, const m11_plan_graph *g, int base, const char *tag) {
    char nm[24];
    int rc;
    snprintf(nm, sizeof nm, "%s_open", tag);
    if ((rc = oob(s, M11_APM_CMD_GRAPH_OPEN, &g->open))) return fail(s, base, nm, rc);
    if (g->graph_id == 1) s->rep->vi_opened = 1; else s->rep->rx_opened = 1;
    done(s, base, nm);
    snprintf(nm, sizeof nm, "%s_cal", tag);
    if ((rc = oob(s, M11_APM_CMD_SET_CFG, &g->cal))) return fail(s, base + 1, nm, rc);
    done(s, base + 1, nm);
    snprintf(nm, sizeof nm, "%s_cfg", tag);
    for (uint32_t i = 0; i < g->num_cfgs; i++) {
        if ((rc = inband(s, &g->cfg[i]))) {
            rec(s, "phase=spk cfg=%s index=%u rc=%d", tag, i, rc);
            return fail(s, base + 2, nm, rc);
        }
    }
    done(s, base + 2, nm);
    return 0;
}

static int region_write(sess *s, uint32_t off, const void *src, uint32_t len) {
    if ((size_t)off + len > s->data->aligned_bytes) return -E2BIG;
    int rc = m11_shmem_begin_cpu_access(s->io->mgr, s->data);
    if (rc) return rc;
    memcpy((uint8_t *)s->data->vaddr + off, src, len);
    return m11_shmem_end_cpu_access(s->io->mgr, s->data);
}

static int submit_write(sess *s, unsigned i, uint32_t off, uint32_t len) {
    uint32_t cmd[11] = {off, 0u, s->data->mem_map_handle, len, 0u, 0u, 0u, 0u, 0u, 0u, 0u};
    int rc = m11_gpr_engine_submit_ex(s->io->eng, 0, s->io->plan->wr_ep, M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2,
                                      cmd, sizeof cmd, &s->wr_tok[i]);
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
        int rc = m11_gpr_engine_wait_token(io->eng, s->wr_tok[head], io->cmd_timeout_ms, &dsp, NULL, 0, NULL);
        if (io->eng->pdr_down) s->rep->pdr_seen = 1;
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
    const int dsp_ok = !io->eng->pdr_down;
    if (r->rx_started && dsp_ok) {
        rc = mgmt(s, M11_APM_CMD_GRAPH_STOP, &io->plan->rx);
        rec(s, "phase=spk teardown=rx_stop rc=%d", rc);
        if (rc && !r->teardown_rc) r->teardown_rc = rc;
    }
    if (s->rx_be_open) {
        rc = m11_snd_pcm_close(io->snd, M11_SND_RX);
        rec(s, "phase=spk teardown=rx_be_close rc=%d", rc);
        if (rc && !r->teardown_rc) r->teardown_rc = rc;
    }
    if (r->vi_started && dsp_ok) {
        rc = mgmt(s, M11_APM_CMD_GRAPH_STOP, &io->plan->vi);
        rec(s, "phase=spk teardown=vi_stop rc=%d", rc);
        if (rc && !r->teardown_rc) r->teardown_rc = rc;
    }
    if (s->vi_be_open) {
        rc = m11_snd_pcm_close(io->snd, M11_SND_TX);
        rec(s, "phase=spk teardown=vi_be_close rc=%d", rc);
        if (rc && !r->teardown_rc) r->teardown_rc = rc;
    }
    if (r->rx_opened && dsp_ok) {
        rc = mgmt(s, M11_APM_CMD_GRAPH_CLOSE, &io->plan->rx);
        rec(s, "phase=spk teardown=rx_close rc=%d", rc);
        if (rc && !r->teardown_rc) r->teardown_rc = rc;
    }
    if (r->vi_opened && dsp_ok) {
        rc = mgmt(s, M11_APM_CMD_GRAPH_CLOSE, &io->plan->vi);
        rec(s, "phase=spk teardown=vi_close rc=%d", rc);
        if (rc && !r->teardown_rc) r->teardown_rc = rc;
    }
    /* the read buffers: collect what completed (their slots), never re-queue */
    for (unsigned i = 0; i < r->rd_queued && dsp_ok; i++) {
        uint32_t dsp = 0;
        if (!m11_gpr_engine_wait_token(io->eng, s->rd_tok[i], 1u, &dsp, NULL, 0, NULL) && !dsp) r->rd_done++;
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
    s->cmd = io->region_fn(io->user, slot[0]);
    s->data = io->region_fn(io->user, slot[1]);
    if (!s->cmd || !s->data || !s->cmd->vaddr || !s->data->vaddr || !s->cmd->mem_map_handle || !s->data->mem_map_handle)
        return fail(s, M11_SPK_MAPPED, "map", -EPROTO);
    done(s, M11_SPK_MAPPED, "map");

    /* 3. VI feedback graph */
    const m11_plan_backend *tx = &p->backend[1], *rxb = &p->backend[0];
    if ((rc = m11_snd_pcm_open(io->snd, M11_SND_TX, tx->rate, tx->channels, tx->format, tx->period, tx->periods,
                               tx->period / 4u, INT_MAX)))
        return fail(s, M11_SPK_VI_BE_OPEN, "vi_be_open", rc);
    s->vi_be_open = 1;
    done(s, M11_SPK_VI_BE_OPEN, "vi_be_open");
    if ((rc = graph_bring_up(s, &p->vi, M11_SPK_VI_OPEN, "vi"))) return rc;
    if ((rc = mgmt(s, M11_APM_CMD_GRAPH_PREPARE, &p->vi))) return fail(s, M11_SPK_VI_PREPARE, "vi_prepare", rc);
    done(s, M11_SPK_VI_PREPARE, "vi_prepare");
    if ((rc = mgmt(s, M11_APM_CMD_GRAPH_START, &p->vi))) return fail(s, M11_SPK_VI_START, "vi_start", rc);
    r->vi_started = 1;
    done(s, M11_SPK_VI_START, "vi_start");
    const uint32_t rd_base = chunk * io->write_buffers;
    for (unsigned i = 0; i < RD_BUFFERS; i++) {
        uint32_t cmd[8] = {rd_base + i * rd_chunk, 0u, s->data->mem_map_handle, rd_chunk, 0u, 0u, 0u, 0u};
        if ((rc = m11_gpr_engine_submit_ex(io->eng, 0, p->rd_ep, M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2, cmd,
                                           sizeof cmd, &s->rd_tok[i])))
            return fail(s, M11_SPK_VI_READS, "vi_reads", rc);
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
    if ((rc = graph_bring_up(s, &p->rx, M11_SPK_RX_OPEN, "rx"))) return rc;
    const m11_aw_safety_context_t ctx = {.aw_dev_0_switch = 0, .aw_dev_1_switch = 0, .amp_enable_requested = false,
        .vi_tx_subgraph_opened = true, .vi_tx_subgraph_prepared = true,
        .vi_tx_module_iid = M11_AW_VI_TX_MODULE_IID, .sp_rx_module_iid = M11_AW_SP_RX_MODULE_IID};
    m11_aw_cal_pair_t cal = {{p->re_mohm[0], p->re_mohm[1]},
                             {m11_aw_mohm_to_q12(p->re_mohm[0]), m11_aw_mohm_to_q12(p->re_mohm[1])}};
    rc = m11_aw_apply_and_verify_re_dsp_ex(io->eng, &ctx, &cal, io->cmd_timeout_ms, &r->re);
    if (rc || !r->re.pair_re_readback_verified) return fail(s, M11_SPK_RX_RE, "rx_re", rc ? rc : -EIO);
    done(s, M11_SPK_RX_RE, "rx_re");
    if ((rc = mgmt(s, M11_APM_CMD_GRAPH_PREPARE, &p->rx))) return fail(s, M11_SPK_RX_PREPARE, "rx_prepare", rc);
    done(s, M11_SPK_RX_PREPARE, "rx_prepare");
    if ((rc = mgmt(s, M11_APM_CMD_GRAPH_START, &p->rx))) return fail(s, M11_SPK_RX_START, "rx_start", rc);
    r->rx_started = 1;
    done(s, M11_SPK_RX_START, "rx_start");

    /* 5. gate (a switch found not Disable is driven Disable by the teardown, whoever set it) */
    if (io->eng->pdr_down) return fail(s, M11_SPK_GATE, "gate", -ENETRESET);
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
    rc = m11_gpr_engine_submit_ex(io->eng, 0, p->wr_ep, M11_DATA_CMD_WR_SH_MEM_EP_EOS, &policy, sizeof policy, &eos_tok);
    if (!rc) rc = m11_gpr_engine_wait_token(io->eng, eos_tok, io->eos_timeout_ms, &dsp, NULL, 0, NULL);
    if (!rc && dsp) rc = -EREMOTEIO;
    r->eos_rc = rc;
    if (rc) return fail(s, M11_SPK_EOS, "eos", rc);
    done(s, M11_SPK_EOS, "eos");
    return 0;
}

int m11_speaker_session_run(const m11_speaker_io *io, m11_speaker_report *rep) {
    if (!io || !rep || !io->eng || !io->mgr || !io->map_fn || !io->region_fn || !io->plan || !io->now_fn ||
        !io->cmd_timeout_ms || !io->eos_timeout_ms || !io->amp_window_ms || !io->region_bytes)
        return -EINVAL;
    memset(rep, 0, sizeof *rep);
    sess s = {.io = io, .rep = rep};
    int rc = run(&s);
    teardown(&s);
    if (!rc && rep->teardown_rc) rc = rep->teardown_rc;
    if (!rc && !rep->amp_off_verified) rc = -EIO;
    return rc;
}
