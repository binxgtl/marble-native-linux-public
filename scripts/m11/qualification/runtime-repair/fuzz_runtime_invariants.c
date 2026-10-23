/*
 * Deterministic fuzz / fault-injection harness for the hardened M11 GPR/DMA/APM runtime.
 *
 * Everything is seeded (xorshift64*, fixed default seeds), so a failure is reproducible with
 * `fuzz_runtime_invariants <iterations> <seed>`. Offline only: the strict mock stands in for
 * the kernel and the ADSP; nothing here talks to hardware. Evidence class: MOCK PASS.
 *
 *   F1  packet/payload validators on exact-size heap buffers (ASan/UBSan find OOB reads)
 *   F2  engine RX path with structured random packets (no crash, no sanitizer finding)
 *   F3  deadline oracle: random event/junk/ACK schedules on a fake clock; the outcome must
 *       follow the schedule exactly (P1)
 *   F4  whole speaker-qualification run under random fault injection; invariants over the
 *       final report and the mock state (P2..P6)
 *   F5  multi-region shmem state machine under random operations and faults; invariants after
 *       EVERY operation, then a drain phase with all faults cleared (P2, P4, P5)
 *
 * Exit status is non-zero when any invariant is violated. The first few violations of each kind
 * are printed with the iteration and seed.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "m11_apm_protocol.h"
#include "m11_aw_protection.h"
#include "m11_gpr_engine.h"
#include "m11_offline_sim.h"
#include "m11_shmem.h"
#include "m11_strict_mock.h"

#ifndef M11_RUNTIME_HARDENING_API_VERSION
#error "fuzz_runtime_invariants targets the hardened runtime only"
#endif

#ifndef ENETRESET
#define ENETRESET 102
#endif

/* ------------------------------------------------------------------------------------------
 * PRNG and violation bookkeeping
 * ---------------------------------------------------------------------------------------- */
static uint64_t g_state;
static uint64_t g_seed;

static uint32_t rnd(void) {
    g_state ^= g_state >> 12;
    g_state ^= g_state << 25;
    g_state ^= g_state >> 27;
    return (uint32_t)((g_state * 0x2545F4914F6CDD1Dull) >> 32);
}
static int pct(int p) { return (int)(rnd() % 100u) < p; }
static uint32_t below(uint32_t n) { return n ? rnd() % n : 0u; }

#define MAX_KINDS 64
static long g_viol[MAX_KINDS];
static const char *g_viol_name[MAX_KINDS];
static long g_total_viol;

static void violation(int kind, const char *name, long iter, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
#include <stdarg.h>
static void violation(int kind, const char *name, long iter, const char *fmt, ...) {
    g_total_viol++;
    g_viol_name[kind] = name;
    if (g_viol[kind]++ < 3) {
        va_list ap;
        va_start(ap, fmt);
        printf("VIOLATION %s at iteration %ld (seed %llu): ", name, iter, (unsigned long long)g_seed);
        vprintf(fmt, ap);
        printf("\n");
        va_end(ap);
    }
}
#define VIOL(kind, iter, ...) violation((kind), #kind, (iter), __VA_ARGS__)

enum {
    V_SIM_UNSAFE_RELEASE = 1, V_SIM_CLEAN_BUT_LIVE, V_SIM_SUCCESS_NOT_FULL, V_SIM_CLEAN_BUT_COUNTERS,
    V_SIM_INVARIANT_FLAGS, V_SIM_RESEND, V_SIM_CLEAN_BUT_DIRTY_RECORD, V_SIM_PAIR_CLAIM,
    V_DL_SUCCESS_AFTER_DEADLINE, V_DL_TIMEOUT_BEFORE_ACK, V_DL_OVERRUN, V_DL_UNDERRUN,
    V_SM_AUDIT, V_SM_UNSAFE_RELEASE, V_SM_RELEASED_DIRTY, V_SM_PENDING_NO_PROOF,
    V_SM_UNRESOLVED_SHAPE, V_SM_ACKED_MISMATCH, V_SM_RESEND, V_SM_ORPHAN_UNTRACKED,
    V_SM_DRAIN_STUCK, V_SM_DRAIN_LEAK, V_SM_COUNTERS_AT_END, V_SM_ERROR_LOST,
    V_SIM_POST_MAP_HOLD, V_SM_POST_MAP_HOLD
};

#ifndef M11_SHMEM_POST_MAP_HOLD
#error "fuzz_runtime_invariants targets the post-MAP hold (m11_shmem.h)"
#endif
/* Post-MAP hold (CP2 criterion 5, L3): a region whose MAP may have been transmitted (write_fn
 * entered, no unsent proof) is never released locally, whatever ACK, NACK or UNMAP follows. */
static int transmitted(const m11_shmem_region_t *r) {
    return r->map_tx_started && !r->map_tx_unsent_proof;
}
static int handles_held(const m11_shmem_region_t *r) {
    return r->dma_buf_fd >= 0 && r->vaddr != NULL && r->ion_imported;
}

/* ------------------------------------------------------------------------------------------
 * F1 / F3: validators on exact-size heap buffers
 * ---------------------------------------------------------------------------------------- */
static void fuzz_validators(long iters) {
    for (long i = 0; i < iters; i++) {
        size_t n = below(160);
        uint8_t *b = malloc(n ? n : 1);
        if (!b) abort();
        for (size_t k = 0; k < n; k++) b[k] = (uint8_t)(pct(40) ? 0 : rnd());
        if (n >= 24 && pct(70)) {
            uint32_t h = m11_gpr_make_header_word(0, 6, (uint32_t)n);
            memcpy(b, &h, 4);
            b[4] = pct(50) ? 2 : 3;
            b[5] = pct(50) ? 3 : 2;
            b[7] = 0;
        }
        m11_gpr_hdr_t h;
        const uint8_t *pl;
        size_t pn;
        (void)m11_gpr_validate_packet(b, n, &h, &pl, &pn);
        uint32_t ids[16], cnt;
        (void)m11_apm_validate_graph_mgmt_inband_payload(b, n, &cnt, ids, 16);
        (void)m11_apm_validate_subgraph_list_block(b, n, &cnt, ids, 16);
        uint32_t ch, q;
        (void)m11_aw_validate_cfg_req_pkt(b, n, pct(50) ? M11_APM_CMD_SET_CFG : M11_APM_CMD_GET_CFG, &ch, &q);
        (void)m11_aw_validate_get_cfg_rsp_pkt(b, n, 0x2001, 1, rnd() & 1u, rnd());
        m11_aw_cal_pair_t cp;
        (void)m11_aw_parse_calr_pair(b, n, &cp);
        free(b);
    }
}

/* ------------------------------------------------------------------------------------------
 * F2: engine RX path
 * ---------------------------------------------------------------------------------------- */
typedef struct {
    uint8_t pkt[M11_GPR_MAX_PKT_BYTES];
    size_t  len;
} rxs_t;

static int f_open(void *u) { (void)u; return 5; }
static int f_close(void *u, int fd) { (void)u; (void)fd; return 0; }
static int f_write(void *u, int fd, const uint8_t *b, size_t n) { (void)u; (void)fd; (void)b; return (int)n; }
static int f_poll(void *u, int fd, uint8_t *b, size_t cap, uint32_t t) {
    (void)fd; (void)t;
    rxs_t *r = u;
    if (r->len > cap) return -EMSGSIZE;
    memcpy(b, r->pkt, r->len);
    return (int)r->len;
}

static void fuzz_engine(long iters) {
    static const uint32_t ops[] = { M11_GPR_IBASIC_RSP_RESULT, M11_APM_CMD_RSP_GET_CFG,
                                    M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, M11_APM_CMD_RSP_GET_SPF_STATE,
                                    0x02FFFFFFu, 0u };
    static const uint32_t reqs[] = { M11_APM_CMD_GET_SPF_STATE, M11_APM_CMD_SHARED_MEM_MAP_REGIONS,
                                     M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS, M11_APM_CMD_GET_CFG,
                                     M11_APM_CMD_SET_CFG, M11_APM_CMD_GRAPH_OPEN };
    rxs_t rx;
    memset(&rx, 0, sizeof(rx));
    m11_gpr_transport_t tp = { f_open, f_close, f_write, f_poll, &rx };
    m11_gpr_engine_t e;
    m11_gpr_engine_init(&e, &tp, 0x2001);
    m11_gpr_engine_open(&e);
    for (long i = 0; i < iters; i++) {
        uint32_t tok;
        if (pct(60)) {
            (void)m11_gpr_engine_submit(&e, pct(50) ? 1 : 0x42D3, reqs[below(6)], NULL, 0, &tok);
        }
        size_t pl = below(80);
        uint8_t payload[96];
        for (size_t k = 0; k < pl; k++) payload[k] = (uint8_t)rnd();
        uint32_t t = pct(70) ? (e.next_token - 1 - below(3)) : rnd();
        size_t l = 0;
        m11_gpr_pack_packet_ex(rx.pkt, sizeof rx.pkt, &l, pct(90) ? 3 : rnd(), pct(90) ? 2 : rnd(), 0,
                               0x2001, pct(50) ? 1 : 0x42D3, t, ops[below(6)], payload, pl);
        rx.len = l;
        if (l == 0) { i--; continue; }
        if (pct(10)) rx.len = rnd() % (l + 1);
        if (pct(5)) rx.pkt[rnd() % l] ^= (uint8_t)rnd();
        (void)m11_gpr_engine_pump_once(&e, 1);
        if (pct(3)) {
            /* also exercises close with orphans outstanding */
            (void)m11_gpr_engine_orphan_count(&e);
            m11_gpr_engine_close(&e);
            m11_gpr_engine_init(&e, &tp, 0x2001);
            m11_gpr_engine_open(&e);
        }
    }
    m11_gpr_engine_close(&e);
}

/* ------------------------------------------------------------------------------------------
 * F3: deadline oracle (P1). A scripted transport on a fake clock.
 * ---------------------------------------------------------------------------------------- */
#define DL_MAX 600u
typedef struct {
    uint8_t  pkt[DL_MAX][M11_GPR_MAX_PKT_BYTES];
    size_t   len[DL_MAX];
    uint64_t at[DL_MAX];
    size_t   head, tail;
    uint64_t now;
    uint64_t write_time;
    uint32_t ack_delay;     /* ms after the request write; 0 = no ACK */
    uint32_t n_junk;
    uint32_t junk_gap_max;
    uint32_t junk_kinds;
} dl_t;

static dl_t DL;

static uint64_t dl_clock(void *u) { return ((const dl_t *)u)->now; }

static void dl_push(uint64_t at, const uint8_t *p, size_t n) {
    if (DL.tail >= DL_MAX) return;
    memcpy(DL.pkt[DL.tail], p, n);
    DL.len[DL.tail] = n;
    DL.at[DL.tail] = at;
    DL.tail++;
}

static int dl_write(void *u, int fd, const uint8_t *buf, size_t len) {
    (void)u; (void)fd;
    DL.write_time = DL.now;
    uint32_t token = 0;
    if (len >= M11_GPR_HDR_BYTES) memcpy(&token, buf + 0x10, 4);
    uint8_t p[M11_GPR_MAX_PKT_BYTES];
    size_t n = 0;
    uint64_t t = DL.write_time;
    for (uint32_t i = 0; i < DL.n_junk; i++) {
        t += below(DL.junk_gap_max + 1u);
        if (t >= DL.write_time + 400u) break;
        uint32_t kind = below(DL.junk_kinds);
        if (kind == 0) {
            uint32_t payload = 0xE0E0E0E0u;
            if (m11_gpr_pack_packet_ex(p, sizeof p, &n, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0u,
                                       0x2001, M11_APM_MODULE_IID, 0u, 0x03001000u + i, &payload, 4u) == 0) {
                dl_push(t, p, n);
            }
        } else if (kind == 1) {
            m11_apm_rsp_get_spf_state_t r = { .status = 1u };
            if (m11_gpr_pack_packet_ex(p, sizeof p, &n, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0u,
                                       0x2001, M11_APM_MODULE_IID, 0xBAD00000u + i,
                                       M11_APM_CMD_RSP_GET_SPF_STATE, &r, sizeof r) == 0) {
                dl_push(t, p, n);
            }
        } else {
            /* right token, wrong opcode */
            m11_gpr_ibasic_rsp_t ib = { .cmd_opcode = 0x01001FFFu, .status = 0u };
            if (m11_gpr_pack_packet_ex(p, sizeof p, &n, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0u,
                                       0x2001, M11_APM_MODULE_IID, token, M11_GPR_IBASIC_RSP_RESULT,
                                       &ib, sizeof ib) == 0) {
                dl_push(t, p, n);
            }
        }
    }
    if (DL.ack_delay != 0u) {
        m11_apm_rsp_get_spf_state_t r = { .status = 1u };
        if (m11_gpr_pack_packet_ex(p, sizeof p, &n, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0u,
                                   0x2001, M11_APM_MODULE_IID, token, M11_APM_CMD_RSP_GET_SPF_STATE,
                                   &r, sizeof r) == 0) {
            /* keep the queue time-ordered: the ACK goes in at its place */
            uint64_t at = DL.write_time + DL.ack_delay;
            size_t pos = DL.tail;
            dl_push(at, p, n);
            while (pos > DL.head && DL.at[pos - 1] > DL.at[pos]) {
                uint8_t tmp[M11_GPR_MAX_PKT_BYTES];
                memcpy(tmp, DL.pkt[pos - 1], M11_GPR_MAX_PKT_BYTES);
                memcpy(DL.pkt[pos - 1], DL.pkt[pos], M11_GPR_MAX_PKT_BYTES);
                memcpy(DL.pkt[pos], tmp, M11_GPR_MAX_PKT_BYTES);
                size_t tl = DL.len[pos - 1]; DL.len[pos - 1] = DL.len[pos]; DL.len[pos] = tl;
                uint64_t ta = DL.at[pos - 1]; DL.at[pos - 1] = DL.at[pos]; DL.at[pos] = ta;
                pos--;
            }
        }
    }
    return (int)len;
}

static int dl_poll(void *u, int fd, uint8_t *buf, size_t cap, uint32_t timeout_ms) {
    (void)u; (void)fd;
    if (DL.head != DL.tail) {
        uint64_t at = DL.at[DL.head];
        if (at > DL.now) {
            if (at - DL.now > timeout_ms) {
                DL.now += timeout_ms;
                return 0;
            }
            DL.now = at;
        }
        size_t n = DL.len[DL.head];
        if (n > cap) return -EMSGSIZE;
        memcpy(buf, DL.pkt[DL.head], n);
        DL.head++;
        return (int)n;
    }
    DL.now += timeout_ms;
    return 0;
}

static void fuzz_deadline(long iters) {
    for (long i = 0; i < iters; i++) {
        memset(&DL, 0, sizeof(DL));
        DL.now = 1000u + below(100000u);
        DL.n_junk = below(400);
        DL.junk_gap_max = below(4);
        DL.junk_kinds = 1u + below(3);
        const uint32_t timeout = 10u + below(290u);
        DL.ack_delay = pct(15) ? 0u : 1u + below(320u);

        m11_gpr_transport_t tp = { .open_fn = f_open, .close_fn = f_close, .write_fn = dl_write,
                                   .poll_read_fn = dl_poll, .user = &DL };
        m11_gpr_engine_t e;
        if (m11_gpr_engine_init(&e, &tp, 0x2001) != 0 || m11_gpr_engine_open(&e) != 0) abort();
        m11_gpr_engine_set_clock(&e, dl_clock, &DL);

        const uint64_t t0 = DL.now;
        uint32_t st = 0;
        int rc = m11_gpr_query_spf_state(&e, timeout, &st);
        const uint64_t elapsed = DL.now - t0;

        /* An ACK strictly inside the deadline must always be accepted, however much junk is in front. */
        const bool ack_inside = DL.ack_delay != 0u && DL.ack_delay + 1u < timeout;
        const bool ack_outside = DL.ack_delay == 0u || DL.ack_delay > timeout + 1u;
        if (ack_inside && rc != 0) {
            VIOL(V_DL_TIMEOUT_BEFORE_ACK, i, "rc=%d ack@%u timeout=%u junk=%u gap<=%u kinds=%u", rc,
                 DL.ack_delay, timeout, DL.n_junk, DL.junk_gap_max, DL.junk_kinds);
        }
        if (ack_outside && rc == 0) {
            VIOL(V_DL_SUCCESS_AFTER_DEADLINE, i, "rc=0 ack@%u timeout=%u", DL.ack_delay, timeout);
        }
        if (rc == -ETIMEDOUT) {
            if (elapsed > (uint64_t)timeout + 1u) {
                VIOL(V_DL_OVERRUN, i, "timed out after %llu ms for a %u ms deadline (junk extended it)",
                     (unsigned long long)elapsed, timeout);
            }
            if (elapsed + 1u < (uint64_t)timeout) {
                VIOL(V_DL_UNDERRUN, i, "timed out after %llu ms for a %u ms deadline (too early)",
                     (unsigned long long)elapsed, timeout);
            }
        }
        (void)m11_gpr_engine_close(&e);
    }
}

/* ------------------------------------------------------------------------------------------
 * F4: whole simulation under random fault injection
 * ---------------------------------------------------------------------------------------- */
static long st_ok, st_map, st_vi, st_rx, st_cal, st_start, st_unres, st_pend, st_clean, st_dirty;
static long st_deferred, st_graph_unknown, st_retained, st_retaining, st_hold, st_hold_pdr;

static uint32_t mock_live_slots(const m11_strict_mock_t *m) {
    uint32_t n = 0;
    for (size_t k = 0; k < M11_MOCK_MAX_SHM_SLOTS; k++) {
        if (m->shm_slots[k].allocated || m->shm_slots[k].dsp_map_handle != 0u) n++;
    }
    return n;
}

static void fuzz_sim(long iters) {
    static m11_strict_mock_t m;
    m11_gpr_transport_t tp;
    m11_shmem_backend_t be;
    m11_gpr_engine_t e;
    m11_shmem_mgr_t mg;
    m11_sim_config_t cfg;
    m11_sim_report_t rep;
    static const int errs[] = { 0, 0, 0, 0, -EBADF, -ENODEV, -EPIPE, -ENETRESET, -EIO };

    for (long i = 0; i < iters; i++) {
        m11_strict_mock_init(&m);
        m11_strict_mock_bind(&m, &tp, &be);
        bool *flags[] = {
            &m.fail_dma_alloc, &m.fail_mmap, &m.fail_dma_buf_sync_start, &m.fail_dma_buf_sync_end,
            &m.skip_dma_buf_sync_end, &m.fail_ion_import, &m.fail_ion_unmap, &m.fail_munmap,
            &m.fail_close_fd, &m.fail_gpr_write_on_map, &m.short_gpr_write_on_map, &m.drop_shmem_map_rsp,
            &m.nack_shmem_map, &m.zero_handle_shmem_map_rsp, &m.drop_shmem_unmap_rsp, &m.nack_shmem_unmap,
            &m.drop_graph_open_rsp, &m.nack_graph_open, &m.pdr_on_graph_prepare, &m.drop_graph_start_rsp,
            &m.drop_graph_stop_rsp, &m.drop_graph_close_rsp, &m.nack_graph_close, &m.nack_set_cfg,
            &m.drop_set_cfg_rsp, &m.corrupt_get_cfg_q12, &m.truncate_get_cfg_rsp, &m.wrong_peer_on_rsp,
            &m.wrong_token_on_rsp, &m.wrong_opcode_on_rsp, &m.hold_next_rsp, &m.duplicate_next_rsp,
            &m.deliver_then_fail_write_on_map, &m.deliver_then_fail_write_on_unmap,
            &m.fail_gpr_write_on_unmap, &m.short_gpr_write_on_unmap, &m.fail_gpr_write_on_graph_open,
        };
        const unsigned nf = (unsigned)(sizeof flags / sizeof flags[0]);
        const unsigned k = below(4);
        for (unsigned j = 0; j < k; j++) *flags[below(nf)] = true;
        if (pct(10)) m.poll_read_errno = errs[below(9)];
        if (pct(15)) m.nack_set_cfg_ch_mask = 1u << below(2);
        if (pct(10)) m.ack_lost_set_cfg_ch_mask = 1u << below(2);
        if (pct(10)) m.corrupt_get_cfg_ch_mask = 1u << below(2);
        if (pct(10)) m.drop_get_cfg_rsp_ch_mask = 1u << below(2);
        if (pct(10)) { m.fail_dma_buf_sync_end = true; m.sync_end_errno = -ENOTTY; }
        m.spf_state = pct(90) ? 1 : 0;

        m11_sim_default_marble_config(&cfg);
        if (pct(10)) cfg.enable_vi_tx_graph = false;
        m11_gpr_engine_init(&e, &tp, 0x2001);
        m11_shmem_mgr_init(&mg, &be, &e, 5);
        int rc = m11_sim_run_speaker_qualification(&cfg, &e, &mg, 5, &rep);

        st_ok += (rc == 0);
        st_map += rep.shmem_mapped;
        st_vi += rep.vi_tx_opened;
        st_rx += rep.rx_opened;
        st_cal += rep.cal_applied_and_verified;
        st_start += rep.graphs_started;
        st_unres += (rep.unresolved_ownership > 0);
        st_pend += (rep.local_release_pending > 0);
        st_clean += rep.clean_teardown;
        st_dirty += (!rep.clean_teardown);
        st_retaining += rep.retaining_teardown;
        st_hold += rep.post_map_hold;
        st_hold_pdr += (rep.post_map_hold && e.pdr_down);
        /* Post-MAP hold: the sim's one MAP is never followed by an UNMAP, and once it may have
         * been transmitted its backing stays held (never released, never clean). */
        if (m.unmap_cmd_count != 0u) {
            VIOL(V_SIM_POST_MAP_HOLD, i, "UNMAP sent (%u) after a MAP", m.unmap_cmd_count);
        }
        if (rep.post_map_hold && rep.unmap_attempted) {
            VIOL(V_SIM_POST_MAP_HOLD, i, "UNMAP call entered under the hold (pdr=%d)", e.pdr_down);
        }
        if (rep.post_map_hold &&
            (!rep.retained_region_valid || rep.clean_teardown || !rep.endpoint_close_deferred ||
             rep.final_shmem_state == M11_SHMEM_STATE_RELEASED ||
             rep.final_shmem_state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING ||
             !handles_held(&rep.retained_region) || mock_live_slots(&m) == 0u)) {
            VIOL(V_SIM_POST_MAP_HOLD, i, "transmitted region not held: state=%s retained=%d clean=%d deferred=%d",
                 m11_shmem_state_name(rep.final_shmem_state), rep.retained_region_valid, rep.clean_teardown,
                 rep.endpoint_close_deferred);
        }
        if (rep.retaining_teardown &&
            (!rep.post_map_hold || rep.final_shmem_state != M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED ||
             rep.unresolved_ownership || rep.local_release_pending || rep.orphans_outstanding ||
             rep.graph_cleanup_unresolved || m.vi_tx_opened || m.rx_opened || m.vi_tx_started ||
             m.rx_started || !m.gpr_fd_open || !e.is_open)) {
            VIOL(V_SIM_POST_MAP_HOLD, i, "retaining teardown claimed with state=%s unres=%u pend=%u orphans=%u",
                 m11_shmem_state_name(rep.final_shmem_state), rep.unresolved_ownership,
                 rep.local_release_pending, rep.orphans_outstanding);
        }
        st_deferred += rep.endpoint_close_deferred;
        st_graph_unknown += rep.graph_cleanup_unresolved;
        st_retained += rep.retained_region_valid;
        if (rep.endpoint_close_deferred && !e.is_open) {
            VIOL(V_SIM_CLEAN_BUT_LIVE, i, "deferred endpoint was nevertheless closed");
        }
        if (rep.retained_region_valid && m11_shmem_mgr_audit(&mg,&rep.retained_region,1u) != 0u) {
            VIOL(V_SIM_CLEAN_BUT_COUNTERS, i, "retained owner record does not account for live handles");
        }
        if (rep.graph_cleanup_unresolved && m.unmap_cmd_count != 0u) {
            VIOL(V_SIM_UNSAFE_RELEASE, i, "UNMAP sent with unconfirmed graph cleanup");
        }

        if (m.unsafe_release_attempts != 0u) {
            VIOL(V_SIM_UNSAFE_RELEASE, i, "local handle released under a live ADSP mapping (%u)",
                 m.unsafe_release_attempts);
        }
        /* One region, one MAP, at most one UNMAP: more means a blind resend. */
        if (m.unmap_cmd_count > m.map_cmd_count || m.map_cmd_count > 1u || m.unmap_cmd_count > 1u) {
            VIOL(V_SIM_RESEND, i, "map_cmd=%u unmap_cmd=%u", m.map_cmd_count, m.unmap_cmd_count);
        }
        if (rep.clean_teardown) {
            if (mock_live_slots(&m) != 0u) {
                VIOL(V_SIM_CLEAN_BUT_LIVE, i, "clean_teardown but a shm slot is still live");
            }
            if (m.vi_tx_opened || m.rx_opened || m.vi_tx_started || m.rx_started || m.gpr_fd_open) {
                VIOL(V_SIM_CLEAN_BUT_LIVE, i, "clean_teardown but a graph/fd is still open");
            }
            if (mg.active_dma_fds || mg.active_mmaps || mg.active_ion_imports || mg.active_dsp_maps ||
                mg.unresolved_regions || mg.local_release_pending_regions) {
                VIOL(V_SIM_CLEAN_BUT_COUNTERS, i, "clean_teardown with fds=%u mmaps=%u ion=%u dsp=%u unres=%u pend=%u",
                     mg.active_dma_fds, mg.active_mmaps, mg.active_ion_imports, mg.active_dsp_maps,
                     mg.unresolved_regions, mg.local_release_pending_regions);
            }
            if (rep.unresolved_ownership || rep.local_release_pending || rep.orphans_outstanding ||
                rep.leaked_resources) {
                VIOL(V_SIM_CLEAN_BUT_DIRTY_RECORD, i, "clean_teardown with unres=%u pend=%u orphans=%u leaked=%u",
                     rep.unresolved_ownership, rep.local_release_pending, rep.orphans_outstanding,
                     rep.leaked_resources);
            }
        }
        /* Success is the full verified flow ending in the retaining teardown (post-MAP hold). */
        if (rc == 0 && !(rep.retaining_teardown && !rep.clean_teardown && rep.cal_applied_and_verified &&
                         rep.graphs_started)) {
            VIOL(V_SIM_SUCCESS_NOT_FULL, i, "rc==0 without the full verified flow and the retaining teardown");
        }
        if (rc == 0 && (m.rx_started || m.vi_tx_started)) {
            VIOL(V_SIM_SUCCESS_NOT_FULL, i, "rc==0 but a graph is still started");
        }
        if (rep.aw_report_valid) {
            const m11_aw_apply_report_t *a = &rep.aw_report;
            if (a->amp_enabled || a->rollback_attempted || a->safety_ctx_is_hardware_evidence) {
                VIOL(V_SIM_INVARIANT_FLAGS, i, "amp=%d rollback=%d ctx_evidence=%d", a->amp_enabled,
                     a->rollback_attempted, a->safety_ctx_is_hardware_evidence);
            }
            if (a->pair_re_readback_verified &&
                !(a->ch[0].stage == M11_AW_STAGE_READBACK_VERIFIED &&
                  a->ch[1].stage == M11_AW_STAGE_READBACK_VERIFIED && a->primary_error == 0)) {
                VIOL(V_SIM_PAIR_CLAIM, i, "pair claimed verified with ch0=%d ch1=%d err=%d", a->ch[0].stage,
                     a->ch[1].stage, a->primary_error);
            }
            if (rep.cal_applied_and_verified != a->pair_re_readback_verified) {
                VIOL(V_SIM_PAIR_CLAIM, i, "report disagrees with the per-channel record");
            }
        } else if (rep.cal_applied_and_verified) {
            VIOL(V_SIM_PAIR_CLAIM, i, "calibration claimed without a per-channel record");
        }
        (void)m11_gpr_engine_close(&e);
    }
}

/* ------------------------------------------------------------------------------------------
 * F5: shmem state machine
 * ---------------------------------------------------------------------------------------- */
#define NREG 3

typedef struct {
    m11_strict_mock_t   mock;
    m11_gpr_transport_t tp;
    m11_shmem_backend_t be;
    m11_gpr_engine_t    gpr;
    m11_shmem_mgr_t     mgr;
    m11_shmem_region_t  r[NREG];
    bool                used[NREG];
    uint32_t            map_calls;          /* alloc_and_map calls: each sends at most ONE MAP */
    uint32_t            unmap_reached_write;
} sm_t;

static sm_t S;
static long sm_held_end; /* drained scenarios' regions that ended held after an UNMAP ACK */

static void sm_reset(void) {
    memset(&S, 0, sizeof(S));
    m11_strict_mock_init(&S.mock);
    m11_strict_mock_bind(&S.mock, &S.tp, &S.be);
    if (m11_gpr_engine_init(&S.gpr, &S.tp, 0x2002) != 0 || m11_gpr_engine_open(&S.gpr) != 0) abort();
    if (m11_shmem_mgr_init(&S.mgr, &S.be, &S.gpr, 3u) != 0) abort();
    for (int i = 0; i < NREG; i++) memset(&S.r[i], 0, sizeof(S.r[i]));
}

static void sm_random_faults(void) {
    m11_strict_mock_t *m = &S.mock;
    bool *flags[] = {
        &m->fail_dma_alloc, &m->fail_mmap, &m->fail_dma_buf_sync_start, &m->fail_dma_buf_sync_end,
        &m->fail_ion_import, &m->fail_ion_unmap, &m->fail_munmap, &m->fail_close_fd,
        &m->fail_gpr_write_on_map, &m->short_gpr_write_on_map, &m->drop_shmem_map_rsp,
        &m->nack_shmem_map, &m->zero_handle_shmem_map_rsp, &m->drop_shmem_unmap_rsp,
        &m->nack_shmem_unmap, &m->wrong_peer_on_rsp, &m->wrong_token_on_rsp, &m->hold_next_rsp,
        &m->duplicate_next_rsp, &m->deliver_then_fail_write_on_map, &m->deliver_then_fail_write_on_unmap,
        &m->fail_gpr_write_on_unmap, &m->short_gpr_write_on_unmap,
    };
    const unsigned nf = (unsigned)(sizeof flags / sizeof flags[0]);
    for (unsigned j = 0; j < nf; j++) *flags[j] = false;
    m->poll_read_errno = 0;
    const unsigned k = below(4);
    for (unsigned j = 0; j < k; j++) *flags[below(nf)] = true;
    if (pct(6)) m->poll_read_errno = pct(30) ? -ENETRESET : (pct(50) ? -ENODEV : -EIO);
}

static void sm_clear_faults(void) {
    m11_strict_mock_t *m = &S.mock;
    m->fail_dma_alloc = m->fail_mmap = m->fail_dma_buf_sync_start = m->fail_dma_buf_sync_end = false;
    m->fail_ion_import = m->fail_ion_unmap = m->fail_munmap = m->fail_close_fd = false;
    m->fail_gpr_write_on_map = m->short_gpr_write_on_map = m->drop_shmem_map_rsp = false;
    m->nack_shmem_map = m->zero_handle_shmem_map_rsp = m->drop_shmem_unmap_rsp = false;
    m->nack_shmem_unmap = m->wrong_peer_on_rsp = m->wrong_token_on_rsp = false;
    m->hold_next_rsp = m->duplicate_next_rsp = false;
    m->deliver_then_fail_write_on_map = m->deliver_then_fail_write_on_unmap = false;
    m->fail_gpr_write_on_unmap = m->short_gpr_write_on_unmap = false;
    m->poll_read_errno = 0;
}

static uint32_t sm_mock_slot_handle(const m11_shmem_region_t *r) {
    for (size_t k = 0; k < M11_MOCK_MAX_SHM_SLOTS; k++) {
        if (S.mock.shm_slots[k].allocated && S.mock.shm_slots[k].dma_fd == r->dma_buf_fd) {
            return S.mock.shm_slots[k].dsp_map_handle;
        }
    }
    return 0u;
}

static void sm_check(long iter, const char *after) {
    if (S.mock.unsafe_release_attempts != 0u) {
        VIOL(V_SM_UNSAFE_RELEASE, iter, "after %s: %u local release(s) under a live ADSP mapping", after,
             S.mock.unsafe_release_attempts);
        S.mock.unsafe_release_attempts = 0u; /* report each occurrence once */
    }
    uint32_t mask = m11_shmem_mgr_audit(&S.mgr, S.r, NREG);
    if (mask != 0u) VIOL(V_SM_AUDIT, iter, "after %s: audit mask 0x%x", after, mask);

    /* The ADSP can only have seen a command that some caller-initiated attempt handed to write_fn. */
    if (S.mock.map_cmd_count > S.map_calls || S.mock.unmap_cmd_count > S.unmap_reached_write) {
        VIOL(V_SM_RESEND, iter, "after %s: ADSP saw map=%u/unmap=%u but only %u MAP call(s) and %u UNMAP attempt(s) were made",
             after, S.mock.map_cmd_count, S.mock.unmap_cmd_count, S.map_calls, S.unmap_reached_write);
    }

    for (int i = 0; i < NREG; i++) {
        const m11_shmem_region_t *r = &S.r[i];
        switch (r->state) {
        case M11_SHMEM_STATE_RELEASED:
            if (r->dma_buf_fd >= 0 || r->vaddr != NULL || r->ion_imported || r->dsp_mapped ||
                r->cpu_access_active) {
                VIOL(V_SM_RELEASED_DIRTY, iter, "after %s: region %d RELEASED with fd=%d vaddr=%p ion=%d dsp=%d cpu=%d",
                     after, i, r->dma_buf_fd, r->vaddr, r->ion_imported, r->dsp_mapped, r->cpu_access_active);
            }
            break;
        case M11_SHMEM_STATE_LOCAL_RELEASE_PENDING:
            if (!r->remote_inactive || r->dsp_mapped) {
                VIOL(V_SM_PENDING_NO_PROOF, iter, "after %s: region %d LOCAL_RELEASE_PENDING remote_inactive=%d dsp=%d",
                     after, i, r->remote_inactive, r->dsp_mapped);
            }
            break;
        case M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED:
            /* only a held transmitted region rests here (its release was refused) */
            if (!transmitted(r) || !r->remote_inactive || r->dsp_mapped) {
                VIOL(V_SM_POST_MAP_HOLD, iter, "after %s: region %d UNMAP_ACKED transmitted=%d remote_inactive=%d dsp=%d",
                     after, i, transmitted(r), r->remote_inactive, r->dsp_mapped);
            }
            break;
        case M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED: {
            const bool has_orphan = r->orphan_kind != M11_SHMEM_ORPHAN_NONE;
            const bool has_blocker = r->blocker != NULL;
            if (has_orphan == has_blocker) {
                VIOL(V_SM_UNRESOLVED_SHAPE, iter, "after %s: region %d UNRESOLVED orphan=%d blocker=%s", after, i,
                     has_orphan, has_blocker ? r->blocker : "(none)");
            }
            if (has_orphan && !S.gpr.pdr_down && !m11_gpr_engine_orphan_tracked(&S.gpr, r->orphan_token)) {
                VIOL(V_SM_ORPHAN_UNTRACKED, iter, "after %s: region %d orphan token %u is not tracked", after, i,
                     r->orphan_token);
            }
            if (r->last_error == 0) {
                VIOL(V_SM_ERROR_LOST, iter, "after %s: region %d UNRESOLVED without any recorded error", after, i);
            }
            break;
        }
        case M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED:
            if (!r->dsp_mapped || r->mem_map_handle == 0u || sm_mock_slot_handle(r) != r->mem_map_handle) {
                VIOL(V_SM_ACKED_MISMATCH, iter, "after %s: region %d ACKED handle=0x%x mock=0x%x dsp=%d", after, i,
                     r->mem_map_handle, sm_mock_slot_handle(r), r->dsp_mapped);
            }
            break;
        default:
            break;
        }
        /* Post-MAP hold: a transmitted region keeps every local handle, in every state. */
        if (S.used[i] && transmitted(r) &&
            (r->state == M11_SHMEM_STATE_RELEASED || r->state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING ||
             !handles_held(r))) {
            VIOL(V_SM_POST_MAP_HOLD, iter, "after %s: transmitted region %d lost its backing (state %s fd=%d ion=%d)",
                 after, i, m11_shmem_state_name(r->state), r->dma_buf_fd, r->ion_imported);
        }
    }
}

static void fuzz_shmem(long scenarios) {
    for (long it = 0; it < scenarios; it++) {
        sm_reset();
        const int nops = 12 + (int)below(40);
        for (int op = 0; op < nops; op++) {
            if (S.gpr.pdr_down && pct(50)) break; /* a latched PDR ends this scenario's interesting part */
            const int i = (int)below(NREG);
            const char *what = "?";
            switch (below(10)) {
            case 0: case 1: {
                what = "alloc_and_map";
                if (S.r[i].state != M11_SHMEM_STATE_NOT_ALLOCATED && S.r[i].state != M11_SHMEM_STATE_RELEASED) break;
                if (pct(60)) sm_random_faults();
                S.map_calls++;
                m11_shmem_region_t tmp;
                memset(&tmp, 0, sizeof tmp);
                int rc = m11_shmem_alloc_and_map(&S.mgr, M11_SHMEM_MODE_DMA_ION_OFFSET, 4096u * (1u + below(4)),
                                                 false, &tmp);
                (void)rc;
                S.r[i] = tmp;
                S.used[i] = true;
                break;
            }
            case 2: case 3: case 4: {
                what = "unmap_and_free";
                if (!S.used[i]) break;
                if (pct(40)) sm_random_faults();
                const m11_shmem_state_t before = S.r[i].state;
                int rc = m11_shmem_unmap_and_free(&S.mgr, &S.r[i]);
                (void)rc;
                if (before == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED &&
                    S.gpr.last_tx_status != M11_GPR_TX_NOT_ATTEMPTED) {
                    S.unmap_reached_write++;
                }
                break;
            }
            case 5: case 6:
                what = "reconcile";
                if (S.used[i] && S.r[i].state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED) {
                    (void)m11_shmem_reconcile(&S.mgr, &S.r[i], 1u + below(4));
                }
                break;
            case 7:
                what = "release_held";
                (void)m11_strict_mock_release_held(&S.mock);
                break;
            case 8:
                what = "pump";
                (void)m11_gpr_engine_pump_once(&S.gpr, 1u);
                break;
            default:
                what = "faults";
                if (pct(50)) sm_random_faults(); else sm_clear_faults();
                break;
            }
            sm_check(it, what);
        }

        /* ---- drain: faults cleared, everything late delivered, then retry everything ---- */
        sm_clear_faults();
        (void)m11_strict_mock_release_held(&S.mock);
        for (int round = 0; round < 3; round++) {
            for (int i = 0; i < NREG; i++) {
                if (!S.used[i]) continue;
                if (S.r[i].state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED) {
                    (void)m11_shmem_reconcile(&S.mgr, &S.r[i], 2u);
                }
                const m11_shmem_state_t before = S.r[i].state;
                (void)m11_shmem_unmap_and_free(&S.mgr, &S.r[i]);
                if (before == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED &&
                    S.gpr.last_tx_status != M11_GPR_TX_NOT_ATTEMPTED) {
                    S.unmap_reached_write++;
                }
            }
            sm_check(it, "drain");
        }
        for (int i = 0; i < NREG; i++) {
            if (!S.used[i]) continue;
            const m11_shmem_region_t *r = &S.r[i];
            /* a transmitted region ends held: UNRESOLVED, or UNMAP-ACKed with its release refused */
            const bool held_end = transmitted(r) && r->state == M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED;
            if (r->state != M11_SHMEM_STATE_RELEASED && r->state != M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED &&
                r->state != M11_SHMEM_STATE_NOT_ALLOCATED && !held_end) {
                VIOL(V_SM_DRAIN_STUCK, it, "region %d ended in %s after the drain", i, m11_shmem_state_name(r->state));
            }
            if (transmitted(r) && r->state == M11_SHMEM_STATE_RELEASED) {
                VIOL(V_SM_POST_MAP_HOLD, it, "transmitted region %d RELEASED after the drain", i);
            }
            sm_held_end += held_end;
        }
        /* Every live mock slot must belong to a region that is still UNRESOLVED (an honest leak)
         * or to a transmitted region held after its UNMAP ACK (post-MAP hold). */
        for (size_t k = 0; k < M11_MOCK_MAX_SHM_SLOTS; k++) {
            if (!S.mock.shm_slots[k].allocated) continue;
            bool owned = false;
            for (int i = 0; i < NREG; i++) {
                if (S.used[i] && S.r[i].dma_buf_fd == S.mock.shm_slots[k].dma_fd &&
                    (S.r[i].state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED ||
                     (transmitted(&S.r[i]) && S.r[i].state == M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED))) {
                    owned = true;
                }
            }
            if (!owned) VIOL(V_SM_DRAIN_LEAK, it, "mock slot %zu is still allocated but no UNRESOLVED or held region owns it", k);
        }
        {
            uint32_t unres = 0;
            for (int i = 0; i < NREG; i++) if (S.used[i] && S.r[i].state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED) unres++;
            if (S.mgr.unresolved_regions != unres || S.mgr.local_release_pending_regions != 0u) {
                VIOL(V_SM_COUNTERS_AT_END, it, "unresolved counter %u vs %u regions, pending %u", S.mgr.unresolved_regions,
                     unres, S.mgr.local_release_pending_regions);
            }
        }
        (void)m11_gpr_engine_close(&S.gpr);
    }
}

/* ------------------------------------------------------------------------------------------ */
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const long n = argc > 1 ? atol(argv[1]) : 20000;
    g_seed = argc > 2 ? strtoull(argv[2], NULL, 10) : 0x9E3779B97F4A7C15ull;
    g_state = g_seed ? g_seed : 1u;

    fuzz_validators(n);
    puts("F1 validators: done (sanitizers are the oracle)");
    fuzz_engine(n);
    puts("F2 engine RX path: done (sanitizers are the oracle)");
    fuzz_deadline(n / 4);
    printf("F3 deadline oracle: %ld schedules\n", n / 4);
    fuzz_sim(n / 8);
    printf("F4 simulation: %ld runs; coverage ok=%ld mapped=%ld vi_open=%ld rx_open=%ld cal_ok=%ld started=%ld "
           "unresolved=%ld local_pending=%ld clean=%ld unclean=%ld\n",
           n / 8, st_ok, st_map, st_vi, st_rx, st_cal, st_start, st_unres, st_pend, st_clean, st_dirty);
    fuzz_shmem(n / 8);
    printf("F5 shmem state machine: %ld scenarios\n", n / 8);
    printf("F4 containment coverage: deferred=%ld graph_unknown=%ld retained=%ld\n",
           st_deferred,st_graph_unknown,st_retained);
    printf("post-MAP hold coverage: F4 hold=%ld retaining_teardown=%ld hold_pdr=%ld; F5 held after UNMAP ACK=%ld\n",
           st_hold, st_retaining, st_hold_pdr, sm_held_end);

    long coverage_problems = 0;
    if (n >= 4000) {
        /* A fuzzer that never reaches the interesting states proves nothing. */
        if (st_ok == 0 || st_unres == 0 || st_pend == 0 || st_cal == 0 ||
            st_map == 0 || st_vi == 0 || st_rx == 0 || st_start == 0 ||
            st_clean == 0 || st_dirty == 0 || st_deferred == 0 || st_retained == 0 ||
            st_hold == 0 || st_retaining == 0 || st_hold_pdr == 0 || sm_held_end == 0) {
            printf("COVERAGE PROBLEM: ok=%ld unresolved=%ld local_pending=%ld cal_ok=%ld clean=%ld hold=%ld "
                   "retaining=%ld hold_pdr=%ld held_end=%ld\n", st_ok, st_unres, st_pend, st_cal, st_clean, st_hold,
                   st_retaining, st_hold_pdr, sm_held_end);
            coverage_problems++;
        }
    }
    if (g_total_viol != 0 || coverage_problems != 0) {
        printf("FUZZ RESULT: FAIL (%ld violation(s), %ld coverage problem(s), seed %llu)\n", g_total_viol,
               coverage_problems, (unsigned long long)g_seed);
        for (int k = 0; k < MAX_KINDS; k++) {
            if (g_viol[k]) printf("  %s: %ld\n", g_viol_name[k], g_viol[k]);
        }
        return 1;
    }
    printf("FUZZ RESULT: PASS (seed %llu)\n", (unsigned long long)g_seed);
    return 0;
}
