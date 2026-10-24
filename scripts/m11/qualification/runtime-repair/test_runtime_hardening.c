/*
 * M11 runtime hardening regression suite (P1..P6).
 *
 * Compiled against TWO trees on purpose:
 *   - the pre-hardening baseline (baselines/pre-hardening): every case that exercises a reproduced defect
 *     must FAIL there. Cases that need the new API are guarded by
 *     M11_RUNTIME_HARDENING_API_VERSION and are simply absent from a baseline build, which is
 *     itself the finding ("the baseline has no way to express this state").
 *   - the hardened tree: every case must PASS.
 *
 * CHECK() records a failure and continues, so one baseline run lists every defect at once.
 * Evidence class of everything here is MOCK PASS: the strict mock models the kernel and the
 * ADSP from the same disassembly the code was written from (circular-validation caveat).
 * Nothing here talks to hardware.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "m11_offline_sim.h"
#include "m11_strict_mock.h"

#ifndef ENETRESET
#define ENETRESET 102
#endif

#ifdef M11_RUNTIME_HARDENING_API_VERSION
#define HARDENED 1
#endif
/*
 * Post-MAP hold (CP2 criterion 5, L3; m11_shmem.h): a region whose MAP may have been transmitted
 * is never released locally. A case shared with the baseline picks its expectation with HOLD;
 * the release mechanics (P4) are then driven through a MAP proven never sent.
 */
#ifdef M11_SHMEM_POST_MAP_HOLD
#define HOLD 1
#endif
#if defined(HARDENED) && !defined(HOLD)
#error "a hardened tree without the post-MAP hold is not a supported build of this suite"
#endif
#ifdef HOLD
#define P4_UNMAPS 0u /* the P4 release mechanics run on a MAP proven never sent */
#else
#define P4_UNMAPS 1u
#endif

/* ------------------------------------------------------------------------------------------
 * Tiny test framework
 * ---------------------------------------------------------------------------------------- */
static int g_cases, g_cases_failed, g_checks, g_checks_failed, g_case_failed;
static const char *g_case_name = "";

static void check_fail(const char *file, int line, const char *expr, const char *fmt, ...) {
    g_checks_failed++;
    g_case_failed = 1;
    printf("    CHECK FAILED %s:%d: %s", file, line, expr);
    if (fmt && fmt[0]) {
        va_list ap;
        va_start(ap, fmt);
        printf(" -- ");
        vprintf(fmt, ap);
        va_end(ap);
    }
    printf("\n");
}

#define CHECK(cond, ...)                                                             \
    do {                                                                             \
        g_checks++;                                                                  \
        if (!(cond)) check_fail(__FILE__, __LINE__, #cond, "" __VA_ARGS__);          \
    } while (0)

typedef void (*case_fn_t)(void);

static void run_case(const char *name, case_fn_t fn) {
    g_cases++;
    g_case_failed = 0;
    g_case_name = name;
    printf("[RUN] %s\n", name);
    fflush(stdout); /* permits independent attribution of a mutation timeout */
    fn();
    if (g_case_failed) g_cases_failed++;
    printf("[%s] %s\n", g_case_failed ? "FAIL" : "PASS", name);
}
#define RUN(fn) run_case(#fn, fn)

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ------------------------------------------------------------------------------------------
 * Strict-mock fixture (kernel + ADSP model)
 * ---------------------------------------------------------------------------------------- */
typedef struct {
    m11_strict_mock_t   mock;
    m11_gpr_transport_t tp;
    m11_shmem_backend_t be;
    m11_gpr_engine_t    gpr;
    m11_shmem_mgr_t     mgr;
} fx_t;

static fx_t FX;
#define FX_SRC_PORT 0x2002u

static void fx_init(uint32_t timeout_ms) {
    memset(&FX, 0, sizeof(FX));
    m11_strict_mock_init(&FX.mock);
    m11_strict_mock_bind(&FX.mock, &FX.tp, &FX.be);
    CHECK(m11_gpr_engine_init(&FX.gpr, &FX.tp, FX_SRC_PORT) == 0);
    CHECK(m11_gpr_engine_open(&FX.gpr) == 0);
    CHECK(m11_shmem_mgr_init(&FX.mgr, &FX.be, &FX.gpr, timeout_ms) == 0);
}

static void fx_close(void) {
    (void)m11_gpr_engine_close(&FX.gpr);
}

static int fx_map(m11_shmem_region_t *r) {
    return m11_shmem_alloc_and_map(&FX.mgr, M11_SHMEM_MODE_DMA_ION_OFFSET, 16416u, false, r);
}

static uint32_t mock_dsp_maps(void) {
    uint32_t n = 0;
    for (size_t i = 0; i < M11_MOCK_MAX_SHM_SLOTS; i++) {
        if (FX.mock.shm_slots[i].allocated && FX.mock.shm_slots[i].dsp_map_handle != 0u) n++;
    }
    return n;
}

static void check_counters_zero(const char *what) {
    CHECK(FX.mgr.active_dma_fds == 0u, "%s: dma_fds=%u", what, FX.mgr.active_dma_fds);
    CHECK(FX.mgr.active_mmaps == 0u, "%s: mmaps=%u", what, FX.mgr.active_mmaps);
    CHECK(FX.mgr.active_ion_imports == 0u, "%s: ion=%u", what, FX.mgr.active_ion_imports);
    CHECK(FX.mgr.active_dsp_maps == 0u, "%s: dsp_maps=%u", what, FX.mgr.active_dsp_maps);
    CHECK(FX.mgr.unresolved_regions == 0u, "%s: unresolved=%u", what, FX.mgr.unresolved_regions);
#ifdef HARDENED
    CHECK(FX.mgr.local_release_pending_regions == 0u, "%s: local_pending=%u", what,
          FX.mgr.local_release_pending_regions);
#endif
}

#ifdef HOLD
/*
 * After an ACKed UNMAP (research path, driven directly) a transmitted region keeps every local
 * handle; only its DSP side is gone. rc is the call that saw the ACK (unmap_and_free or reconcile).
 */
static void check_held_after_unmap_ack(const m11_shmem_region_t *r, int rc, const char *what) {
    CHECK(rc == -EPERM, "%s: rc=%d", what, rc);
    CHECK(r->state == M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED, "%s: state=%s", what, m11_shmem_state_name(r->state));
    CHECK(r->remote_inactive && !r->dsp_mapped && r->mem_map_handle == 0u, "%s: DSP side not recorded as unmapped", what);
    CHECK(r->map_tx_started && !r->map_tx_unsent_proof, "%s: tx flags", what);
    CHECK(r->dma_buf_fd >= 0 && r->vaddr != NULL && r->ion_imported, "%s: a local handle was released", what);
    CHECK(FX.mgr.active_dma_fds == 1u && FX.mgr.active_mmaps == 1u && FX.mgr.active_ion_imports == 1u,
          "%s: fds=%u mmaps=%u ion=%u", what, FX.mgr.active_dma_fds, FX.mgr.active_mmaps, FX.mgr.active_ion_imports);
    CHECK(FX.mgr.active_dsp_maps == 0u && FX.mgr.unresolved_regions == 0u &&
          FX.mgr.local_release_pending_regions == 0u, "%s: remote counters", what);
    CHECK(mock_dsp_maps() == 0u && FX.mock.unsafe_release_attempts == 0u, "%s: mock", what);
    CHECK(m11_shmem_mgr_audit(&FX.mgr, r, 1u) == 0u, "%s: audit", what);
}

/* Every FREE pending slot marked busy (orphans keep theirs): the next MAP submit is refused
 * before write_fn (TX_NOT_ATTEMPTED), the only failure that proves the MAP was never sent. */
static bool fx_blocked[M11_GPR_MAX_PENDING];
static void fx_block_submit(bool on) {
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) {
        if (on) {
            fx_blocked[i] = !FX.gpr.slots[i].in_use;
            if (fx_blocked[i]) FX.gpr.slots[i].in_use = true;
        } else if (fx_blocked[i]) {
            memset(&FX.gpr.slots[i], 0, sizeof(FX.gpr.slots[i]));
            fx_blocked[i] = false;
        }
    }
}

/* A MAP refused before write_fn: the proof is set and the local release runs at once. */
static int fx_map_unsent(m11_shmem_region_t *r) {
    fx_block_submit(true);
    int rc = fx_map(r);
    fx_block_submit(false);
    CHECK(rc == -ENOSPC && FX.gpr.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED, "unsent MAP rc=%d", rc);
    CHECK(r->map_tx_started && r->map_tx_unsent_proof, "the unsent proof must be set");
    return rc;
}
#endif

/* ------------------------------------------------------------------------------------------
 * Scripted transport (P1, P6): packets become readable at chosen times, so a test controls
 * exactly what arrives before or after a response, in fake or real time.
 * ---------------------------------------------------------------------------------------- */
#define SC_MAX     2048u
#define SC_PKT_MAX 96u
#define SC_SRC     FX_SRC_PORT

typedef struct sc_s sc_t;
typedef void (*sc_gen_fn)(sc_t *s, uint32_t token, uint32_t opcode);

struct sc_s {
    uint8_t   pkt[SC_MAX][SC_PKT_MAX];
    size_t    len[SC_MAX];
    uint64_t  at[SC_MAX];
    size_t    head, tail;
    bool      realtime;
    uint64_t  fake_now;
    uint64_t  write_time;       /* time of the last request write */
    uint32_t  polls;
    uint32_t  events_delivered;
    uint32_t  timeouts_seen[4096];
    uint32_t  max_timeout_seen;
    bool      infinite_events;  /* every poll yields one more unsolicited event */
    uint32_t  event_cost_ms;    /* time each endless event takes to arrive (fake or real) */
    int       fail_errno;       /* returned by poll once polls > fail_after_polls */
    uint32_t  fail_after_polls;
    sc_gen_fn gen;
    uint32_t  writes;
    uint32_t  gen_arg0, gen_arg1, gen_arg2;
};

static sc_t SC;

static uint64_t sc_now(const sc_t *s) {
    return s->realtime ? mono_ms() : s->fake_now;
}

static void sc_sleep(sc_t *s, uint64_t ms) {
    if (ms == 0u) return;
    if (s->realtime) {
        struct timespec ts = { .tv_sec = (time_t)(ms / 1000u),
                               .tv_nsec = (long)((ms % 1000u) * 1000000u) };
        nanosleep(&ts, NULL);
    } else {
        s->fake_now += ms;
    }
}

#ifdef HARDENED
static uint64_t sc_clock_cb(void *user) {
    return sc_now((const sc_t *)user);
}
#endif

static void sc_push(sc_t *s, uint64_t delay_ms, const uint8_t *pkt, size_t len) {
    if (s->tail >= SC_MAX || len > SC_PKT_MAX) return;
    memcpy(s->pkt[s->tail], pkt, len);
    s->len[s->tail] = len;
    s->at[s->tail] = s->write_time + delay_ms;
    s->tail++;
}

/* Builds an ADSP -> APPS packet. */
static size_t sc_build(uint8_t *out, uint8_t src_dom, uint32_t src_port, uint32_t token,
                       uint32_t opcode, const void *pl, size_t pl_len) {
    size_t n = 0;
    int rc = m11_gpr_pack_packet_ex(out, SC_PKT_MAX, &n, M11_GPR_DOMAIN_APPS, src_dom, 0u,
                                    SC_SRC, src_port, token, opcode, pl, pl_len);
    return rc == 0 ? n : 0u;
}

static void sc_push_event(sc_t *s, uint64_t delay_ms, uint32_t ev_opcode) {
    uint8_t p[SC_PKT_MAX];
    uint32_t payload = 0xE0E0E0E0u;
    size_t n = sc_build(p, M11_GPR_DOMAIN_ADSP, M11_APM_MODULE_IID, 0u, ev_opcode, &payload, 4u);
    sc_push(s, delay_ms, p, n);
}

static void sc_push_stale(sc_t *s, uint64_t delay_ms, uint32_t token) {
    uint8_t p[SC_PKT_MAX];
    m11_apm_rsp_get_spf_state_t r = { .status = 1u };
    size_t n = sc_build(p, M11_GPR_DOMAIN_ADSP, M11_APM_MODULE_IID, token,
                        M11_APM_CMD_RSP_GET_SPF_STATE, &r, sizeof(r));
    sc_push(s, delay_ms, p, n);
}

static void sc_push_spf_ack(sc_t *s, uint64_t delay_ms, uint32_t token) {
    sc_push_stale(s, delay_ms, token);
}

static void sc_push_ibasic(sc_t *s, uint64_t delay_ms, uint32_t src_port, uint32_t token,
                           uint32_t cmd_opcode, uint32_t status) {
    uint8_t p[SC_PKT_MAX];
    m11_gpr_ibasic_rsp_t ib = { .cmd_opcode = cmd_opcode, .status = status };
    size_t n = sc_build(p, M11_GPR_DOMAIN_ADSP, src_port, token, M11_GPR_IBASIC_RSP_RESULT,
                        &ib, sizeof(ib));
    sc_push(s, delay_ms, p, n);
}

static int sc_open(void *u) { (void)u; return 7; }
static int sc_close(void *u, int fd) { (void)u; (void)fd; return 0; }

static int sc_write(void *u, int fd, const uint8_t *buf, size_t len) {
    sc_t *s = (sc_t *)u;
    (void)fd;
    s->writes++;
    s->write_time = sc_now(s);
    uint32_t token = 0, opcode = 0;
    if (len >= M11_GPR_HDR_BYTES) {
        memcpy(&token, buf + 0x10, 4);
        memcpy(&opcode, buf + 0x14, 4);
    }
    if (s->gen) s->gen(s, token, opcode);
    return (int)len;
}

static int sc_poll(void *u, int fd, uint8_t *buf, size_t cap, uint32_t timeout_ms) {
    sc_t *s = (sc_t *)u;
    (void)fd;
    if (s->polls < 4096u) s->timeouts_seen[s->polls] = timeout_ms;
    if (timeout_ms > s->max_timeout_seen) s->max_timeout_seen = timeout_ms;
    s->polls++;
    if (s->fail_errno != 0 && s->polls > s->fail_after_polls) return s->fail_errno;

    if (s->infinite_events) {
        sc_sleep(s, s->event_cost_ms);
        size_t n = sc_build(buf, M11_GPR_DOMAIN_ADSP, M11_APM_MODULE_IID, 0u, 0x03004000u, NULL, 0u);
        s->events_delivered++;
        return (int)n;
    }

    uint64_t now = sc_now(s);
    if (s->head != s->tail) {
        uint64_t at = s->at[s->head];
        if (at > now) {
            if (at - now > timeout_ms) {
                sc_sleep(s, timeout_ms);
                return 0; /* nothing within this poll's window */
            }
            sc_sleep(s, at - now);
        }
        size_t n = s->len[s->head];
        if (n > cap) return -EMSGSIZE;
        memcpy(buf, s->pkt[s->head], n);
        s->head++;
        s->events_delivered++;
        return (int)n;
    }
    sc_sleep(s, timeout_ms);
    return 0;
}

static m11_gpr_engine_t SCG; /* engine bound to the scripted transport */

static void sc_setup(sc_gen_fn gen, bool realtime) {
    memset(&SC, 0, sizeof(SC));
    memset(&SCG, 0, sizeof(SCG));
    SC.gen = gen;
    SC.realtime = realtime;
    m11_gpr_transport_t tp = { .open_fn = sc_open, .close_fn = sc_close, .write_fn = sc_write,
                               .poll_read_fn = sc_poll, .user = &SC };
    CHECK(m11_gpr_engine_init(&SCG, &tp, SC_SRC) == 0);
    CHECK(m11_gpr_engine_open(&SCG) == 0);
}

static void sc_teardown(void) {
    (void)m11_gpr_engine_close(&SCG);
}

/* ===========================================================================================
 * P1 - absolute-deadline wait (replaces the 64-iteration cap)
 * ========================================================================================= */

/* arg0 = events before the ACK, arg1 = gap between them (ms), arg2 = junk kind */
enum { JUNK_EVENT = 0, JUNK_STALE_TOKEN = 1, JUNK_MIXED = 2 };

static void gen_junk_then_ack(sc_t *s, uint32_t token, uint32_t opcode) {
    (void)opcode;
    uint64_t t = 0;
    for (uint32_t i = 0; i < s->gen_arg0; i++) {
        t += s->gen_arg1;
        switch (s->gen_arg2) {
            case JUNK_EVENT:       sc_push_event(s, t, 0x03001000u + i); break;
            case JUNK_STALE_TOKEN: sc_push_stale(s, t, 0xBAD00000u + i); break;
            default:
                if ((i % 3u) == 0u) {
                    sc_push_event(s, t, 0x03001000u + i);
                } else if ((i % 3u) == 1u) {
                    sc_push_stale(s, t, 0xBAD00000u + i);
                } else {
                    /* right token, wrong opcode: must be dropped, not complete the call */
                    sc_push_ibasic(s, t, M11_APM_MODULE_IID, token, 0x01001FFFu, 0u);
                }
                break;
        }
    }
    sc_push_spf_ack(s, t + s->gen_arg1, token);
}

static void p1_run_spf(uint32_t timeout_ms, int expect_rc, const char *label) {
    uint32_t st = 0;
    int rc = m11_gpr_query_spf_state(&SCG, timeout_ms, &st);
    CHECK(rc == expect_rc, "%s: rc=%d expected %d (polls=%u, delivered=%u)", label, rc,
          expect_rc, SC.polls, SC.events_delivered);
}

/* Reproduced defect: >=64 unsolicited events ahead of a valid ACK made wait_token give up. */
static void p1_seventy_events_before_valid_ack(void) {
    sc_setup(gen_junk_then_ack, false);
    SC.gen_arg0 = 70u; SC.gen_arg1 = 0u; SC.gen_arg2 = JUNK_EVENT;
    p1_run_spf(200u, 0, "70 events + ACK");
    CHECK(SCG.rx_unsolicited_events == 70u, "events=%u", SCG.rx_unsolicited_events);
    sc_teardown();
}

static void p1_event_flood_before_valid_ack(void) {
    sc_setup(gen_junk_then_ack, false);
    SC.gen_arg0 = 1500u; SC.gen_arg1 = 0u; SC.gen_arg2 = JUNK_EVENT;
    p1_run_spf(200u, 0, "1500 events + ACK");
    sc_teardown();
}

static void p1_stale_and_wrong_packet_flood_before_valid_ack(void) {
    sc_setup(gen_junk_then_ack, false);
    SC.gen_arg0 = 300u; SC.gen_arg1 = 0u; SC.gen_arg2 = JUNK_MIXED;
    p1_run_spf(200u, 0, "300 mixed junk + ACK");
    CHECK(SCG.rx_dropped_unknown_token > 0u);
    CHECK(SCG.rx_dropped_malformed > 0u);
    sc_teardown();
}

/* Wrong-opcode packets with the right token must never complete the transaction. */
static void gen_only_wrong_opcode(sc_t *s, uint32_t token, uint32_t opcode) {
    (void)opcode;
    for (uint32_t i = 0; i < 5; i++) sc_push_ibasic(s, 0, M11_APM_MODULE_IID, token, 0x01001FFFu, 0u);
}
static void p1_token_opcode_peer_checks_survive(void) {
    sc_setup(gen_only_wrong_opcode, false);
    p1_run_spf(30u, -ETIMEDOUT, "wrong-opcode ACKs must not complete");
    sc_teardown();

    /* right token + right opcode but from the wrong module port */
    sc_setup(NULL, false);
    uint32_t tok = 0;
    CHECK(m11_gpr_engine_submit(&SCG, M11_APM_MODULE_IID, M11_APM_CMD_GET_SPF_STATE, NULL, 0, &tok) == 0);
    {
        uint8_t p[SC_PKT_MAX];
        m11_apm_rsp_get_spf_state_t r = { .status = 1u };
        size_t n = sc_build(p, M11_GPR_DOMAIN_ADSP, 0x42D3u, tok, M11_APM_CMD_RSP_GET_SPF_STATE, &r, sizeof(r));
        sc_push(&SC, 0, p, n);
    }
    uint32_t dsp = 0;
    int rc = m11_gpr_engine_wait_token(&SCG, tok, 30u, &dsp, NULL, 0, NULL);
    CHECK(rc == -ETIMEDOUT, "wrong-peer-port ACK rc=%d", rc);
    sc_teardown();
}

/* Measured wall-clock deadline: drip-fed junk must neither shorten nor extend the call. */
static void gen_dripfeed_junk(sc_t *s, uint32_t token, uint32_t opcode) {
    (void)token; (void)opcode;
    for (uint32_t i = 1; i <= s->gen_arg0; i++) sc_push_event(s, (uint64_t)i * s->gen_arg1, 0x03002000u + i);
}
static void p1_real_time_total_deadline_with_dripfed_events(void) {
    sc_setup(gen_dripfeed_junk, true);
    SC.gen_arg0 = 300u; SC.gen_arg1 = 10u; /* an event every 10 ms for 3 s */
    uint32_t st = 0;
    uint64_t t0 = mono_ms();
    int rc = m11_gpr_query_spf_state(&SCG, 200u, &st);
    uint64_t dt = mono_ms() - t0;
    CHECK(rc == -ETIMEDOUT, "rc=%d", rc);
    CHECK(dt >= 195u, "returned after %llu ms, deadline was 200 ms (too early)", (unsigned long long)dt);
    CHECK(dt <= 400u, "returned after %llu ms, deadline was 200 ms (event stream extended it)", (unsigned long long)dt);
    sc_teardown();
}

static void gen_dripfeed_then_ack_at_150(sc_t *s, uint32_t token, uint32_t opcode) {
    (void)opcode;
    for (uint32_t i = 1; i <= 14u; i++) sc_push_event(s, (uint64_t)i * 10u, 0x03002000u + i);
    sc_push_spf_ack(s, 150u, token);
}
static void p1_real_time_ack_inside_deadline_succeeds(void) {
    sc_setup(gen_dripfeed_then_ack_at_150, true);
    uint32_t st = 0;
    uint64_t t0 = mono_ms();
    int rc = m11_gpr_query_spf_state(&SCG, 400u, &st);
    uint64_t dt = mono_ms() - t0;
    CHECK(rc == 0, "rc=%d", rc);
    CHECK(dt >= 140u && dt < 380u, "elapsed %llu ms", (unsigned long long)dt);
    sc_teardown();
}

/* Transport failures keep their exact errno (never rewritten into a timeout). */
static void p1_transport_errno_is_exact(void) {
    static const int errs[] = { -ENODEV, -EIO, -EBADF, -EPIPE, -EFAULT, -ENOTCONN };
    for (size_t i = 0; i < sizeof(errs) / sizeof(errs[0]); i++) {
        sc_setup(gen_junk_then_ack, false);
        SC.gen_arg0 = 5u; SC.gen_arg1 = 0u; SC.gen_arg2 = JUNK_EVENT;
        SC.fail_errno = errs[i];
        SC.fail_after_polls = 3u;
        uint32_t st = 0;
        int rc = m11_gpr_query_spf_state(&SCG, 200u, &st);
        CHECK(rc == errs[i], "errno %d came back as %d", errs[i], rc);
        sc_teardown();
    }
    /* PDR latches the engine for good. */
    sc_setup(gen_junk_then_ack, false);
    SC.gen_arg0 = 5u; SC.gen_arg1 = 0u; SC.gen_arg2 = JUNK_EVENT;
    SC.fail_errno = -ENETRESET; SC.fail_after_polls = 2u;
    uint32_t st = 0;
    CHECK(m11_gpr_query_spf_state(&SCG, 200u, &st) == -ENETRESET);
    CHECK(SCG.pdr_down);
    CHECK(m11_gpr_query_spf_state(&SCG, 200u, &st) == -ENETRESET);
    sc_teardown();
}

#ifdef HARDENED
/* Deterministic fake-clock variants: the remaining time is what each poll gets. */
static void p1_each_poll_gets_only_the_remaining_time(void) {
    sc_setup(gen_dripfeed_junk, false);
    m11_gpr_engine_set_clock(&SCG, sc_clock_cb, &SC);
    SC.gen_arg0 = 100u; SC.gen_arg1 = 7u;
    uint32_t st = 0;
    int rc = m11_gpr_query_spf_state(&SCG, 100u, &st);
    CHECK(rc == -ETIMEDOUT, "rc=%d", rc);
    CHECK(SC.max_timeout_seen <= 100u, "a poll was given %u ms of a 100 ms transaction", SC.max_timeout_seen);
    for (uint32_t i = 1; i < SC.polls && i < 4096u; i++) {
        CHECK(SC.timeouts_seen[i] == 100u - 7u * i,
              "poll %u must receive exactly %u ms, got %u",i,100u - 7u * i,SC.timeouts_seen[i]);
        CHECK(SC.timeouts_seen[i] <= SC.timeouts_seen[i - 1], "poll %u got %u ms after %u ms", i,
              SC.timeouts_seen[i], SC.timeouts_seen[i - 1]);
    }
    CHECK(SC.fake_now >= 100u && SC.fake_now <= 107u, "fake clock ended at %llu", (unsigned long long)SC.fake_now);
    sc_teardown();
}

static void p1_deadline_is_total_not_per_poll_fake_clock(void) {
    sc_setup(gen_dripfeed_then_ack_at_150, false);
    m11_gpr_engine_set_clock(&SCG, sc_clock_cb, &SC);
    uint32_t st = 0;
    CHECK(m11_gpr_query_spf_state(&SCG, 149u, &st) == -ETIMEDOUT, "ACK at 150 ms must miss a 149 ms deadline");
    sc_teardown();

    sc_setup(gen_dripfeed_then_ack_at_150, false);
    m11_gpr_engine_set_clock(&SCG, sc_clock_cb, &SC);
    CHECK(m11_gpr_query_spf_state(&SCG, 151u, &st) == 0, "ACK at 150 ms must make a 151 ms deadline");
    sc_teardown();
}

static uint64_t stuck_clock(void *u) { (void)u; return 12345u; }
static void p1_stuck_clock_cannot_hang_forever(void) {
    sc_setup(NULL, false);
    SC.infinite_events = true;
    m11_gpr_engine_set_clock(&SCG, stuck_clock, NULL);
    uint32_t tok = 0;
    CHECK(m11_gpr_engine_submit(&SCG, M11_APM_MODULE_IID, M11_APM_CMD_GET_SPF_STATE, NULL, 0, &tok) == 0);
    int rc = m11_gpr_engine_wait_token(&SCG, tok, 50u, NULL, NULL, 0, NULL);
    CHECK(rc == -ETIMEDOUT, "rc=%d", rc);
    CHECK(SC.polls < (1u << 21), "polls=%u", SC.polls);
    sc_teardown();
}
static void p1_stuck_clock_idle_queue_times_out(void) {
    sc_setup(NULL, false);
    m11_gpr_engine_set_clock(&SCG, stuck_clock, NULL);
    uint32_t st = 0;
    int rc = m11_gpr_query_spf_state(&SCG, 50u, &st);
    CHECK(rc == -ETIMEDOUT, "rc=%d", rc);
    sc_teardown();
}

static uint64_t backward_clock_val;
static uint64_t backward_clock(void *u) { (void)u; return backward_clock_val; }
static void p1_clock_stepping_backwards_never_extends_polls(void) {
    sc_setup(NULL, false);
    backward_clock_val = 1000000u;
    m11_gpr_engine_set_clock(&SCG, backward_clock, NULL);
    uint32_t tok = 0;
    CHECK(m11_gpr_engine_submit(&SCG, M11_APM_MODULE_IID, M11_APM_CMD_GET_SPF_STATE, NULL, 0, &tok) == 0);
    backward_clock_val = 10u; /* clock jumps far back before the first poll */
    int rc = m11_gpr_engine_wait_token(&SCG, tok, 50u, NULL, NULL, 0, NULL);
    CHECK(rc == -ETIMEDOUT, "rc=%d", rc);
    CHECK(SC.max_timeout_seen <= 50u, "poll got %u ms of a 50 ms transaction", SC.max_timeout_seen);
    sc_teardown();
}
#endif /* HARDENED */

/*
 * An endless stream of valid-looking events is the worst case for a loop that only checks its
 * deadline when it is idle: with a source that is ALWAYS readable, nothing but the absolute
 * deadline can end the call. (Baseline: the 64-iteration cap ends it ~64 ms early instead.)
 */
static void p1_endless_event_stream_cannot_extend_the_deadline_real_time(void) {
    sc_setup(NULL, true);
    SC.infinite_events = true;
    SC.event_cost_ms = 1u; /* one event per millisecond, forever */
    uint32_t st = 0;
    uint64_t t0 = mono_ms();
    int rc = m11_gpr_query_spf_state(&SCG, 150u, &st);
    uint64_t dt = mono_ms() - t0;
    CHECK(rc == -ETIMEDOUT, "rc=%d", rc);
    CHECK(dt >= 145u, "returned after %llu ms, deadline was 150 ms (too early)", (unsigned long long)dt);
    CHECK(dt <= 350u, "returned after %llu ms, deadline was 150 ms (events extended it)", (unsigned long long)dt);
    CHECK(SC.events_delivered >= 100u, "only %u events were seen", SC.events_delivered);
    sc_teardown();
}

#ifdef HARDENED
static void p1_endless_event_stream_cannot_extend_the_deadline_fake_clock(void) {
    sc_setup(NULL, false);
    m11_gpr_engine_set_clock(&SCG, sc_clock_cb, &SC);
    SC.infinite_events = true;
    SC.event_cost_ms = 1u;
    uint32_t st = 0;
    int rc = m11_gpr_query_spf_state(&SCG, 100u, &st);
    CHECK(rc == -ETIMEDOUT, "rc=%d", rc);
    CHECK(SC.fake_now >= 100u && SC.fake_now <= 102u, "fake clock ended at %llu", (unsigned long long)SC.fake_now);
    CHECK(SC.polls >= 99u && SC.polls <= 110u, "a 100 ms deadline took %u polls", SC.polls);
    CHECK(SCG.rx_unsolicited_events >= 99u, "events=%u", SCG.rx_unsolicited_events);
    sc_teardown();
}
#endif

/* The ordinary request/response paths stay correct. */
static void p1_normal_round_trip_unchanged(void) {
    sc_setup(gen_junk_then_ack, false);
    SC.gen_arg0 = 0u;
    uint32_t st = 0;
    CHECK(m11_gpr_query_spf_state(&SCG, 50u, &st) == 0);
    CHECK(st == 1u);
    sc_teardown();
}

/* ===========================================================================================
 * P2 - late / orphaned MAP and UNMAP responses
 * ========================================================================================= */

static void p2_ack_before_timeout_is_normal(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    CHECK(r.state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    CHECK(r.dsp_mapped && r.mem_map_handle != 0u);
    CHECK(mock_dsp_maps() == 1u);
#ifdef HOLD
    check_held_after_unmap_ack(&r, m11_shmem_unmap_and_free(&FX.mgr, &r), "normal path");
    CHECK(FX.mock.unmap_cmd_count == 1u);
#else
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == 0);
    CHECK(r.state == M11_SHMEM_STATE_RELEASED);
    check_counters_zero("normal path");
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    CHECK(mock_dsp_maps() == 0u);
#endif
    fx_close();
}

/*
 * Reproduced defect: the MAP ACK that arrives after the host gave up was discarded as an
 * unknown token, leaving a live ADSP mapping nobody can address.
 */
static void p2_late_map_ack_after_timeout_is_correlated(void) {
    fx_init(30u);
    FX.mock.hold_next_rsp = true; /* ADSP maps, but its ACK is delayed past the host deadline */
    m11_shmem_region_t r;
    int rc = fx_map(&r);
    CHECK(rc == -ETIMEDOUT, "rc=%d", rc);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(FX.mock.held_count == 1u);
    CHECK(mock_dsp_maps() == 1u, "the ADSP did create the mapping");
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY, "must not free while the ADSP may map it");
    CHECK(FX.mock.unsafe_release_attempts == 0u);

    CHECK(m11_strict_mock_release_held(&FX.mock) == 1u);
    uint32_t dropped = FX.gpr.rx_dropped_unknown_token;
    (void)m11_gpr_engine_pump_once(&FX.gpr, 10u);
    CHECK(FX.gpr.rx_dropped_unknown_token == dropped, "late MAP ACK was discarded as an unknown token");
#ifdef HARDENED
    CHECK(m11_gpr_engine_orphan_tracked(&FX.gpr, r.orphan_token));
    CHECK(r.blocker == NULL, "resolvable region must carry no blocker");
    CHECK(r.cause == M11_SHMEM_CAUSE_MAP_TIMEOUT, "cause=%s", m11_shmem_cause_name(r.cause));
    rc = m11_shmem_reconcile(&FX.mgr, &r, 10u);
    CHECK(rc == 0, "reconcile rc=%d", rc);
    CHECK(r.state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED, "state=%s", m11_shmem_state_name(r.state));
    CHECK(r.dsp_mapped && r.mem_map_handle == FX.mock.shm_slots[0].dsp_map_handle);
    CHECK(FX.mgr.unresolved_regions == 0u && FX.mgr.active_dsp_maps == 1u);
    CHECK(m11_shmem_mgr_audit(&FX.mgr, &r, 1u) == 0u);
    check_held_after_unmap_ack(&r, m11_shmem_unmap_and_free(&FX.mgr, &r), "after adopted late ACK");
    CHECK(FX.mock.map_cmd_count == 1u && FX.mock.unmap_cmd_count == 1u);
#endif
    fx_close();
}

static void p2_late_unmap_ack_after_timeout_is_correlated(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    FX.mock.hold_next_rsp = true; /* ADSP unmaps, ACK delayed */
    int rc = m11_shmem_unmap_and_free(&FX.mgr, &r);
    CHECK(rc == -ETIMEDOUT, "rc=%d", rc);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(mock_dsp_maps() == 0u, "ADSP already dropped the mapping, the host cannot know yet");
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY, "no blind retry while unknown");
    CHECK(FX.mock.unmap_cmd_count == 1u, "UNMAP was re-sent blindly (%u)", FX.mock.unmap_cmd_count);
    CHECK(FX.mock.unsafe_release_attempts == 0u);

    CHECK(m11_strict_mock_release_held(&FX.mock) == 1u);
    uint32_t dropped = FX.gpr.rx_dropped_unknown_token;
    (void)m11_gpr_engine_pump_once(&FX.gpr, 10u);
    CHECK(FX.gpr.rx_dropped_unknown_token == dropped, "late UNMAP ACK was discarded as an unknown token");
#ifdef HARDENED
    check_held_after_unmap_ack(&r, m11_shmem_reconcile(&FX.mgr, &r, 10u), "after adopted late UNMAP ACK");
    CHECK(FX.mock.unmap_cmd_count == 1u);
#endif
    fx_close();
}

#ifdef HARDENED
static void p2_duplicate_late_ack_is_applied_once(void) {
    fx_init(30u);
    FX.mock.hold_next_rsp = true;
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == -ETIMEDOUT);
    FX.mock.duplicate_next_rsp = true; /* the late ACK is delivered twice */
    CHECK(m11_strict_mock_release_held(&FX.mock) == 1u);
    CHECK(FX.mock.rx_tail - FX.mock.rx_head == 2u);

    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == 0);
    CHECK(r.state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    CHECK(FX.mgr.active_dsp_maps == 1u, "dsp_maps=%u", FX.mgr.active_dsp_maps);
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -EINVAL, "second reconcile on a resolved region");

    check_held_after_unmap_ack(&r, m11_shmem_unmap_and_free(&FX.mgr, &r), "duplicate ACK");
    CHECK(FX.gpr.rx_dropped_unknown_token == 1u, "the duplicate must be dropped, dropped=%u",
          FX.gpr.rx_dropped_unknown_token);
    fx_close();
}

static void p2_wrong_token_ack_never_resolves(void) {
    fx_init(30u);
    FX.mock.wrong_token_on_rsp = true;
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == -ETIMEDOUT);
    FX.mock.wrong_token_on_rsp = false;
    CHECK(mock_dsp_maps() == 1u);
    CHECK(FX.gpr.rx_dropped_unknown_token == 1u);
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -ETIMEDOUT);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(!r.dsp_mapped && r.mem_map_handle == 0u, "must not adopt a handle from a foreign token");
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    CHECK(m11_shmem_mgr_audit(&FX.mgr, &r, 1u) == 0u);
    fx_close();
}

static void p2_wrong_peer_ack_never_resolves(void) {
    fx_init(30u);
    FX.mock.wrong_peer_on_rsp = true; /* source domain MODEM instead of ADSP */
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == -ETIMEDOUT);
    FX.mock.wrong_peer_on_rsp = false;
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -ETIMEDOUT);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && !r.dsp_mapped);
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);
    CHECK(FX.mock.unsafe_release_attempts == 0u);

    /* right token, right domain, but sent from another module port than the request target */
    fx_close();
    fx_init(30u);
    FX.mock.drop_shmem_map_rsp = true;
    CHECK(fx_map(&r) == -ETIMEDOUT);
    uint8_t pkt[SC_PKT_MAX];
    m11_apm_rsp_shared_mem_map_t rsp = { .mem_map_handle = 0xA0009999u };
    size_t n = 0;
    CHECK(m11_gpr_pack_packet_ex(pkt, sizeof(pkt), &n, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0u,
                                 FX_SRC_PORT, 0x42D3u, r.orphan_token,
                                 M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &rsp, sizeof(rsp)) == 0);
    CHECK(m11_strict_mock_enqueue_raw_rx(&FX.mock, pkt, n) == 0);
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -ETIMEDOUT);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && !r.dsp_mapped);
    CHECK(FX.gpr.rx_dropped_malformed >= 1u);
    fx_close();
}

/* Post-MAP hold: a late MAP NACK proves nothing about the mapping, so the backing is held. */
static void p2_late_map_nack_is_held_not_released(void) {
    fx_init(30u);
    FX.mock.nack_shmem_map = true;
    FX.mock.hold_next_rsp = true;
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == -ETIMEDOUT);
    CHECK(m11_strict_mock_release_held(&FX.mock) == 1u);
    int rc = m11_shmem_reconcile(&FX.mgr, &r, 10u);
    CHECK(rc == -EREMOTEIO, "rc=%d", rc);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED, "state=%s", m11_shmem_state_name(r.state));
    CHECK(r.cause == M11_SHMEM_CAUSE_MAP_NACK && r.blocker != NULL, "cause=%s", m11_shmem_cause_name(r.cause));
    CHECK(r.last_error == -EREMOTEIO && r.orphan_kind == M11_SHMEM_ORPHAN_NONE);
    CHECK(r.dma_buf_fd >= 0 && r.vaddr != NULL && r.ion_imported, "a local handle was released");
    CHECK(FX.mgr.active_dma_fds == 1u && FX.mgr.active_mmaps == 1u && FX.mgr.active_ion_imports == 1u);
    CHECK(FX.mgr.unresolved_regions == 1u && m11_shmem_mgr_audit(&FX.mgr, &r, 1u) == 0u);
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY && r.ion_imported);
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -ENOENT, "a consumed NACK leaves nothing to wait for");
    CHECK(FX.mock.unmap_cmd_count == 0u && FX.mock.unsafe_release_attempts == 0u);
    fx_close();
}

static void p2_write_error_after_delivery_is_recovered(void) {
    fx_init(30u);
    FX.mock.deliver_then_fail_write_on_map = true; /* ADSP got it, write_fn still reports -EIO */
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == -EIO);
    FX.mock.deliver_then_fail_write_on_map = false;
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(r.cause == M11_SHMEM_CAUSE_MAP_WRITE_ERROR);
    CHECK(mock_dsp_maps() == 1u);
    CHECK(r.blocker == NULL && r.orphan_kind == M11_SHMEM_ORPHAN_MAP);
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == 0);
    CHECK(r.state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    check_held_after_unmap_ack(&r, m11_shmem_unmap_and_free(&FX.mgr, &r), "write error after delivery");
    fx_close();
}

static void p2_unmap_write_error_after_delivery_is_recovered(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    FX.mock.deliver_then_fail_write_on_unmap = true;
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EIO);
    FX.mock.deliver_then_fail_write_on_unmap = false;
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(r.cause == M11_SHMEM_CAUSE_UNMAP_WRITE_ERROR);
    CHECK(r.dsp_mapped, "the host still believes the ADSP maps it until an ACK says otherwise");
    check_held_after_unmap_ack(&r, m11_shmem_reconcile(&FX.mgr, &r, 10u), "unmap write error after delivery");
    CHECK(FX.mock.unmap_cmd_count == 1u);
    fx_close();
}

static void p2_short_write_on_unmap_keeps_ownership_unresolved(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    FX.mock.short_gpr_write_on_unmap = true;
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EIO);
    FX.mock.short_gpr_write_on_unmap = false;
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(r.cause == M11_SHMEM_CAUSE_UNMAP_SHORT_WRITE, "cause=%s", m11_shmem_cause_name(r.cause));
    CHECK(mock_dsp_maps() == 1u, "the short UNMAP never reached the ADSP");
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);
    fx_close();
}

static void p2_transport_disconnect_keeps_orphan_until_it_recovers(void) {
    fx_init(30u);
    FX.mock.hold_next_rsp = true;
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == -ETIMEDOUT);
    CHECK(m11_strict_mock_release_held(&FX.mock) == 1u);

    FX.mock.poll_read_errno = -ENODEV; /* transport gone: exact errno, orphan kept */
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -ENODEV);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(r.cause == M11_SHMEM_CAUSE_MAP_TRANSPORT_ERR, "cause=%s", m11_shmem_cause_name(r.cause));
    CHECK(m11_gpr_engine_orphan_tracked(&FX.gpr, r.orphan_token));
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);

    FX.mock.poll_read_errno = 0; /* transport back: the late ACK is still there */
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == 0);
    CHECK(r.state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    check_held_after_unmap_ack(&r, m11_shmem_unmap_and_free(&FX.mgr, &r), "transport recovered");
    fx_close();
}

static void p2_pdr_keeps_unresolved_with_blocker(void) {
    fx_init(30u);
    FX.mock.hold_next_rsp = true;
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == -ETIMEDOUT);
    CHECK(m11_strict_mock_release_held(&FX.mock) == 1u);

    FX.mock.poll_read_errno = -ENETRESET;
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -ENETRESET);
    CHECK(FX.gpr.pdr_down);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(r.cause == M11_SHMEM_CAUSE_MAP_PDR, "cause=%s", m11_shmem_cause_name(r.cause));
    CHECK(r.blocker != NULL, "PDR must publish a blocker");
    CHECK(FX.gpr.orphans_lost == 1u && m11_gpr_engine_orphan_count(&FX.gpr) == 0u);
    CHECK(!r.dsp_mapped, "a mapping must not be assumed or assumed away after PDR");
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -ENOENT);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && FX.mgr.unresolved_regions == 1u);
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    CHECK(m11_shmem_mgr_audit(&FX.mgr, &r, 1u) == 0u);
    fx_close();
}

static void p2_pdr_during_unmap_never_frees(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    FX.mock.poll_read_errno = -ENETRESET;
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -ENETRESET);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(r.cause == M11_SHMEM_CAUSE_UNMAP_PDR, "cause=%s", m11_shmem_cause_name(r.cause));
    CHECK(r.blocker != NULL);
    CHECK(r.dsp_mapped, "the recorded handle is kept, not dropped");
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);
    CHECK(FX.mock.unmap_cmd_count == 1u);
    fx_close();
}

static void p2_pdr_before_unmap_submit_is_unresolved_not_mapped(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    FX.gpr.pdr_down = true; /* engine latched since the MAP was ACKed */
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -ENETRESET);
    CHECK(FX.gpr.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED, "state=%s", m11_shmem_state_name(r.state));
    CHECK(r.blocker != NULL && r.cause == M11_SHMEM_CAUSE_UNMAP_PDR);
    CHECK(FX.mock.unmap_cmd_count == 0u);
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    fx_close();
}

static void p2_unmap_nack_blocks_with_blocker_and_no_resend(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    FX.mock.nack_shmem_unmap = true;
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EREMOTEIO);
    FX.mock.nack_shmem_unmap = false;
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(r.cause == M11_SHMEM_CAUSE_UNMAP_NACK, "cause=%s", m11_shmem_cause_name(r.cause));
    CHECK(r.blocker != NULL, "a consumed NACK leaves nothing to wait for");
    CHECK(r.dsp_mapped && mock_dsp_maps() == 1u);
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -ENOENT);
    CHECK(FX.mock.unmap_cmd_count == 1u, "no blind UNMAP resend, count=%u", FX.mock.unmap_cmd_count);
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    fx_close();
}

static void p2_unmap_not_attempted_is_retryable(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) FX.gpr.slots[i].in_use = true;
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -ENOSPC);
    CHECK(FX.gpr.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED);
    CHECK(r.state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED, "state=%s", m11_shmem_state_name(r.state));
    CHECK(r.dsp_mapped && FX.mock.unmap_cmd_count == 0u);
    for (size_t i = 0; i < M11_GPR_MAX_PENDING; i++) memset(&FX.gpr.slots[i], 0, sizeof(FX.gpr.slots[i]));
    check_held_after_unmap_ack(&r, m11_shmem_unmap_and_free(&FX.mgr, &r), "retryable unmap");
    CHECK(FX.mock.unmap_cmd_count == 1u);
    fx_close();
}

/* No path may resend MAP/UNMAP on its own: polling an orphan only listens. */
static void p2_orphan_polling_never_resends_map_or_unmap(void) {
    m11_shmem_region_t r;

    /* UNMAP orphan: the timeout itself, then repeated reconcile/release attempts. */
    fx_init(30u);
    CHECK(fx_map(&r) == 0);
    FX.mock.hold_next_rsp = true;
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -ETIMEDOUT);
    CHECK(r.cause == M11_SHMEM_CAUSE_UNMAP_TIMEOUT, "cause=%s", m11_shmem_cause_name(r.cause));
    CHECK(FX.mock.unmap_cmd_count == 1u, "unmap_cmd_count=%u right after the timeout", FX.mock.unmap_cmd_count);
    const uint32_t tx_unmap = FX.mock.tx_pkt_count;
    for (int i = 0; i < 5; i++) {
        CHECK(m11_shmem_reconcile(&FX.mgr, &r, 5u) == -ETIMEDOUT);
        CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);
    }
    CHECK(FX.mock.unmap_cmd_count == 1u && FX.mock.tx_pkt_count == tx_unmap,
          "UNMAP orphan polling sent %u extra packet(s)", FX.mock.tx_pkt_count - tx_unmap);
    CHECK(m11_strict_mock_release_held(&FX.mock) == 1u);
    check_held_after_unmap_ack(&r, m11_shmem_reconcile(&FX.mgr, &r, 10u), "unmap orphan, no resend");
    CHECK(FX.mock.unmap_cmd_count == 1u && FX.mock.tx_pkt_count == tx_unmap);
    fx_close();

    /* MAP orphan. */
    fx_init(30u);
    FX.mock.hold_next_rsp = true;
    CHECK(fx_map(&r) == -ETIMEDOUT);
    const uint32_t tx_map = FX.mock.tx_pkt_count;
    for (int i = 0; i < 5; i++) {
        CHECK(m11_shmem_reconcile(&FX.mgr, &r, 5u) == -ETIMEDOUT);
        CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);
    }
    CHECK(FX.mock.map_cmd_count == 1u && FX.mock.unmap_cmd_count == 0u && FX.mock.tx_pkt_count == tx_map,
          "MAP orphan polling changed the wire (map=%u unmap=%u)", FX.mock.map_cmd_count,
          FX.mock.unmap_cmd_count);
    CHECK(m11_strict_mock_release_held(&FX.mock) == 1u);
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == 0);
    check_held_after_unmap_ack(&r, m11_shmem_unmap_and_free(&FX.mgr, &r), "map orphan, no resend");
    CHECK(FX.mock.map_cmd_count == 1u && FX.mock.unmap_cmd_count == 1u);
    fx_close();
}

static void p2_map_ack_without_usable_handle_is_blocked(void) {
    fx_init(30u);
    FX.mock.zero_handle_shmem_map_rsp = true;
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == -EREMOTEIO);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(r.cause == M11_SHMEM_CAUSE_MAP_AMBIGUOUS_RSP);
    CHECK(r.blocker != NULL);
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -ENOENT);
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    fx_close();
}

static void p2_reconcile_misuse_is_rejected(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -EINVAL, "reconcile on an ACKed region");
    CHECK(m11_shmem_reconcile(NULL, &r, 10u) == -EINVAL);
    CHECK(m11_shmem_reconcile(&FX.mgr, NULL, 10u) == -EINVAL);
    check_held_after_unmap_ack(&r, m11_shmem_unmap_and_free(&FX.mgr, &r), "reconcile misuse");
    CHECK(m11_shmem_reconcile(&FX.mgr, &r, 10u) == -EINVAL, "reconcile on an UNMAP-ACKed (held) region");
    fx_close();
}

static void p2_engine_orphan_contract(void) {
    fx_init(30u);
    FX.mock.drop_shmem_map_rsp = true;
    uint32_t tok = 0;
    uint8_t zero[20] = {0};
    CHECK(m11_gpr_engine_submit(&FX.gpr, M11_APM_MODULE_IID, M11_APM_CMD_SHARED_MEM_MAP_REGIONS,
                                zero, sizeof(zero), &tok) == 0);
    CHECK(m11_gpr_engine_wait_token(&FX.gpr, tok, 20u, NULL, NULL, 0, NULL) == -ETIMEDOUT);
    CHECK(m11_gpr_engine_orphan_tracked(&FX.gpr, tok));
    CHECK(m11_gpr_engine_orphan_count(&FX.gpr) == 1u);
    CHECK(m11_gpr_engine_wait_token(&FX.gpr, tok, 20u, NULL, NULL, 0, NULL) == -EALREADY,
          "an orphan is collected through orphan_poll only");
    uint32_t st = 0, op = 0;
    CHECK(m11_gpr_engine_orphan_poll(&FX.gpr, tok, 20u, &st, &op, NULL, 0, NULL) == -ETIMEDOUT);
    CHECK(m11_gpr_engine_orphan_tracked(&FX.gpr, tok), "a timed-out poll must keep the orphan");
    CHECK(m11_gpr_engine_orphan_poll(&FX.gpr, tok + 99u, 20u, &st, &op, NULL, 0, NULL) == -ENOENT);
    CHECK(m11_gpr_engine_orphan_poll(&FX.gpr, 0u, 20u, &st, &op, NULL, 0, NULL) == -EINVAL);
    CHECK(m11_gpr_engine_close(&FX.gpr) == 0);
    CHECK(FX.gpr.orphans_lost == 1u);
    CHECK(!m11_gpr_engine_orphan_tracked(&FX.gpr, tok));
}

static void p2_non_ownership_timeouts_are_not_retained(void) {
    sc_setup(NULL, false);
    for (int i = 0; i < 40; i++) {
        uint32_t st = 0;
        CHECK(m11_gpr_query_spf_state(&SCG, 5u, &st) == -ETIMEDOUT);
    }
    CHECK(m11_gpr_engine_orphan_count(&SCG) == 0u, "plain timeouts must not pin slots");
    uint32_t st = 0;
    CHECK(m11_gpr_query_spf_state(&SCG, 5u, &st) == -ETIMEDOUT, "no slot exhaustion");
    sc_teardown();
}

static void p2_orphan_slot_exhaustion_fails_closed_and_cleans_up(void) {
    fx_init(30u);
    FX.mock.drop_shmem_map_rsp = true;
    uint8_t zero[20] = {0};
    for (unsigned i = 0; i < M11_GPR_MAX_PENDING; i++) {
        uint32_t tok = 0;
        CHECK(m11_gpr_engine_submit(&FX.gpr, M11_APM_MODULE_IID, M11_APM_CMD_SHARED_MEM_MAP_REGIONS,
                                    zero, sizeof(zero), &tok) == 0);
        CHECK(m11_gpr_engine_wait_token(&FX.gpr, tok, 5u, NULL, NULL, 0, NULL) == -ETIMEDOUT);
    }
    CHECK(m11_gpr_engine_orphan_count(&FX.gpr) == M11_GPR_MAX_PENDING);
    FX.mock.drop_shmem_map_rsp = false;
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == -ENOSPC, "no free slot: nothing may be sent");
    CHECK(FX.gpr.last_tx_status == M11_GPR_TX_NOT_ATTEMPTED);
    CHECK(r.map_tx_started && r.map_tx_unsent_proof, "only NOT_ATTEMPTED is the unsent proof");
    CHECK(r.state == M11_SHMEM_STATE_RELEASED, "state=%s", m11_shmem_state_name(r.state));
    check_counters_zero("exhausted slots");
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    fx_close();
}
#endif /* HARDENED */

/*
 * Reproduced hazard: after a timed-out UNMAP the old engine freed its slot, so a counter wrap
 * (or any reuse) could hand the SAME token to a new request while a late ACK for the old one
 * can still arrive and be taken for the new answer.
 */
static void p2_orphaned_token_is_not_reused(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    FX.mock.hold_next_rsp = true;
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -ETIMEDOUT);
    const uint32_t reserved = FX.gpr.next_token - 1u; /* the token the timed-out UNMAP used */
    FX.gpr.next_token = reserved;                     /* force a wrap onto it */
    uint32_t tok2 = 0;
    CHECK(m11_gpr_engine_submit(&FX.gpr, M11_APM_MODULE_IID, M11_APM_CMD_GET_SPF_STATE, NULL, 0, &tok2) == 0);
    CHECK(tok2 != reserved, "token %u was handed out again while its late ACK may still arrive", tok2);
    fx_close();
}

/* ===========================================================================================
 * P3 - per-channel Awinic speaker-protection result
 * ========================================================================================= */
#ifdef HARDENED

static m11_aw_safety_context_t p3_ctx(void) {
    m11_aw_safety_context_t c = {
        .aw_dev_0_switch = 0, .aw_dev_1_switch = 0, .amp_enable_requested = false,
        .vi_tx_subgraph_opened = true, .vi_tx_subgraph_prepared = true,
        .vi_tx_module_iid = M11_AW_VI_TX_MODULE_IID, .sp_rx_module_iid = M11_AW_SP_RX_MODULE_IID,
    };
    return c;
}

static m11_aw_cal_pair_t p3_cal(void) {
    int32_t pair[2] = { M11_MARBLE_CH0_FACTORY_MOHM, M11_MARBLE_CH1_FACTORY_MOHM };
    m11_aw_cal_pair_t cal;
    CHECK(m11_aw_parse_calr_pair((const uint8_t *)pair, sizeof(pair), &cal) == 0);
    return cal;
}

static void p3_setup(void) {
    fx_init(30u);
    FX.mock.vi_tx_opened = true;
    FX.mock.vi_tx_prepared = true;
}

static void p3_invariants(const m11_aw_apply_report_t *rep) {
    CHECK(!rep->rollback_attempted, "no automatic rollback exists");
    CHECK(!rep->amp_enabled, "the amplifier is never enabled");
    CHECK(!rep->safety_ctx_is_hardware_evidence, "caller-asserted context is not hardware evidence");
}

static void p3_all_ok(void) {
    p3_setup();
    m11_aw_safety_context_t ctx = p3_ctx();
    m11_aw_cal_pair_t cal = p3_cal();
    m11_aw_apply_report_t rep;
    CHECK(m11_aw_apply_and_verify_re_dsp_ex(&FX.gpr, &ctx, &cal, 30u, &rep) == 0);
    CHECK(rep.ch[0].stage == M11_AW_STAGE_READBACK_VERIFIED && rep.ch[1].stage == M11_AW_STAGE_READBACK_VERIFIED);
    CHECK(rep.pair_re_readback_verified && rep.primary_error == 0 && rep.primary_channel == -1);
    CHECK(rep.ch[0].readback_valid && rep.ch[0].readback_q12 == M11_MARBLE_CH0_FACTORY_Q12);
    CHECK(rep.ch[1].readback_valid && rep.ch[1].readback_q12 == M11_MARBLE_CH1_FACTORY_Q12);
    CHECK(FX.mock.tx_pkt_count == 4u);
    p3_invariants(&rep);
    CHECK(m11_aw_apply_and_verify_re_dsp(&FX.gpr, &ctx, &cal, 30u) == 0, "compat wrapper");
    fx_close();
}

/* ch0 applied and verified, ch1 refused: the old API said only "-EREMOTEIO". */
static void p3_ch0_ok_ch1_nack(void) {
    p3_setup();
    FX.mock.nack_set_cfg_ch_mask = 2u;
    m11_aw_safety_context_t ctx = p3_ctx();
    m11_aw_cal_pair_t cal = p3_cal();
    m11_aw_apply_report_t rep;
    int rc = m11_aw_apply_and_verify_re_dsp_ex(&FX.gpr, &ctx, &cal, 30u, &rep);
    CHECK(rc == -EREMOTEIO, "rc=%d", rc);
    CHECK(rep.primary_error == -EREMOTEIO && rep.primary_channel == 1);
    CHECK(rep.ch[0].stage == M11_AW_STAGE_READBACK_VERIFIED && rep.ch[0].error == 0);
    CHECK(rep.ch[0].dsp_state_may_have_changed);
    CHECK(rep.ch[1].stage == M11_AW_STAGE_FAILED);
    CHECK(rep.ch[1].failed_after == M11_AW_STAGE_SET_SENT && rep.ch[1].failed_op == M11_AW_OP_SET_CFG);
    CHECK(rep.ch[1].error == -EREMOTEIO);
    CHECK(rep.ch[1].dsp_state_may_have_changed, "a NACK does not prove the DSP kept its old value");
    CHECK(!rep.pair_re_readback_verified, "the pair must not be reported as protected");
    CHECK(rep.dsp_state_may_have_changed);
    CHECK(FX.mock.stored_q12_re[0] == M11_MARBLE_CH0_FACTORY_Q12 && FX.mock.stored_q12_re[1] == 0u,
          "ch0 applied, ch1 not: the partial state the caller must be told about");
    /* ch0 SET + ch0 GET + the refused ch1 SET; nothing after the failure (no rollback). */
    CHECK(FX.mock.tx_pkt_count == 3u, "no rollback / extra write after the failure, tx=%u", FX.mock.tx_pkt_count);
    p3_invariants(&rep);
    fx_close();

    p3_setup();
    FX.mock.nack_set_cfg_ch_mask = 2u;
    CHECK(m11_aw_apply_and_verify_re_dsp(&FX.gpr, &ctx, &cal, 30u) == -EREMOTEIO, "wrapper keeps the primary errno");
    fx_close();
}

/* The reverse case: ch0 fails first, ch1 must never be touched. */
static void p3_ch0_nack_ch1_never_sent(void) {
    p3_setup();
    FX.mock.nack_set_cfg_ch_mask = 1u;
    m11_aw_safety_context_t ctx = p3_ctx();
    m11_aw_cal_pair_t cal = p3_cal();
    m11_aw_apply_report_t rep;
    int rc = m11_aw_apply_and_verify_re_dsp_ex(&FX.gpr, &ctx, &cal, 30u, &rep);
    CHECK(rc == -EREMOTEIO);
    CHECK(rep.primary_channel == 0);
    CHECK(rep.ch[0].stage == M11_AW_STAGE_FAILED && rep.ch[0].failed_after == M11_AW_STAGE_SET_SENT);
    CHECK(rep.ch[1].stage == M11_AW_STAGE_NOT_SENT && rep.ch[1].failed_op == M11_AW_OP_NONE);
    CHECK(!rep.ch[1].dsp_state_may_have_changed && rep.ch[1].error == 0);
    CHECK(!rep.pair_re_readback_verified);
    CHECK(FX.mock.stored_q12_re[0] == 0u && FX.mock.stored_q12_re[1] == 0u);
    CHECK(FX.mock.tx_pkt_count == 1u, "fail-stop: ch1 must not be written, tx=%u", FX.mock.tx_pkt_count);
    p3_invariants(&rep);
    fx_close();
}

/* The ADSP applied the value but the ACK never came: the state still changed. */
static void p3_ch1_set_ack_lost_state_may_have_changed(void) {
    p3_setup();
    FX.mock.ack_lost_set_cfg_ch_mask = 2u;
    m11_aw_safety_context_t ctx = p3_ctx();
    m11_aw_cal_pair_t cal = p3_cal();
    m11_aw_apply_report_t rep;
    int rc = m11_aw_apply_and_verify_re_dsp_ex(&FX.gpr, &ctx, &cal, 30u, &rep);
    CHECK(rc == -ETIMEDOUT);
    CHECK(rep.ch[1].stage == M11_AW_STAGE_FAILED && rep.ch[1].failed_after == M11_AW_STAGE_SET_SENT);
    CHECK(rep.ch[1].error == -ETIMEDOUT && rep.ch[1].dsp_state_may_have_changed);
    CHECK(FX.mock.stored_q12_re[1] == M11_MARBLE_CH1_FACTORY_Q12, "the ADSP did apply ch1");
    CHECK(!rep.pair_re_readback_verified && rep.dsp_state_may_have_changed);
    CHECK(FX.mock.tx_pkt_count == 3u);
    p3_invariants(&rep);
    fx_close();
}

static void p3_ch1_readback_mismatch_reports_the_value_the_dsp_holds(void) {
    p3_setup();
    FX.mock.corrupt_get_cfg_ch_mask = 2u;
    m11_aw_safety_context_t ctx = p3_ctx();
    m11_aw_cal_pair_t cal = p3_cal();
    m11_aw_apply_report_t rep;
    int rc = m11_aw_apply_and_verify_re_dsp_ex(&FX.gpr, &ctx, &cal, 30u, &rep);
    CHECK(rc == -EBADMSG);
    CHECK(rep.ch[0].stage == M11_AW_STAGE_READBACK_VERIFIED);
    CHECK(rep.ch[1].stage == M11_AW_STAGE_FAILED && rep.ch[1].failed_after == M11_AW_STAGE_SET_ACKED);
    CHECK(rep.ch[1].failed_op == M11_AW_OP_VERIFY);
    CHECK(rep.ch[1].readback_valid && rep.ch[1].readback_q12 == (M11_MARBLE_CH1_FACTORY_Q12 ^ 0x1234u));
    CHECK(rep.ch[1].requested_q12 == M11_MARBLE_CH1_FACTORY_Q12);
    CHECK(!rep.pair_re_readback_verified);
    p3_invariants(&rep);
    fx_close();
}

static void p3_ch1_get_cfg_unanswered(void) {
    p3_setup();
    FX.mock.drop_get_cfg_rsp_ch_mask = 2u;
    m11_aw_safety_context_t ctx = p3_ctx();
    m11_aw_cal_pair_t cal = p3_cal();
    m11_aw_apply_report_t rep;
    int rc = m11_aw_apply_and_verify_re_dsp_ex(&FX.gpr, &ctx, &cal, 30u, &rep);
    CHECK(rc == -ETIMEDOUT);
    CHECK(rep.ch[1].stage == M11_AW_STAGE_FAILED && rep.ch[1].failed_after == M11_AW_STAGE_SET_ACKED);
    CHECK(rep.ch[1].failed_op == M11_AW_OP_GET_CFG && !rep.ch[1].readback_valid);
    CHECK(rep.ch[1].dsp_state_may_have_changed);
    CHECK(!rep.pair_re_readback_verified);
    p3_invariants(&rep);
    fx_close();
}

static void p3_build_failure_on_ch1_after_ch0_done(void) {
    p3_setup();
    m11_aw_safety_context_t ctx = p3_ctx();
    m11_aw_cal_pair_t cal = p3_cal();
    cal.re_mohm[1] = 100; /* outside the accepted RE window */
    m11_aw_apply_report_t rep;
    int rc = m11_aw_apply_and_verify_re_dsp_ex(&FX.gpr, &ctx, &cal, 30u, &rep);
    CHECK(rc == -ERANGE);
    CHECK(rep.ch[0].stage == M11_AW_STAGE_READBACK_VERIFIED);
    CHECK(rep.ch[1].stage == M11_AW_STAGE_FAILED && rep.ch[1].failed_op == M11_AW_OP_BUILD);
    CHECK(rep.ch[1].failed_after == M11_AW_STAGE_NOT_SENT && !rep.ch[1].dsp_state_may_have_changed);
    CHECK(!rep.pair_re_readback_verified);
    CHECK(FX.mock.tx_pkt_count == 2u);
    p3_invariants(&rep);
    fx_close();
}

static void p3_preconditions_send_nothing(void) {
    m11_aw_cal_pair_t cal;
    struct { int sw0, sw1; bool amp, opened, prepared; uint32_t vi, sp; int expect; } t[] = {
        { 0, 0, true,  true,  true,  M11_AW_VI_TX_MODULE_IID, M11_AW_SP_RX_MODULE_IID, -EACCES },
        { 1, 0, false, true,  true,  M11_AW_VI_TX_MODULE_IID, M11_AW_SP_RX_MODULE_IID, -EACCES },
        { 0, 1, false, true,  true,  M11_AW_VI_TX_MODULE_IID, M11_AW_SP_RX_MODULE_IID, -EACCES },
        { 0, 0, false, false, true,  M11_AW_VI_TX_MODULE_IID, M11_AW_SP_RX_MODULE_IID, -EDESTADDRREQ },
        { 0, 0, false, true,  false, M11_AW_VI_TX_MODULE_IID, M11_AW_SP_RX_MODULE_IID, -EDESTADDRREQ },
        { 0, 0, false, true,  true,  0x1234u,                 M11_AW_SP_RX_MODULE_IID, -EPROTO },
        { 0, 0, false, true,  true,  M11_AW_VI_TX_MODULE_IID, 0x1u,                    -EPROTO },
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        p3_setup();
        cal = p3_cal();
        m11_aw_safety_context_t ctx = {
            .aw_dev_0_switch = t[i].sw0, .aw_dev_1_switch = t[i].sw1, .amp_enable_requested = t[i].amp,
            .vi_tx_subgraph_opened = t[i].opened, .vi_tx_subgraph_prepared = t[i].prepared,
            .vi_tx_module_iid = t[i].vi, .sp_rx_module_iid = t[i].sp,
        };
        m11_aw_apply_report_t rep;
        int rc = m11_aw_apply_and_verify_re_dsp_ex(&FX.gpr, &ctx, &cal, 30u, &rep);
        CHECK(rc == t[i].expect, "case %zu: rc=%d expected %d", i, rc, t[i].expect);
        CHECK(rep.ch[0].stage == M11_AW_STAGE_NOT_SENT && rep.ch[1].stage == M11_AW_STAGE_NOT_SENT);
        CHECK(!rep.dsp_state_may_have_changed && !rep.pair_re_readback_verified);
        CHECK(FX.mock.tx_pkt_count == 0u, "case %zu: a packet was sent", i);
        CHECK(rep.primary_error == t[i].expect && rep.primary_channel == -1);
        p3_invariants(&rep);
        fx_close();
    }
}

/* A caller that claims the VI graph is ready does not make it so. */
static void p3_caller_asserted_context_is_not_evidence(void) {
    fx_init(30u); /* the mock's VI TX graph is NOT opened */
    m11_aw_safety_context_t ctx = p3_ctx(); /* ...but the caller says it is */
    m11_aw_cal_pair_t cal = p3_cal();
    m11_aw_apply_report_t rep;
    int rc = m11_aw_apply_and_verify_re_dsp_ex(&FX.gpr, &ctx, &cal, 30u, &rep);
    CHECK(rc == -EREMOTEIO, "the DSP must be the one to refuse: rc=%d", rc);
    CHECK(rep.ch[0].stage == M11_AW_STAGE_FAILED && rep.ch[0].failed_op == M11_AW_OP_SET_CFG);
    CHECK(!rep.pair_re_readback_verified);
    CHECK(!rep.safety_ctx_is_hardware_evidence);
    fx_close();
}

static void p3_null_report_is_allowed(void) {
    p3_setup();
    m11_aw_safety_context_t ctx = p3_ctx();
    m11_aw_cal_pair_t cal = p3_cal();
    CHECK(m11_aw_apply_and_verify_re_dsp_ex(&FX.gpr, &ctx, &cal, 30u, NULL) == 0);
    CHECK(m11_aw_apply_and_verify_re_dsp_ex(NULL, &ctx, &cal, 30u, NULL) == -EINVAL);
    fx_close();
}
#endif /* HARDENED (P3) */

/* ===========================================================================================
 * P4 - local release after the DSP unmap is proven
 * ========================================================================================= */

/*
 * Reproduced defect: UNMAP ACKed, close() fails once -> region stuck forever.
 * HOLD: after an UNMAP ACK nothing is released at all (the close fault is never reached); the
 * same fault on a MAP proven never sent leaves LOCAL_RELEASE_PENDING and a retry recovers it.
 */
static void p4_close_failure_after_unmap_ack_is_recoverable(void) {
#ifdef HOLD
    m11_shmem_region_t r;
    fx_init(30u);
    CHECK(fx_map(&r) == 0);
    FX.mock.fail_close_fd = true;
    check_held_after_unmap_ack(&r, m11_shmem_unmap_and_free(&FX.mgr, &r), "close fault never reached");
    CHECK(FX.mock.unmap_cmd_count == 1u);
    fx_close();

    fx_init(30u);
    FX.mock.fail_close_fd = true;
    (void)fx_map_unsent(&r);
    CHECK(r.state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING, "state=%s", m11_shmem_state_name(r.state));
    CHECK(r.remote_inactive && r.cause == M11_SHMEM_CAUSE_LOCAL_RELEASE_FAILED);
    CHECK(r.cleanup_error == -EIO && r.last_error == -ENOSPC, "cleanup=%d last=%d", r.cleanup_error, r.last_error);
    CHECK(FX.mgr.local_release_pending_regions == 1u && FX.mgr.unresolved_regions == 0u);
    CHECK(m11_shmem_mgr_audit(&FX.mgr, &r, 1u) == 0u);
    FX.mock.fail_close_fd = false; /* the local fault is gone */
    int u2 = m11_shmem_unmap_and_free(&FX.mgr, &r);
    CHECK(u2 == 0, "retry after the fault cleared returned %d (state %s)", u2, m11_shmem_state_name(r.state));
    CHECK(r.state == M11_SHMEM_STATE_RELEASED, "state=%s", m11_shmem_state_name(r.state));
    CHECK(FX.mock.map_cmd_count == 0u && FX.mock.unmap_cmd_count == 0u, "nothing may ever be sent");
    check_counters_zero("after recovered close failure");
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    fx_close();
#else
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    FX.mock.fail_close_fd = true;
    int u1 = m11_shmem_unmap_and_free(&FX.mgr, &r);
    CHECK(u1 == -EIO, "u1=%d", u1);
    CHECK(FX.mock.unmap_cmd_count == 1u && mock_dsp_maps() == 0u, "the DSP unmap itself completed");
    CHECK(!r.dsp_mapped && r.mem_map_handle == 0u);
#ifdef HARDENED
    CHECK(r.state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING, "state=%s", m11_shmem_state_name(r.state));
    CHECK(r.remote_inactive && r.cause == M11_SHMEM_CAUSE_LOCAL_RELEASE_FAILED);
    CHECK(r.cleanup_error == -EIO && r.last_error == -EIO);
    CHECK(FX.mgr.local_release_pending_regions == 1u && FX.mgr.unresolved_regions == 0u);
    CHECK(m11_shmem_mgr_audit(&FX.mgr, &r, 1u) == 0u);
#endif
    FX.mock.fail_close_fd = false; /* the local fault is gone */
    int u2 = m11_shmem_unmap_and_free(&FX.mgr, &r);
    CHECK(u2 == 0, "retry after the fault cleared returned %d (state %s)", u2, m11_shmem_state_name(r.state));
    CHECK(r.state == M11_SHMEM_STATE_RELEASED, "state=%s", m11_shmem_state_name(r.state));
    CHECK(FX.mock.unmap_cmd_count == 1u, "UNMAP was re-sent (%u)", FX.mock.unmap_cmd_count);
    check_counters_zero("after recovered close failure");
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    fx_close();
#endif
}

static void p4_repeated_retries_keep_counters_consistent(void) {
    fx_init(30u);
    m11_shmem_region_t r;
#ifdef HOLD
    FX.mock.fail_close_fd = true;
    (void)fx_map_unsent(&r); /* the first release attempt fails inside the MAP call */
#else
    CHECK(fx_map(&r) == 0);
    FX.mock.fail_close_fd = true;
#endif
    for (int i = 0; i < 6; i++) {
        int rc = m11_shmem_unmap_and_free(&FX.mgr, &r);
        CHECK(rc < 0, "retry %d unexpectedly succeeded", i);
#ifdef HARDENED
        CHECK(rc == -EIO, "retry %d rc=%d", i, rc);
        CHECK(FX.mgr.local_release_pending_regions == 1u, "pending=%u after %d retries",
              FX.mgr.local_release_pending_regions, i + 1);
        CHECK(FX.mgr.unresolved_regions == 0u);
        CHECK(m11_shmem_mgr_audit(&FX.mgr, &r, 1u) == 0u);
#endif
        CHECK(FX.mgr.active_dma_fds == 1u && FX.mgr.active_dsp_maps == 0u);
        CHECK(FX.mock.unmap_cmd_count == P4_UNMAPS, "UNMAP re-sent on retry %d", i);
    }
    FX.mock.fail_close_fd = false;
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == 0);
    check_counters_zero("after repeated retries");
    fx_close();
}

/* Partial cleanup: a retry resumes at the failed step and never repeats an earlier one. */
static void p4_partial_cleanup_resumes_at_failed_step(void) {
    const char *names[] = { "ion_unmap", "munmap", "close" };
    for (int step = 0; step < 3; step++) {
        fx_init(30u);
        bool *flag = step == 0 ? &FX.mock.fail_ion_unmap : step == 1 ? &FX.mock.fail_munmap : &FX.mock.fail_close_fd;
        m11_shmem_region_t r;
#ifdef HOLD
        *flag = true;
        (void)fx_map_unsent(&r); /* the first release runs (and fails) inside the MAP call */
#else
        CHECK(fx_map(&r) == 0);
        *flag = true;
        CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EIO, "%s: first release", names[step]);
#endif
        CHECK(FX.mgr.active_ion_imports == (step == 0 ? 1u : 0u), "%s: ion=%u", names[step], FX.mgr.active_ion_imports);
        CHECK(FX.mgr.active_mmaps == (step <= 1 ? 1u : 0u), "%s: mmaps=%u", names[step], FX.mgr.active_mmaps);
        CHECK(FX.mgr.active_dma_fds == 1u, "%s: fds=%u", names[step], FX.mgr.active_dma_fds);
#ifdef HARDENED
        CHECK(r.state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING, "%s: state=%s", names[step], m11_shmem_state_name(r.state));
        CHECK(m11_shmem_mgr_audit(&FX.mgr, &r, 1u) == 0u, "%s: audit", names[step]);
#endif
        *flag = false;
        int rc = m11_shmem_unmap_and_free(&FX.mgr, &r);
        CHECK(rc == 0, "%s: resume rc=%d (an already-done step was repeated?)", names[step], rc);
        CHECK(r.state == M11_SHMEM_STATE_RELEASED, "%s: state=%s", names[step], m11_shmem_state_name(r.state));
        check_counters_zero(names[step]);
        CHECK(FX.mock.unmap_cmd_count == P4_UNMAPS, "%s: UNMAP re-sent", names[step]);
        fx_close();
    }
}

static void p4_end_rw_failure_at_release_is_recorded_not_blocking(void) {
    fx_init(30u);
    m11_shmem_region_t r;
#ifdef HOLD
    FX.mock.fail_dma_buf_sync_end = true;
    (void)fx_map_unsent(&r); /* the release (and its END) runs inside the MAP call */
    CHECK(FX.mock.map_cmd_count == 0u, "nothing may be sent");
#else
    CHECK(fx_map(&r) == 0);
    FX.mock.fail_dma_buf_sync_end = true;
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == 0, "a failed cache-maintenance ioctl must not leak the buffer");
#endif
    CHECK(r.state == M11_SHMEM_STATE_RELEASED && !r.cpu_access_active);
#ifdef HARDENED
    CHECK(r.sync_end_failures == 1u && r.sync_end_count == 0u);
#endif
    check_counters_zero("END failure at release");
    fx_close();
}

static void p4_double_release_is_a_noop(void) {
    fx_init(30u);
    m11_shmem_region_t r;
#ifdef HOLD
    /* a held (UNMAP-ACKed) region: every later call is refused and sends nothing */
    CHECK(fx_map(&r) == 0);
    check_held_after_unmap_ack(&r, m11_shmem_unmap_and_free(&FX.mgr, &r), "held region");
    for (int i = 0; i < 3; i++) check_held_after_unmap_ack(&r, m11_shmem_unmap_and_free(&FX.mgr, &r), "held region again");
    CHECK(FX.mock.unmap_cmd_count == 1u);
    fx_close();
    fx_init(30u);
    (void)fx_map_unsent(&r);
    CHECK(r.state == M11_SHMEM_STATE_RELEASED);
#else
    CHECK(fx_map(&r) == 0);
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == 0);
#endif
    for (int i = 0; i < 3; i++) {
        CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == 0);
        CHECK(r.state == M11_SHMEM_STATE_RELEASED);
    }
    check_counters_zero("double release");
    CHECK(FX.mock.unmap_cmd_count == P4_UNMAPS);
    m11_shmem_region_t z;
    memset(&z, 0, sizeof(z));
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &z) == 0, "never-allocated region");
    check_counters_zero("zero region");
    fx_close();
}

#ifdef HARDENED
/*
 * White-box: LOCAL_RELEASE_PENDING is only ever entered with the remote-inactive proof. A record
 * that claims it without the proof is corrupt; it must be quarantined, never released.
 */
static void p4_pending_without_remote_proof_is_quarantined_not_released(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    CHECK(r.dsp_mapped && !r.remote_inactive);
    r.state = M11_SHMEM_STATE_LOCAL_RELEASE_PENDING; /* corrupt: no proof that the ADSP let go */
    int rc = m11_shmem_unmap_and_free(&FX.mgr, &r);
    CHECK(rc == -EPROTO, "rc=%d", rc);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED, "state=%s", m11_shmem_state_name(r.state));
    CHECK(r.blocker != NULL);
    CHECK(FX.mock.unsafe_release_attempts == 0u, "local handles were released under a live ADSP mapping");
    CHECK(r.dma_buf_fd >= 0 && r.vaddr != NULL && r.ion_imported, "local handles must be untouched");
    CHECK(mock_dsp_maps() == 1u && FX.mock.unmap_cmd_count == 0u);
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    fx_close();
}

#endif

static void p4_unknown_remote_ownership_is_never_released(void) {
    fx_init(30u);
    FX.mock.drop_shmem_map_rsp = true; /* no answer: remote state UNKNOWN */
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == -ETIMEDOUT);
    for (int i = 0; i < 3; i++) CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EBUSY);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    CHECK(FX.mgr.unresolved_regions == 1u, "unresolved=%u (counted once per region)", FX.mgr.unresolved_regions);
    CHECK(FX.mgr.active_dma_fds == 1u && FX.mgr.active_mmaps == 1u && FX.mgr.active_ion_imports == 1u);
    CHECK(r.last_error == -ETIMEDOUT, "the primary error must survive refused releases, last_error=%d", r.last_error);
#ifdef HARDENED
    /* A LOCAL_RELEASE_PENDING region without the remote-inactive proof is refused, not freed. */
    r.state = M11_SHMEM_STATE_LOCAL_RELEASE_PENDING;
    r.remote_inactive = false;
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &r) == -EPROTO);
    CHECK(r.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(FX.mock.unsafe_release_attempts == 0u);
    CHECK(m11_shmem_mgr_audit(&FX.mgr, &r, 1u) == 0u);
#endif
    fx_close();
}

/* alloc_and_map failing early AND its local cleanup failing must stay recoverable. */
static void p4_alloc_failure_with_cleanup_failure_is_recoverable(void) {
    fx_init(30u);
    FX.mock.fail_mmap = true;
    FX.mock.fail_close_fd = true;
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == -ENOMEM);
    FX.mock.fail_mmap = false;
    CHECK(FX.mgr.active_dma_fds == 1u, "the fd is still held");
    FX.mock.fail_close_fd = false;
    int rc = m11_shmem_unmap_and_free(&FX.mgr, &r);
    CHECK(rc == 0, "retry rc=%d state=%s", rc, m11_shmem_state_name(r.state));
    CHECK(r.state == M11_SHMEM_STATE_RELEASED);
    check_counters_zero("alloc failure recovery");
#ifdef HARDENED
    CHECK(r.last_error == -ENOMEM, "primary error must survive the cleanup failure, last_error=%d", r.last_error);
#endif
    CHECK(FX.mock.map_cmd_count == 0u, "nothing may be sent before the buffer is mapped");
    fx_close();
}

#ifdef HARDENED
static void p4_mixed_region_audit(void) {
    fx_init(30u);
    m11_shmem_region_t reg[4];
    memset(reg, 0, sizeof(reg));
    CHECK(fx_map(&reg[0]) == 0);              /* A: healthy */
    FX.mock.drop_shmem_map_rsp = true;
    CHECK(fx_map(&reg[1]) == -ETIMEDOUT);     /* B: unresolved */
    FX.mock.drop_shmem_map_rsp = false;
    FX.mock.fail_close_fd = true;             /* C: proven unsent, local release pending */
    (void)fx_map_unsent(&reg[2]);
    FX.mock.fail_close_fd = false;
    CHECK(reg[2].state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING, "C state=%s", m11_shmem_state_name(reg[2].state));
    CHECK(m11_shmem_mgr_audit(&FX.mgr, reg, 4u) == 0u, "audit after A/B/C");
    CHECK(FX.mgr.unresolved_regions == 1u && FX.mgr.local_release_pending_regions == 1u);
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &reg[2]) == 0);
    CHECK(m11_shmem_mgr_audit(&FX.mgr, reg, 4u) == 0u, "audit after C recovered");
    /* A: the UNMAP is ACKed but the transmitted region is held (post-MAP hold) */
    CHECK(m11_shmem_unmap_and_free(&FX.mgr, &reg[0]) == -EPERM);
    CHECK(reg[0].state == M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED && reg[0].ion_imported);
    CHECK(m11_shmem_mgr_audit(&FX.mgr, reg, 4u) == 0u, "audit after A held");
    CHECK(FX.mgr.unresolved_regions == 1u && FX.mgr.active_dma_fds == 2u && FX.mgr.active_dsp_maps == 0u);

    /* the audit must actually catch drift */
    FX.mgr.active_mmaps++;
    CHECK((m11_shmem_mgr_audit(&FX.mgr, reg, 4u) & 2u) != 0u, "audit missed an mmap counter drift");
    FX.mgr.active_mmaps--;
    FX.mgr.unresolved_regions++;
    CHECK((m11_shmem_mgr_audit(&FX.mgr, reg, 4u) & 16u) != 0u, "audit missed an unresolved counter drift");
    FX.mgr.unresolved_regions--;
    CHECK(m11_shmem_mgr_audit(&FX.mgr, reg, 4u) == 0u);
    fx_close();
}
#endif

/* ===========================================================================================
 * P5 - CPU-access bracket on error paths
 * ========================================================================================= */
static uint32_t SG_VI[2] = { 0xB00000D5u, 0xB00000CEu };

static int p5_open(m11_shmem_region_t *r, uint32_t n) {
    uint32_t dsp = 0;
    return m11_apm_transact_graph_open_region(&FX.gpr, &FX.mgr, r, 0u, SG_VI, n, 30u, &dsp);
}

/* Reproduced defect: START issued, payload build fails, END never issued. */
static void p5_build_failure_closes_the_bracket_it_opened(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    CHECK(p5_open(&r, 2u) == 0);
    CHECK(!r.cpu_access_active, "a good open leaves the bracket closed");
    int rc = p5_open(&r, 0u); /* 0 sub-graphs: build fails after START */
    CHECK(rc == -EINVAL, "primary error rc=%d", rc);
    CHECK(!r.cpu_access_active, "START was issued and never closed");
    CHECK(!FX.mock.shm_slots[0].cpu_access_active, "kernel-side bracket still open");
    CHECK(r.sync_start_count == r.sync_end_count, "start=%u end=%u", r.sync_start_count, r.sync_end_count);
    CHECK(FX.mock.graph_open_cmd_count == 1u, "GRAPH_OPEN must not be sent for a failed build");
#ifdef HARDENED
    CHECK(r.last_error == -EINVAL);
#endif
    CHECK(p5_open(&r, 2u) == 0, "the region stays usable");
    fx_close();
}

static void p5_start_failure_sends_nothing(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    CHECK(p5_open(&r, 2u) == 0);
    const uint32_t opens = FX.mock.graph_open_cmd_count, starts = r.sync_start_count;
    FX.mock.fail_dma_buf_sync_start = true;
    CHECK(p5_open(&r, 2u) == -EIO);
    CHECK(!r.cpu_access_active && r.sync_start_count == starts);
    CHECK(FX.mock.graph_open_cmd_count == opens, "GRAPH_OPEN sent after a failed START");
    FX.mock.fail_dma_buf_sync_start = false;
    CHECK(p5_open(&r, 2u) == 0);
    fx_close();
}

static void p5_end_failure_blocks_graph_open_and_claims_no_sync(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    CHECK(p5_open(&r, 2u) == 0);
    const uint32_t opens = FX.mock.graph_open_cmd_count;
    FX.mock.fail_dma_buf_sync_end = true;
    int rc = p5_open(&r, 2u);
    CHECK(rc == -EIO, "rc=%d", rc);
    CHECK(FX.mock.graph_open_cmd_count == opens, "GRAPH_OPEN sent although END_RW failed");
    CHECK(r.cpu_access_active, "the bracket really is still open");
    CHECK(!r.cpu_cache_clean_for_dsp, "no cache sync may be claimed");
#ifdef HARDENED
    CHECK(r.sync_end_failures == 1u);
#endif
    FX.mock.fail_dma_buf_sync_end = false;
    CHECK(p5_open(&r, 2u) == 0, "recoverable once END works again");
    CHECK(FX.mock.graph_open_cmd_count == opens + 1u);
    fx_close();
}

#ifdef HARDENED
static void p5_primary_error_survives_a_failing_cleanup_end(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    CHECK(p5_open(&r, 2u) == 0);
    const uint32_t opens = FX.mock.graph_open_cmd_count;
    FX.mock.fail_dma_buf_sync_end = true;
    int rc = p5_open(&r, 0u); /* build fails, then the cleanup END fails too */
    CHECK(rc == -EINVAL, "the build failure is the primary error, rc=%d", rc);
    CHECK(r.last_error == -EINVAL && r.cleanup_error == -EIO, "last=%d cleanup=%d", r.last_error, r.cleanup_error);
    CHECK(r.cpu_access_active && r.sync_end_failures == 1u, "state must say the bracket is still open");
    CHECK(FX.mock.graph_open_cmd_count == opens);
    fx_close();
}
#endif

#ifdef HARDENED
/* The failing ioctl's own errno must reach the caller, not a generic replacement. */
static void p5_sync_errnos_reach_the_caller_unchanged(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    CHECK(p5_open(&r, 2u) == 0);
    const uint32_t opens = FX.mock.graph_open_cmd_count;

    FX.mock.fail_dma_buf_sync_end = true;
    FX.mock.sync_end_errno = -ENOTTY;
    int rc = p5_open(&r, 2u);
    CHECK(rc == -ENOTTY, "END_RW errno came back as %d", rc);
    CHECK(r.last_error == -ENOTTY, "last_error=%d", r.last_error);
    CHECK(FX.mock.graph_open_cmd_count == opens);
    FX.mock.fail_dma_buf_sync_end = false;
    FX.mock.sync_end_errno = 0;
    CHECK(p5_open(&r, 2u) == 0, "recoverable");

    FX.mock.fail_dma_buf_sync_start = true;
    FX.mock.sync_start_errno = -ENOTTY;
    rc = p5_open(&r, 2u);
    CHECK(rc == -ENOTTY, "START_RW errno came back as %d", rc);
    CHECK(FX.mock.graph_open_cmd_count == opens + 1u);
    fx_close();
}
#endif

static void p5_submit_failure_after_end(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    CHECK(p5_open(&r, 2u) == 0);
    const uint32_t opens = FX.mock.graph_open_cmd_count;
    FX.mock.fail_gpr_write_on_graph_open = true;
    CHECK(p5_open(&r, 2u) == -EIO);
    CHECK(FX.gpr.last_tx_status == M11_GPR_TX_WRITE_ERROR);
    CHECK(!r.cpu_access_active && r.cpu_cache_clean_for_dsp, "END ran before the failed submit");
    CHECK(FX.mock.graph_open_cmd_count == opens);
    FX.mock.fail_gpr_write_on_graph_open = false;
    CHECK(p5_open(&r, 2u) == 0);
    fx_close();
}

static void p5_dsp_nack_on_graph_open_leaves_bracket_closed(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    FX.mock.nack_graph_open = true;
    CHECK(p5_open(&r, 2u) == -EREMOTEIO);
    CHECK(!r.cpu_access_active && !FX.mock.shm_slots[0].cpu_access_active);
    fx_close();
}

/* A bracket that was already open on entry (stock opens it at allocation) is left as found. */
static void p5_bracket_open_on_entry_is_left_as_found(void) {
    fx_init(30u);
    m11_shmem_region_t r;
    CHECK(fx_map(&r) == 0);
    CHECK(r.cpu_access_active);
    const uint32_t ends = r.sync_end_count;
    CHECK(p5_open(&r, 0u) == -EINVAL);
    CHECK(r.cpu_access_active && r.sync_end_count == ends, "entered open, must stay open");
    CHECK(FX.mock.graph_open_cmd_count == 0u);
    fx_close();
}

/* ===========================================================================================
 * P6 - IBASIC status 0 for a request whose success response carries data
 * ========================================================================================= */
static void gen_ibasic_ok_only(sc_t *s, uint32_t token, uint32_t opcode) {
    sc_push_ibasic(s, 0, 0x42D3u, token, opcode, 0u);
}

static void gen_ibasic_nack_only(sc_t *s, uint32_t token, uint32_t opcode) {
    sc_push_ibasic(s, 0, 0x42D3u, token, opcode, 1u);
}

static void gen_ibasic_ok_then_data(sc_t *s, uint32_t token, uint32_t opcode) {
    sc_push_ibasic(s, 0, 0x42D3u, token, opcode, 0u);
    uint8_t p[SC_PKT_MAX];
    size_t n = 0;
    if (m11_aw_pack_get_cfg_rsp_pkt(p, sizeof(p), &n, SC_SRC, token, 0u, 0u, M11_MARBLE_CH0_FACTORY_MOHM) == 0) {
        sc_push(s, 0, p, n);
    }
}

static int p6_get_cfg(uint32_t timeout_ms, uint32_t *dsp, m11_apm_rsp_aw_re_get_cfg_t *rsp, size_t *len) {
    uint8_t req[64];
    memset(req, 0, sizeof(req));
    *len = 0;
    return m11_gpr_engine_transact(&SCG, M11_AW_SP_RX_MODULE_IID, M11_APM_CMD_GET_CFG,
                                   req, sizeof(req), timeout_ms, dsp, rsp, sizeof(*rsp), len);
}

static void p6_get_cfg_answered_by_a_bare_ack_is_not_success(void) {
    sc_setup(gen_ibasic_ok_only, false);
    m11_apm_rsp_aw_re_get_cfg_t rsp;
    uint32_t dsp = 0;
    size_t len = 0;
    memset(&rsp, 0, sizeof(rsp));
    int rc = p6_get_cfg(30u, &dsp, &rsp, &len);
    CHECK(rc < 0, "GET_CFG reported success (rc=0, rsp_len=%zu) without any config data", len);
#ifdef HARDENED
    CHECK(rc == -ETIMEDOUT, "rc=%d", rc);
    CHECK(SCG.rx_ibasic_ack_without_data == 1u);
#endif
    sc_teardown();
}

static void p6_ack_followed_by_the_data_response_succeeds(void) {
    sc_setup(gen_ibasic_ok_then_data, false);
    m11_apm_rsp_aw_re_get_cfg_t rsp;
    uint32_t dsp = 0;
    size_t len = 0;
    memset(&rsp, 0, sizeof(rsp));
    int rc = p6_get_cfg(30u, &dsp, &rsp, &len);
    CHECK(rc == 0, "rc=%d", rc);
    CHECK(len == sizeof(rsp), "the data response must be what is returned, len=%zu", len);
    CHECK(rsp.env.q12_re == M11_MARBLE_CH0_FACTORY_Q12, "q12=%u", rsp.env.q12_re);
    sc_teardown();
}

static void p6_explicit_nack_still_fails_fast(void) {
    sc_setup(gen_ibasic_nack_only, false);
    m11_apm_rsp_aw_re_get_cfg_t rsp;
    uint32_t dsp = 0;
    size_t len = 0;
    int rc = p6_get_cfg(30u, &dsp, &rsp, &len);
    CHECK(rc == -EREMOTEIO && dsp == 1u, "rc=%d dsp=%u", rc, dsp);
    sc_teardown();
}

static void p6_ack_only_commands_still_complete_on_ibasic_zero(void) {
    static const uint32_t ops[] = { M11_APM_CMD_SET_CFG, M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS,
                                    M11_APM_CMD_GRAPH_STOP, M11_APM_CMD_GRAPH_CLOSE,
                                    M11_APM_CMD_GRAPH_PREPARE, M11_APM_CMD_GRAPH_START };
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        sc_setup(gen_ibasic_ok_only, false);
        uint8_t payload[16] = {0};
        uint32_t dsp = 99;
        int rc = m11_gpr_engine_transact(&SCG, M11_AW_SP_RX_MODULE_IID, ops[i], payload, sizeof(payload),
                                         30u, &dsp, NULL, 0, NULL);
        CHECK(rc == 0 && dsp == 0u, "opcode 0x%08x: rc=%d", ops[i], rc);
        sc_teardown();
    }
}

static void p6_spf_state_bare_ack_is_not_success(void) {
    sc_setup(gen_ibasic_ok_only, false);
    uint32_t st = 0;
    int rc = m11_gpr_query_spf_state(&SCG, 30u, &st);
    CHECK(rc < 0, "rc=%d", rc);
    sc_teardown();
}

#if defined(HARDENED) && defined(M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2)
#define DATAPATH 1
/* ===========================================================================================
 * P7 - shared-memory end point data commands (P5 speaker session): each completes on its own
 * response opcode, with an exact payload size and the status word at its offset
 * ========================================================================================= */
#define P7_WR_EP 0x40BDu
#define P7_RD_EP 0x4547u
/* gen_arg0: payload length override (0 = exact), gen_arg1: data status, gen_arg2: 1 = answer from APM's
 * port instead of the end point's, 2 = an IBASIC error instead of the completion */
static void gen_data_rsp(sc_t *s, uint32_t token, uint32_t opcode) {
    uint8_t pl[64], p[SC_PKT_MAX];
    memset(pl, 0, sizeof(pl));
    uint32_t rsp = 0, port = opcode == M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2 ? P7_RD_EP : P7_WR_EP;
    size_t len = 0, at = 0;
    if (opcode == M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2) { rsp = M11_DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE_V2; len = 32; at = 12; }
    else if (opcode == M11_DATA_CMD_WR_SH_MEM_EP_EOS) { rsp = M11_DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED; len = 8; at = 4; }
    else if (opcode == M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2) { rsp = M11_DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE_V2; len = 56; at = 0; }
    if (s->gen_arg2 == 2u) { sc_push_ibasic(s, 0, port, token, opcode, 1u); return; }
    if (s->gen_arg0) len = s->gen_arg0;
    memcpy(pl + at, &s->gen_arg1, sizeof(uint32_t));
    size_t n = sc_build(p, M11_GPR_DOMAIN_ADSP, s->gen_arg2 == 1u ? M11_APM_MODULE_IID : port, token, rsp, pl, len);
    if (n) sc_push(s, 0, p, n);
}

static int p7_send(uint32_t opcode, uint32_t *dsp, size_t *len) {
    uint8_t cmd[44];
    uint8_t rsp[64];
    memset(cmd, 0, sizeof(cmd));
    *len = 0;
    uint32_t port = opcode == M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2 ? P7_RD_EP : P7_WR_EP;
    size_t cmd_len = opcode == M11_DATA_CMD_WR_SH_MEM_EP_EOS ? 4u : opcode == M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2 ? 32u : 44u;
    return m11_gpr_engine_transact(&SCG, port, opcode, cmd, cmd_len, 30u, dsp, rsp, sizeof(rsp), len);
}

static void p7_data_commands_complete_on_their_own_responses(void) {
    static const uint32_t ops[] = { M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2, M11_DATA_CMD_WR_SH_MEM_EP_EOS,
                                    M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2 };
    static const size_t lens[] = { 32u, 8u, 56u };
    for (size_t i = 0; i < 3; i++) {
        sc_setup(gen_data_rsp, false);
        uint32_t dsp = 99;
        size_t len = 0;
        int rc = p7_send(ops[i], &dsp, &len);
        CHECK(rc == 0 && dsp == 0u && len == lens[i], "opcode 0x%08x: rc=%d dsp=%u len=%zu", ops[i], rc, dsp, len);
        sc_teardown();
        sc_setup(gen_data_rsp, false);
        SC.gen_arg1 = 5u; /* a non-zero data / render status fails the command */
        rc = p7_send(ops[i], &dsp, &len);
        CHECK(rc == -EREMOTEIO && dsp == 5u, "opcode 0x%08x status 5: rc=%d dsp=%u", ops[i], rc, dsp);
        sc_teardown();
    }
}

static void p7_malformed_or_misrouted_completions_are_dropped(void) {
    static const uint32_t ops[] = { M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2, M11_DATA_CMD_WR_SH_MEM_EP_EOS,
                                    M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2 };
    static const uint32_t bad_lens[] = { 28u, 12u, 48u };
    for (size_t i = 0; i < 3; i++) {
        sc_setup(gen_data_rsp, false);
        SC.gen_arg0 = bad_lens[i];
        uint32_t dsp = 0;
        size_t len = 0;
        int rc = p7_send(ops[i], &dsp, &len);
        CHECK(rc == -ETIMEDOUT && SCG.rx_dropped_malformed == 1u, "opcode 0x%08x short: rc=%d", ops[i], rc);
        sc_teardown();
        sc_setup(gen_data_rsp, false);
        SC.gen_arg2 = 1u; /* the right token from the wrong port */
        rc = p7_send(ops[i], &dsp, &len);
        CHECK(rc == -ETIMEDOUT && SCG.rx_dropped_malformed == 1u, "opcode 0x%08x misrouted: rc=%d", ops[i], rc);
        sc_teardown();
    }
}

static void p7_data_command_nack_fails_fast(void) {
    sc_setup(gen_data_rsp, false);
    SC.gen_arg2 = 2u;
    uint32_t dsp = 0;
    size_t len = 0;
    int rc = p7_send(M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2, &dsp, &len);
    CHECK(rc == -EREMOTEIO && dsp == 1u, "rc=%d dsp=%u", rc, dsp);
    CHECK(!m11_gpr_opcode_retains_on_timeout(M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2) &&
          !m11_gpr_opcode_retains_on_timeout(M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2) &&
          !m11_gpr_opcode_retains_on_timeout(M11_DATA_CMD_WR_SH_MEM_EP_EOS),
          "data commands carry no ownership: never retained as orphans");
    sc_teardown();
}
#endif

/* ===========================================================================================
 * Simulator integration (teardown behaviour with the hardened layers)
 * ========================================================================================= */
static m11_strict_mock_t SIMM;
static m11_gpr_transport_t SIM_TP;
static m11_shmem_backend_t SIM_BE;
static m11_gpr_engine_t SIM_GPR;
static m11_shmem_mgr_t SIM_SHM;

static int sim_run(m11_sim_report_t *rep) {
    m11_sim_config_t cfg;
    m11_sim_default_marble_config(&cfg);
    m11_strict_mock_bind(&SIMM, &SIM_TP, &SIM_BE);
    CHECK(m11_gpr_engine_init(&SIM_GPR, &SIM_TP, 0x2001u) == 0);
    CHECK(m11_shmem_mgr_init(&SIM_SHM, &SIM_BE, &SIM_GPR, 50u) == 0);
    return m11_sim_run_speaker_qualification(&cfg, &SIM_GPR, &SIM_SHM, 50u, rep);
}

static void sim_positive_path_unchanged(void) {
    m11_strict_mock_init(&SIMM);
    m11_sim_report_t rep;
    CHECK(sim_run(&rep) == 0);
#ifdef HOLD
    /* post-MAP hold: graphs stopped and closed, no UNMAP, region and endpoint held */
    CHECK(rep.cal_applied_and_verified && rep.retaining_teardown && !rep.clean_teardown && rep.graphs_started);
    CHECK(rep.post_map_hold && rep.final_shmem_state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    CHECK(SIMM.map_cmd_count == 1u && SIMM.unmap_cmd_count == 0u);
#else
    CHECK(rep.cal_applied_and_verified && rep.clean_teardown && rep.graphs_started);
    CHECK(rep.final_shmem_state == M11_SHMEM_STATE_RELEASED);
#endif
    CHECK(SIMM.unsafe_release_attempts == 0u);
#ifdef HARDENED
    CHECK(rep.aw_report_valid && rep.aw_report.pair_re_readback_verified);
#endif
}

#ifdef HARDENED
static void sim_partial_calibration_is_reported(void) {
    m11_strict_mock_init(&SIMM);
    SIMM.nack_set_cfg_ch_mask = 2u;
    m11_sim_report_t rep;
    int rc = sim_run(&rep);
    CHECK(rc == -EREMOTEIO, "rc=%d", rc);
    CHECK(rep.primary_errno == -EREMOTEIO);
    CHECK(!rep.cal_applied_and_verified && !rep.graphs_started);
    CHECK(rep.aw_report_valid);
    CHECK(rep.aw_report.ch[0].stage == M11_AW_STAGE_READBACK_VERIFIED);
    CHECK(rep.aw_report.ch[1].stage == M11_AW_STAGE_FAILED);
    CHECK(rep.aw_report.dsp_state_may_have_changed && !rep.aw_report.pair_re_readback_verified);
    CHECK(SIMM.stored_q12_re[0] == M11_MARBLE_CH0_FACTORY_Q12 && SIMM.stored_q12_re[1] == 0u);
    CHECK(rep.retaining_teardown && !rep.clean_teardown && rep.cleanup_errno == 0,
          "graphs are still torn down cleanly; the memory is held (post-MAP hold)");
    CHECK(SIMM.unmap_cmd_count == 0u);
}

/* The late MAP ACK is collected in teardown (reconciled), then the region is held, never unmapped. */
static void sim_write_error_with_late_ack_is_reconciled_and_held(void) {
    m11_strict_mock_init(&SIMM);
    SIMM.deliver_then_fail_write_on_map = true;
    m11_sim_report_t rep;
    int rc = sim_run(&rep);
    CHECK(rc == -EIO, "the primary failure must be preserved, rc=%d", rc);
    CHECK(rep.primary_errno == -EIO && rep.cleanup_errno == 0, "cleanup_errno=%d", rep.cleanup_errno);
    CHECK(rep.final_shmem_state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED, "state=%s",
          m11_shmem_state_name(rep.final_shmem_state));
    CHECK(rep.post_map_hold && rep.retaining_teardown && !rep.clean_teardown);
    CHECK(rep.unresolved_ownership == 0u && rep.orphans_outstanding == 0u);
    CHECK(SIMM.map_cmd_count == 1u && SIMM.unmap_cmd_count == 0u);
    CHECK(SIMM.unsafe_release_attempts == 0u);
}

static void sim_unanswered_map_stays_unresolved_with_a_reason(void) {
    m11_strict_mock_init(&SIMM);
    SIMM.drop_shmem_map_rsp = true;
    m11_sim_report_t rep;
    int rc = sim_run(&rep);
    CHECK(rc == -ETIMEDOUT);
    CHECK(rep.final_shmem_state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED);
    CHECK(rep.shmem_cause == M11_SHMEM_CAUSE_MAP_TIMEOUT, "cause=%s", m11_shmem_cause_name(rep.shmem_cause));
    CHECK(rep.orphans_outstanding == 1u && rep.unresolved_ownership == 1u && !rep.clean_teardown);
    CHECK(SIMM.unsafe_release_attempts == 0u);
}

/*
 * Post-MAP hold: a run whose MAP went out never releases, so a local release failure needs a
 * failure before any MAP (here the ION import) whose cleanup close then fails.
 */
static void sim_local_release_failure_is_reported_as_pending(void) {
    m11_strict_mock_init(&SIMM);
    SIMM.fail_ion_import = true;
    SIMM.fail_close_fd = true;
    m11_sim_report_t rep;
    int rc = sim_run(&rep);
    CHECK(rc == -EFAULT, "the primary (import) failure must be preserved, rc=%d", rc);
    CHECK(rep.cleanup_errno == -EIO, "cleanup_errno=%d", rep.cleanup_errno);
    CHECK(rep.final_shmem_state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING, "state=%s",
          m11_shmem_state_name(rep.final_shmem_state));
    CHECK(rep.local_release_pending == 1u && rep.unresolved_ownership == 0u && !rep.clean_teardown);
    CHECK(rep.shmem_cause == M11_SHMEM_CAUSE_LOCAL_RELEASE_FAILED);
    CHECK(!rep.post_map_hold && !rep.retaining_teardown && !rep.shmem_mapped);
    CHECK(SIMM.map_cmd_count == 0u && SIMM.unmap_cmd_count == 0u, "nothing may be sent");
}

/*
 * Post-MAP hold: PD down after the MAP ACK. The teardown never enters the UNMAP call (the engine's
 * PDR latch is not what keeps the wire quiet); the region manager records the unknown remote state
 * (cause MAP_PDR, not UNMAP_PDR) and the region stays held.
 */
static void sim_pdr_while_held_records_unknown_without_unmap(void) {
    m11_strict_mock_init(&SIMM);
    SIMM.pdr_on_graph_prepare = true;
    m11_sim_report_t rep;
    int rc = sim_run(&rep);
    CHECK(rc == -ENETRESET && rep.primary_errno == -ENETRESET, "rc=%d", rc);
    CHECK(rep.post_map_hold && !rep.unmap_attempted, "unmap_attempted=%d", rep.unmap_attempted);
    CHECK(rep.final_shmem_state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED, "state=%s",
          m11_shmem_state_name(rep.final_shmem_state));
    CHECK(rep.shmem_cause == M11_SHMEM_CAUSE_MAP_PDR && rep.shmem_blocker != NULL, "cause=%s",
          m11_shmem_cause_name(rep.shmem_cause));
    CHECK(rep.cleanup_errno == -ENETRESET && !rep.clean_teardown && !rep.retaining_teardown);
    CHECK(rep.retained_region_valid && rep.retained_region.dma_buf_fd >= 0 && rep.retained_region.vaddr != NULL &&
          rep.retained_region.ion_imported && rep.endpoint_close_deferred);
    CHECK(SIMM.map_cmd_count == 1u && SIMM.unmap_cmd_count == 0u && SIMM.unsafe_release_attempts == 0u);
}
#endif

int main(void) {
#ifdef HARDENED
    printf("== M11 runtime hardening regression suite (HARDENED API v%d) ==\n",
           M11_RUNTIME_HARDENING_API_VERSION);
#else
    printf("== M11 runtime hardening regression suite (BASELINE build: no hardening API) ==\n");
#endif
    /* P1 */
    RUN(p1_normal_round_trip_unchanged);
    RUN(p1_seventy_events_before_valid_ack);
    RUN(p1_event_flood_before_valid_ack);
    RUN(p1_stale_and_wrong_packet_flood_before_valid_ack);
    RUN(p1_token_opcode_peer_checks_survive);
    RUN(p1_real_time_total_deadline_with_dripfed_events);
    RUN(p1_real_time_ack_inside_deadline_succeeds);
    RUN(p1_endless_event_stream_cannot_extend_the_deadline_real_time);
    RUN(p1_transport_errno_is_exact);
#ifdef HARDENED
    RUN(p1_each_poll_gets_only_the_remaining_time);
    RUN(p1_deadline_is_total_not_per_poll_fake_clock);
    RUN(p1_endless_event_stream_cannot_extend_the_deadline_fake_clock);
    RUN(p1_stuck_clock_cannot_hang_forever);
    RUN(p1_stuck_clock_idle_queue_times_out);
    RUN(p1_clock_stepping_backwards_never_extends_polls);
#endif
    /* P2 */
    RUN(p2_ack_before_timeout_is_normal);
    RUN(p2_late_map_ack_after_timeout_is_correlated);
    RUN(p2_late_unmap_ack_after_timeout_is_correlated);
    RUN(p2_orphaned_token_is_not_reused);
#ifdef HARDENED
    RUN(p2_duplicate_late_ack_is_applied_once);
    RUN(p2_wrong_token_ack_never_resolves);
    RUN(p2_wrong_peer_ack_never_resolves);
    RUN(p2_late_map_nack_is_held_not_released);
    RUN(p2_write_error_after_delivery_is_recovered);
    RUN(p2_unmap_write_error_after_delivery_is_recovered);
    RUN(p2_short_write_on_unmap_keeps_ownership_unresolved);
    RUN(p2_transport_disconnect_keeps_orphan_until_it_recovers);
    RUN(p2_pdr_keeps_unresolved_with_blocker);
    RUN(p2_pdr_during_unmap_never_frees);
    RUN(p2_pdr_before_unmap_submit_is_unresolved_not_mapped);
    RUN(p2_unmap_nack_blocks_with_blocker_and_no_resend);
    RUN(p2_unmap_not_attempted_is_retryable);
    RUN(p2_orphan_polling_never_resends_map_or_unmap);
    RUN(p2_map_ack_without_usable_handle_is_blocked);
    RUN(p2_reconcile_misuse_is_rejected);
    RUN(p2_engine_orphan_contract);
    RUN(p2_non_ownership_timeouts_are_not_retained);
    RUN(p2_orphan_slot_exhaustion_fails_closed_and_cleans_up);
#endif
    /* P3 */
#ifdef HARDENED
    RUN(p3_all_ok);
    RUN(p3_ch0_ok_ch1_nack);
    RUN(p3_ch0_nack_ch1_never_sent);
    RUN(p3_ch1_set_ack_lost_state_may_have_changed);
    RUN(p3_ch1_readback_mismatch_reports_the_value_the_dsp_holds);
    RUN(p3_ch1_get_cfg_unanswered);
    RUN(p3_build_failure_on_ch1_after_ch0_done);
    RUN(p3_preconditions_send_nothing);
    RUN(p3_caller_asserted_context_is_not_evidence);
    RUN(p3_null_report_is_allowed);
#endif
    /* P4 */
    RUN(p4_close_failure_after_unmap_ack_is_recoverable);
    RUN(p4_repeated_retries_keep_counters_consistent);
    RUN(p4_partial_cleanup_resumes_at_failed_step);
    RUN(p4_end_rw_failure_at_release_is_recorded_not_blocking);
    RUN(p4_double_release_is_a_noop);
    RUN(p4_unknown_remote_ownership_is_never_released);
    RUN(p4_alloc_failure_with_cleanup_failure_is_recoverable);
#ifdef HARDENED
    RUN(p4_mixed_region_audit);
    RUN(p4_pending_without_remote_proof_is_quarantined_not_released);
#endif
    /* P5 */
    RUN(p5_build_failure_closes_the_bracket_it_opened);
    RUN(p5_start_failure_sends_nothing);
    RUN(p5_end_failure_blocks_graph_open_and_claims_no_sync);
#ifdef HARDENED
    RUN(p5_sync_errnos_reach_the_caller_unchanged);
    RUN(p5_primary_error_survives_a_failing_cleanup_end);
#endif
    RUN(p5_submit_failure_after_end);
    RUN(p5_dsp_nack_on_graph_open_leaves_bracket_closed);
    RUN(p5_bracket_open_on_entry_is_left_as_found);
    /* P6 */
    RUN(p6_get_cfg_answered_by_a_bare_ack_is_not_success);
    RUN(p6_ack_followed_by_the_data_response_succeeds);
    RUN(p6_explicit_nack_still_fails_fast);
    RUN(p6_ack_only_commands_still_complete_on_ibasic_zero);
    RUN(p6_spf_state_bare_ack_is_not_success);
#ifdef DATAPATH
    /* P7 */
    RUN(p7_data_commands_complete_on_their_own_responses);
    RUN(p7_malformed_or_misrouted_completions_are_dropped);
    RUN(p7_data_command_nack_fails_fast);
#endif
    /* Simulator integration */
    RUN(sim_positive_path_unchanged);
#ifdef HARDENED
    RUN(sim_partial_calibration_is_reported);
    RUN(sim_write_error_with_late_ack_is_reconciled_and_held);
    RUN(sim_unanswered_map_stays_unresolved_with_a_reason);
    RUN(sim_local_release_failure_is_reported_as_pending);
    RUN(sim_pdr_while_held_records_unknown_without_unmap);
#endif

    printf("== %d/%d cases passed, %d/%d checks passed ==\n", g_cases - g_cases_failed, g_cases,
           g_checks - g_checks_failed, g_checks);
    if (g_cases_failed != 0) {
        printf("HARDENING RESULT: FAIL (%d case(s) failed)\n", g_cases_failed);
        return 1;
    }
    printf("HARDENING RESULT: PASS\n");
    return 0;
}
