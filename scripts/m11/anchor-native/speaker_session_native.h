/* P5 W5 (docs/m11-argon-speaker-run-design.md, sections 3 and 4): the native speaker session. Built only in
 * the reviewed M11_CUSTODIAN_NATIVE build; never part of a candidate until the operator's review (CP2,
 * criterion 9).
 *
 * The stock AGM/PAL order, fail-closed; the first failing step stops the session and the teardown runs:
 *  1. plan and amplifier pre-checks: the AW module instances are the ones the Re code is written for, both
 *     amplifier switches are set Disable and both profiles to the plan's values, each read back;
 *  2. two regions mapped through the caller's map_fn (the custodian: MAP intent, census, PDR settle): the
 *     out-of-band command region and the data region. Every DSP command from here on goes through the
 *     custodian (W5b, rev 6 owner session calls: graph ledger, single-owner accounting); each out-of-band
 *     payload gets its own 4 KiB-aligned offset of the command region, never reused;
 *  3. VI: TX back end open (HW_PARAMS), GRAPH_OPEN and calibration out of band, the in-band configs,
 *     PREPARE, START, the read buffers queued once (never re-queued: stock PAL never reads the VI front end),
 *     TX back end PREPARE;
 *  4. RX: RX back end open (HW_PARAMS: the kernel votes the LPASS TDM clock), GRAPH_OPEN and calibration out
 *     of band, the in-band configs, Re applied and read back on both channels (VI prepared, amplifier off),
 *     PREPARE, START;
 *  5. gate: every step above returned 0 with DSP status 0, Re read back on both channels, both switches still
 *     read back Disable;
 *  6. amplifier on: both switches Enable (read back), then the RX back end PREPARE (the kernel unmutes the
 *     codec DAIs);
 *  7. play: the plan's PCM through the write buffers, each refilled on its BUFFER_DONE, every buffer done
 *     with status 0, inside amp_window_ms from the amplifier enable; then the stop (the teardown). No EOS, as
 *     stock PCM playback: libagm_pcm_plugin.so has no agm_session_eos, only stop (Run30 EOS {0,0});
 *  8. teardown, always, from wherever the session stopped: both switches Disable first (read back) if
 *     either was ever written Enable, then GRAPH_STOP RX, RX back end close, GRAPH_STOP VI, TX back end
 *     close, GRAPH_CLOSE RX, GRAPH_CLOSE VI, each as the custodian's graph ledger allows (a graph left
 *     UNKNOWN is never commanded again; no DSP command once the engine latched PDR). No UNMAP, no
 *     unimport, no free: the regions stay held (post-MAP hold) and the caller ends the boot retaining.
 */
#ifndef M11_SPEAKER_SESSION_NATIVE_H
#define M11_SPEAKER_SESSION_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "speaker_session_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "speaker_plan_native.h"
#include "snd_backend_native.h"
#include "../qualification/runtime-repair/m11_aw_protection.h"
#include "../qualification/ownership/m11_custodian.h"

typedef struct {
    m11_custodian *cust;                    /* the owner; its engine is the journaled one */
    int (*map_fn)(void *user, size_t bytes, unsigned *slot);   /* a custodian MAP; slot = its region */
    void *user;
    m11_snd_backend *snd;                   /* prepared before the seal */
    const m11_speaker_plan *plan;
    void (*record_fn)(void *user, const char *line);   /* one evidence record per call */
    void (*settle_fn)(void *user);          /* after every custodian call and wait (P5: the runner's PDR settle);
                                             * NULL: none */
    uint64_t (*now_fn)(void *user);
    uint32_t wait_timeout_ms;               /* per data buffer (commands use the custodian's budget) */
    uint32_t amp_window_ms;                 /* amplifier enable -> disable */
    size_t region_bytes;                    /* each of the two regions */
    unsigned write_buffers;                 /* 2..8 */
    uint32_t buffer_ms;                     /* 10..100 */
} m11_speaker_io;

/* steps (report.stage = the last completed one) */
enum {
    M11_SPK_PLAN = 1, M11_SPK_AMP_OFF, M11_SPK_MAPPED,
    M11_SPK_VI_BE_OPEN, M11_SPK_VI_OPEN, M11_SPK_VI_CAL, M11_SPK_VI_CFG, M11_SPK_VI_PREPARE, M11_SPK_VI_START,
    M11_SPK_VI_READS, M11_SPK_VI_BE_PREPARE,
    M11_SPK_RX_BE_OPEN, M11_SPK_RX_OPEN, M11_SPK_RX_CAL, M11_SPK_RX_CFG, M11_SPK_RX_RE, M11_SPK_RX_PREPARE,
    M11_SPK_RX_START, M11_SPK_GATE, M11_SPK_AMP_ON, M11_SPK_RX_BE_PREPARE, M11_SPK_PLAYED
};

typedef struct {
    int stage, rc, fail_step;
    unsigned regions_mapped;
    int vi_opened, vi_started, rx_opened, rx_started, amp_touched, amp_on;
    uint32_t buffers_sent, buffers_done, bytes_played, rd_queued, rd_done;
    uint64_t amp_on_ms, amp_off_ms;
    int teardown_rc, amp_off_verified, pdr_seen;
    m11_aw_apply_report_t re;
} m11_speaker_report;

/* 0 once every PCM buffer completed with status 0 and the teardown completed, otherwise the first failure (negative errno);
 * the report says where and what was undone. */
int m11_speaker_session_run(const m11_speaker_io *, m11_speaker_report *);

#endif
