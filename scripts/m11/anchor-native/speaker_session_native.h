/* P5 W5 (docs/m11-argon-speaker-run-design.md, sections 3 and 4): the native speaker session. Built only in
 * the reviewed M11_CUSTODIAN_NATIVE build; never part of a candidate until the operator's review (CP2,
 * criterion 9).
 *
 * The stock AGM/PAL order, fail-closed; the first failing step stops the session and the teardown runs:
 *  1. plan and amplifier pre-checks: the AW module instances are the ones the Re code is written for, both
 *     amplifier switches are set Disable and both profiles to the plan's values, each read back;
 *  2. two regions mapped through the caller's map_fn (the custodian: MAP intent, census, PDR settle): the
 *     out-of-band command region and the data region;
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
 *  7. play: the plan's PCM through the write buffers, each refilled on its BUFFER_DONE, then EOS and its
 *     RENDERED, all inside amp_window_ms from the amplifier enable;
 *  8. teardown, always, from wherever the session stopped: both switches Disable first (read back) if
 *     either was ever written Enable, then GRAPH_STOP RX, RX back end close, GRAPH_STOP VI, TX back end
 *     close, GRAPH_CLOSE RX, GRAPH_CLOSE VI, each only if its counterpart ran (no DSP command once the
 *     engine latched PDR). No UNMAP, no unimport, no free: the regions stay held (post-MAP hold) and the
 *     caller ends the boot retaining.
 */
#ifndef M11_SPEAKER_SESSION_NATIVE_H
#define M11_SPEAKER_SESSION_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "speaker_session_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "speaker_plan_native.h"
#include "snd_backend_native.h"
#include "../qualification/runtime-repair/m11_aw_protection.h"
#include "../qualification/runtime-repair/m11_shmem.h"

typedef struct {
    m11_gpr_engine_t *eng;                  /* the journaled engine */
    m11_shmem_mgr_t *mgr;
    int (*map_fn)(void *user, size_t bytes, unsigned *slot);
    m11_shmem_region_t *(*region_fn)(void *user, unsigned slot);
    void *user;
    m11_snd_backend *snd;                   /* prepared before the seal */
    const m11_speaker_plan *plan;
    void (*record_fn)(void *user, const char *line);   /* one evidence record per call */
    uint64_t (*now_fn)(void *user);
    uint32_t cmd_timeout_ms;                /* per DSP command */
    uint32_t eos_timeout_ms;
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
    M11_SPK_RX_START, M11_SPK_GATE, M11_SPK_AMP_ON, M11_SPK_RX_BE_PREPARE, M11_SPK_PLAYED, M11_SPK_EOS
};

typedef struct {
    int stage, rc, fail_step;
    unsigned regions_mapped;
    int vi_opened, vi_started, rx_opened, rx_started, amp_touched, amp_on;
    uint32_t buffers_sent, buffers_done, bytes_played, rd_queued, rd_done;
    int eos_rc;
    uint64_t amp_on_ms, amp_off_ms;
    int teardown_rc, amp_off_verified, pdr_seen;
    m11_aw_apply_report_t re;
} m11_speaker_report;

/* 0 once the PCM played to its EOS and the teardown completed, otherwise the first failure (negative errno);
 * the report says where and what was undone. */
int m11_speaker_session_run(const m11_speaker_io *, m11_speaker_report *);

#endif
