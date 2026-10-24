/* P5 W5 (docs/m11-argon-speaker-run-design.md): the staged speaker session plan (plan.bin, written by the
 * local-only scripts/m11/r2/speaker_plan.py). Built only in the reviewed M11_CUSTODIAN_NATIVE build.
 *
 * The parser checks every size against the file before it points into it, requires the exact section
 * order the generator writes (VI graph, RX graph, IDS, BACKEND, CONTROL, RE, SIGNAL, PCM), and keeps
 * pointers into the caller's buffer (nothing is copied). It never interprets a payload: the session sends
 * the out-of-band and in-band blobs as they are. A plan that fails any check is refused whole (-EBADMSG).
 */
#ifndef M11_SPEAKER_PLAN_NATIVE_H
#define M11_SPEAKER_PLAN_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "speaker_plan_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include <stddef.h>
#include <stdint.h>

#define M11_PLAN_MAX_SGS 8u
#define M11_PLAN_MAX_CFGS 16u
#define M11_PLAN_MAX_CTLS 8u
#define M11_PLAN_MAX_OOB 65536u     /* a graph open or calibration blob (fits one mapped region) */
#define M11_PLAN_MAX_INBAND 1024u   /* one in-band SET_CFG body (well under one 4,096-byte GPR packet) */

typedef struct { const uint8_t *data; uint32_t len; } m11_plan_blob;

typedef struct {
    uint32_t graph_id;                    /* 1 = VI, 2 = RX */
    uint32_t num_sgs, sgs[M11_PLAN_MAX_SGS];
    m11_plan_blob open, cal;
    uint32_t num_cfgs;
    m11_plan_blob cfg[M11_PLAN_MAX_CFGS];
} m11_plan_graph;

typedef struct {
    uint32_t direction, rate, channels, format, period, periods;
    char name[64];
} m11_plan_backend;

typedef struct { char name[44]; char value[20]; } m11_plan_control;

typedef struct {
    m11_plan_graph vi, rx;
    uint32_t wr_ep, rd_ep, sp_rx, vi_tx, tdm_sink, tdm_source, volume;
    uint32_t stream_rate, stream_format, stream_channels, vi_rate, vi_format, vi_channels, volume_level;
    m11_plan_backend backend[2];          /* [0] RX playback, [1] TX capture */
    uint32_t num_controls;
    m11_plan_control control[M11_PLAN_MAX_CTLS];
    int32_t re_mohm[2];
    uint32_t duration_ms, fade_ms, num_tones;
    int32_t peak_mdbfs;
    m11_plan_blob pcm;                    /* S16_LE interleaved at stream_rate x stream_channels */
    uint8_t acdb_sha256[32];
} m11_speaker_plan;

/* 0 with *out filled (pointers into buf), or -EBADMSG. */
int m11_speaker_plan_parse(const uint8_t *buf, size_t len, m11_speaker_plan *out);

#endif
