/* M17 G5b/G5c: the speaker protection probe and the loudness backstop (docs/m17-speaker-protection.md,
 * docs/m17-loudness-plan.md).
 *
 * While the desktop's sound plays, the speaker stream reads the Awinic protection module's live status, the way stock
 * libawcal's aw_dsp_read_st (0x108dcc) does: a SET_CFG of the read command for AW message 7 on parameter 0x10013D2A of
 * module 0x42D3, then a GET_CFG of 32 bytes. The reply holds, per speaker, the live Re (Q12 ohms) and a temperature
 * value. Nothing is written but that read command.
 *
 * G5c: the stream may play louder than M19's -10 dB only while the probe runs, and the backstop drops it back to M19's
 * gain for the rest of the boot when a probe fails, a live temperature reaches te_limit, a live Re leaves
 * [re_min, re_max], or ref_limit probes in a row while the sound was loud brought no live reply. It never raises it.
 *
 * This file builds the two requests, checks the reply, decides the backstop and writes one line a probe. It has no DSP
 * access of its own: the stream sends the requests through the custodian. */
#ifndef M17_AWPROBE_H
#define M17_AWPROBE_H

#include <stddef.h>
#include <stdint.h>

#define M17_AW_IID 0x000042D3u        /* the protection module (module_sp), M11 */
#define M17_AW_MSG_PARAM 0x10013D2Au  /* the AW message parameter of the first amplifier pair */
#define M17_AW_MSG_STATUS 7u          /* libawcal's "read st" */
#define M17_AW_STATUS_BYTES 32u
#define M17_AW_CMD_BYTES 56u          /* apm_cmd_header_t, then {iid, param, 24, 0} and the six-word message */
#define M17_AW_REQ_BYTES 64u          /* apm_cmd_header_t, then {iid, param, 32, 0} and 32 zero bytes */
#define M17_AW_RSP_BYTES 52u          /* status, {iid, param, 32, 0}, then 32 bytes */
#define M17_AW_REF_TE 25              /* the temperature of a reference reply (the calibration's, G5b) */

struct m17_aw_status {
    uint32_t raw[8];
    int32_t re_mohm[2], te[2]; /* per speaker: the live Re in milliohms (Q12 x 1000 >> 12) and the temperature value */
};

/* why the backstop dropped the gain; M17_DROP_NONE while it has not */
enum m17_drop { M17_DROP_NONE = 0, M17_DROP_PROBE, M17_DROP_TEMP, M17_DROP_RE, M17_DROP_BLIND };

struct m17_backstop {
    int32_t te_limit;       /* a live temperature at or above it drops (G5c: 45) */
    int32_t re_min, re_max; /* a live Re outside drops, milliohms (3000, 12000) */
    unsigned ref_limit;     /* this many reference replies in a row while loud drop (10: 20 s at 2 s) */
    int32_t loud_peak;      /* the output peak since the last probe that counts as loud (3277: -20 dBFS) */
};

struct m17_backstop_state {
    enum m17_drop dropped;
    unsigned ref_streak;
};

/* The entry sets this; with log NULL or period_ms 0 the stream never probes and never plays louder than M19. */
struct m17_probe_config {
    const char *log;          /* "/var/lib/m19/m17-aw.log" */
    unsigned period_ms;       /* between probes while the amplifiers are on */
    unsigned log_limit;       /* bytes; the older file is kept as LOG.1 */
    int32_t gain_q15;         /* G5c: the stream's gain while the backstop has not dropped (0: M19's) */
    int32_t peak_limit;       /* G5c: its clamp */
    struct m17_backstop backstop;
};
extern struct m17_probe_config m17_probe;

size_t m17_aw_status_cmd(uint8_t out[M17_AW_CMD_BYTES]);
size_t m17_aw_status_req(uint8_t out[M17_AW_REQ_BYTES]);
/* The GET_CFG reply as the engine hands it over: 0, or -EPROTO when its status, module, parameter, size or error code
 * is not the one asked for. */
int m17_aw_status_parse(const void *rsp, size_t len, struct m17_aw_status *out);
/* A reply that carries the calibration's reference instead of a live estimate (G5b: both words of each speaker's Re
 * equal and both temperatures 25). */
int m17_aw_status_is_reference(const struct m17_aw_status *st);
/* Whether the configuration may play louder: the probe on and every limit set and sane. */
int m17_backstop_valid(const struct m17_probe_config *cfg);
/* One probe's outcome: probe_rc (0 or the probe's failure), its status, and the output peak since the last probe.
 * Returns the reason when this probe drops the gain, M17_DROP_NONE otherwise (also once already dropped). */
enum m17_drop m17_backstop_step(const struct m17_backstop *cfg, struct m17_backstop_state *state, int probe_rc,
                                const struct m17_aw_status *st, int32_t recent_peak);
const char *m17_drop_name(enum m17_drop why);
/* One line: boot time, both speakers' Re and temperature, the eight raw words, whether the amplifiers are on, the
 * stream's output peak, the probe's rc and DSP status, the gain in force, whether the reply was live, and the backstop's
 * state. 0 or -errno. */
int m17_aw_status_log(const char *path, unsigned limit, const struct m17_aw_status *st, int amp_on, int32_t peak_out, int rc,
                      uint32_t dsp_status, int32_t gain_q15, int live, enum m17_drop dropped);

#endif
