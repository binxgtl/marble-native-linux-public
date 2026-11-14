/* M17 G5b: the speaker protection probe (docs/m17-speaker-protection.md).
 *
 * While the desktop's sound plays, the speaker stream reads the Awinic protection module's live status, the way stock
 * libawcal's aw_dsp_read_st (0x108dcc) does: a SET_CFG of the read command for AW message 7 on parameter 0x10013D2A of
 * module 0x42D3, then a GET_CFG of 32 bytes. The reply holds, per speaker, the live Re (Q12 ohms) and a temperature
 * value. Nothing is written but that read command; the level, the gain and the protection's settings never change.
 *
 * This file builds the two requests, checks the reply and writes one line a probe. It has no DSP access of its own:
 * the stream sends the requests through the custodian. */
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

struct m17_aw_status {
    uint32_t raw[8];
    int32_t re_mohm[2], te[2]; /* per speaker: the live Re in milliohms (Q12 x 1000 >> 12) and the temperature value */
};

/* The entry sets this; with log NULL the stream never probes. */
struct m17_probe_config {
    const char *log;      /* "/var/lib/m19/m17-aw.log" */
    unsigned period_ms;   /* between probes while the amplifiers are on */
    unsigned log_limit;   /* bytes; the older file is kept as LOG.1 */
};
extern struct m17_probe_config m17_probe;

size_t m17_aw_status_cmd(uint8_t out[M17_AW_CMD_BYTES]);
size_t m17_aw_status_req(uint8_t out[M17_AW_REQ_BYTES]);
/* The GET_CFG reply as the engine hands it over: 0, or -EPROTO when its status, module, parameter, size or error code
 * is not the one asked for. */
int m17_aw_status_parse(const void *rsp, size_t len, struct m17_aw_status *out);
/* One line: boot time, both speakers' Re and temperature, the eight raw words, whether the amplifiers are on, the
 * stream's output peak, and the probe's rc. 0 or -errno. */
int m17_aw_status_log(const char *path, unsigned limit, const struct m17_aw_status *st, int amp_on, int32_t peak_out, int rc,
                      uint32_t dsp_status);

#endif
