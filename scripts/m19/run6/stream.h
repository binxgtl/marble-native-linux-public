/* M19 R6: the desktop's speaker stream (docs/m19-r6.md). M11 Run31's native speaker session, step for step, with one
 * change after its step 7: once the plan's bounded chord has played to its last BUFFER_DONE, the same RX graph keeps
 * running and takes PCM from the sound server instead, until the stop.
 *
 *  - every sample from the server is scaled by gain_q15 (10362/32768, -10 dB) and clamped to +-peak_limit (10362,
 *    -10 dBFS): the loudest the server can make the speaker is the chord's level, at the plan's volume level 8;
 *  - a buffer with no server data, or with a short read, is padded with silence (an underrun), never repeated;
 *  - the amplifier switches go Disable (read back) after idle_off_ms of silence and Enable (read back) before the
 *    first buffer that is not silent; Run31 proved both writes on the running graph, the Disable in its teardown;
 *  - stop_fn (the session guard's marker, or SIGTERM) ends the stream; the buffers in flight complete and Run31's
 *    teardown runs: both switches Disable first, read back, then the graphs. No UNMAP, ever.
 * Any DSP status, wait timeout or readback failure ends the stream the same way. */
#ifndef M19_STREAM_H
#define M19_STREAM_H
#ifndef M11_CUSTODIAN_NATIVE
#error "m19 stream requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "speaker_session_native.h"
#include <stddef.h>
#include <stdint.h>

#define M19_STREAM_GAIN_Q15 10362
#define M19_STREAM_PEAK 10362
#define M19_STREAM_CHUNK_MAX 16384u
/* report.stage once the stream ended cleanly (after Run31's M11_SPK_PLAYED) */
#define M19_SPK_STREAMED (M11_SPK_PLAYED + 1)

typedef struct {
    int streaming;            /* the chord is done and the server's PCM flows */
    int amp_on;               /* both switches read back Enable */
    int stopped;              /* stop_fn ended the stream */
    uint64_t buffers, bytes_in, bytes_loud, underruns;
    uint32_t amp_enables, amp_disables;
    int32_t peak_in, peak_out; /* largest magnitude read from the server, and sent to the DSP */
    uint64_t started_ms, last_loud_ms;
} m19_stream_status;

typedef struct {
    m11_speaker_io spk;       /* Run31's session: plan, custodian, regions, buffers, the chord's amp_window_ms */
    /* bytes read from the server into out (at most room, whole frames), 0 when none is waiting */
    size_t (*source_fn)(void *user, uint8_t *out, size_t room);
    int (*stop_fn)(void *user);
    void (*streaming_fn)(void *user, const m11_speaker_report *, const m19_stream_status *); /* once, at the switch */
    void (*status_fn)(void *user, const m19_stream_status *); /* every status_ms */
    void *user;
    uint32_t idle_off_ms, status_ms;
    int32_t gain_q15, peak_limit;
} m19_stream_io;

/* 0 once the stream was stopped and Run31's teardown completed; otherwise the first failure. */
int m19_stream_session_run(const m19_stream_io *, m11_speaker_report *, m19_stream_status *);

/* Scales samples in place and clamps them; nonzero when any input sample was not zero. Peaks are magnitudes. */
int m19_stream_scale(int16_t *pcm, size_t samples, int32_t gain_q15, int32_t limit, int32_t *peak_in, int32_t *peak_out);

#endif
