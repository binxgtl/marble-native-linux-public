/* Experimental Linux SPF query only. Not a playback API or qualified payload. */
#ifndef M11_GPR_NATIVE_H
#define M11_GPR_NATIVE_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define M11_GPR_MAX 4096u
#define M11_GPR_EVENTS 16u
#define M11_GPR_GET_SPF 0x01001021u
#define M11_GPR_SPF_RESPONSE 0x02001007u
#define M11_GPR_BASIC_RESPONSE 0x02001005u
#define M11_GPR_SOURCE_PORT 0x2003u
struct m11_audio_runtime;

enum m11_gpr_outcome {
    M11_GPR_INVALID, M11_GPR_OPEN_FAILED, M11_GPR_DIRTY_QUEUE,
    M11_GPR_TX_FAILED, M11_GPR_TX_INCOMPLETE, M11_GPR_RX_FAILED,
    M11_GPR_PROTOCOL_ERROR, M11_GPR_SPF_READY, M11_GPR_SPF_NOT_READY,
    M11_GPR_FIRMWARE_REJECTED, M11_GPR_TIMEOUT, M11_GPR_SERVICE_DOWN,
    M11_GPR_CANCELLED, M11_GPR_IO_ERROR, M11_GPR_CLOSE_FAILED
};
enum m11_gpr_stage { M11_GPR_BEGIN, M11_GPR_OPEN, M11_GPR_PREFLIGHT,
    M11_GPR_TX_BEGIN, M11_GPR_TX_RETURN, M11_GPR_RX_RETURN,
    M11_GPR_CLOSE_BEGIN, M11_GPR_CLOSE_RETURN, M11_GPR_DONE };
struct m11_gpr_event {
    uint32_t stage, outcome, size, reserved;
    int64_t rc;                 /* Linux negative errno, not libc's bare -1. */
    uint64_t monotonic_ns;
    unsigned char packet[M11_GPR_MAX];
};
struct m11_gpr_result {
    unsigned char capture_nonce[16], image_sha256[32];
    uint32_t token;
    uint64_t start_ns, deadline_ns;
    enum m11_gpr_outcome outcome;
    unsigned int event_count;
    struct m11_gpr_event events[M11_GPR_EVENTS];
    int worker_reaped, worker_exit_ok, close_returned, close_ok;
    int ipc_complete, query_consistent;
    pid_t unresolved_worker;    /* Nonzero means caller must retain containment. */
    int permits_playback;      /* Always zero, including an SPF_READY response. */
};
struct m11_gpr_session {
    /* Public Linux entry requires an acquired runtime, live audio-PD and owner
     * admission. Legacy boolean is retained for injected core tests ONLY; it
     * cannot authorize the public endpoint entry. No stock Android use. */
    int exclusive_native_owner, consumed;
    struct m11_audio_runtime *runtime;
    dev_t expected_device;
    uint32_t token;
    unsigned char capture_nonce[16], image_sha256[32];
    /* Borrowed pipe/socket descriptors: any activity/error/HUP invalidates query.
     * Public entry overwrites service_down_fd with its owned, latched notifier.
     * Caller supplies cancel_fd and keeps it valid throughout the operation. */
    int service_down_fd, cancel_fd;
    uint32_t budget_ms, reap_grace_ms; /* 1..4000 and 1..200 respectively. */
    /* Optional diagnostic sink, invoked only in the contained worker before
     * sending the same event to PID1. Must be bounded/nonblocking; its failure
     * fails evidence closed. NULL preserves the historical behavior. A sink
     * return is not proof of host delivery or a successful device operation. */
    int (*observe)(void *, const struct m11_gpr_event *);
    void *observe_context;
};

/* Opens only /dev/aud_pasthru_adsp in an isolated child, sends one payload-free
 * GET_SPF_STATE, matches typed response, closes, and bounds parent observation.
 * Kernel D-state cannot be killed/reaped by a userspace deadline. Unresolved
 * worker is reported; never assume teardown or retry in that case.
 * Return 0 only for complete, normally reaped SPF_READY evidence; -1 otherwise.
 * Neither value grants runtime safety qualification or amplifier permission. */
int m11_gpr_linux_query(struct m11_gpr_session *, struct m11_gpr_result *);
/* Complete JSON or -1; never returns a successful truncated record. No I/O.
 * Caller must drain/seal logs separately; this is not a USB completeness proof. */
int m11_gpr_result_encode(const struct m11_gpr_result *, char *, size_t);
#endif
