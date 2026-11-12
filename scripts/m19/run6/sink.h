/* M19 R6 marble-sink: the desktop sound server's speaker end (docs/m19-r6.md). R5b's session speaker holder
 * (100% of M11 Run31's gates: SERVREG PD monitor, strict-IOMMU gate, /dev/kmsg intent journal, sealed endpoint/ION
 * anchors, private heap node and sealed dma-buf pool, private /dev/m11-snd nodes unlinked on open, factory Re applied
 * and read back with the amplifier off, the plan's -10 dBFS chord at volume level <= 8, Disable-first teardown, zero
 * UNMAP, a retaining hold until reset), with stream.h's stream after the chord: PulseAudio's pipe sink feeds it
 * through a FIFO, never louder than the chord, the amplifier off after 3 s of silence.
 */
#ifndef M19_SINK_H
#define M19_SINK_H

#ifndef M11_CUSTODIAN_NATIVE
#error "m19 sink requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif

#include "custodian_entry_native.h"
#include "snd_backend_native.h"
#include "speaker_session_native.h"
#include "stream.h"
#include <stddef.h>
#include <stdint.h>

#define M19_SPK_PLAN_MAX (2u << 20)
#define M19_SPK_MAX_DURATION_MS 5000u
#define M19_SPK_MAX_PEAK_MDBFS (-10000)
#define M19_SPK_MAX_VOLUME_LEVEL 8u

/* Pre-entry failure steps (when entry_phase == 0 in speaker.report). */
enum {
    M19_SPK_PRE_NONE = 0,
    M19_SPK_PRE_ARGS = 1,
    M19_SPK_PRE_PID = 2,
    M19_SPK_PRE_LOCK = 3,
    M19_SPK_PRE_DEV = 4,
    M19_SPK_PRE_HOLDERS = 5,
    M19_SPK_PRE_PLAN = 6,
};

struct m19_sink_config {
    const char *started_path;         /* "/run/m19/sink.started" */
    const char *plan_path;            /* "/run/m19/sink/plan.bin" */
    const char *plan_sha_path;        /* "/run/m19/sink/plan.sha256" */
    const char *report_path;          /* "/run/m19/sink.report" */
    const char *status_path;          /* "/run/m19/sink.status": the stream's counters, every status_ms */
    const char *fifo_path;            /* "/run/m19/sink/fifo": PulseAudio's module-pipe-sink writes, s16le 48 kHz stereo */
    const char *stop_path;            /* "/run/m19/guard-tripped": the session guard's marker ends the stream */
    const char *dev_root;             /* "/dev" */
    const char *proc_root;            /* "/proc" (runner tree census) */
    const char *holder_proc_root;     /* "/proc" (system-wide pre-open audio holder scan) */
    const char *sys_root;             /* "/sys" */
    const char *proc_devices;         /* "/proc/devices" */
    const char *cmdline_path;         /* "/proc/cmdline" */
    const char *journal_path;         /* "/dev/kmsg" */
    const char *panic_path;           /* "/proc/sys/kernel/panic" */
    const char *endpoint_node;        /* "/dev/aud_pasthru_adsp" */
    const char *ion_node;             /* "/dev/msm_audio_ion" */
    const char *ion_cma_node;         /* "/dev/msm_audio_ion_cma" */
    const char *heap_dir;             /* "/dev/m11-heap" */
    const char *heap_node;            /* "/dev/m11-heap/system" */
    const char *spawner_bin;          /* "/bin/true" */
    m11_snd_paths snd_paths;          /* "/proc/asound/pcm", "/sys/class/sound", "/dev/m11-snd", card 0 */
    const m11_qrtr_sys *qrtr;         /* NULL = libc AF_QIPCRTR */
    const m11_shmem_native_sys *shmem_sys; /* NULL = libc */
    const m11_snd_sys *snd_sys;       /* NULL = libc */
    int require_root;                 /* production 1 */
    int spawner_require_drop;         /* production 1 */
    int journal_require_kmsg;         /* production 1 (char 1:11) */
    int cdev_require_minor0;          /* production 1 */
    int heap_require_kernel_fs;       /* production 1 */
    unsigned journal_rotate;          /* production 9 */
    unsigned pool_count;              /* production 2 */
    size_t pool_len;                  /* production 65536 */
    int pool_base;                    /* production 200 */
    uint32_t pd_ready_budget_ms;      /* production 10000 */
    uint32_t timeout_ms;              /* production 1000 */
    uint32_t recovery_budget_ms;      /* production 5000 */
    uint32_t hold_idle_ms;            /* production 1000 */
    uint32_t wait_timeout_ms;         /* production 1000 */
    uint32_t amp_window_ms;           /* production 12000: the chord's amplifier window, as Run31 */
    uint32_t idle_off_ms;             /* production 3000: silence before both switches go Disable */
    uint32_t status_ms;               /* production 1000 */
    int pipe_bytes;                   /* production 16384: the FIFO's capacity, about 85 ms */
    unsigned write_buffers;           /* production 4 */
    uint32_t buffer_ms;               /* production 40 */
    uint64_t boot_epoch;              /* 0 = derived at entry */
    void (*session_ready_fn)(void *user, m11_entry *entry); /* NULL in production; test PTY handshake */
    void *session_ready_user;
    int return_from_hold;             /* 0 in production (never returns after m11_entry_run); 1 in tests */
};

struct m19_sink_config m19_sink_config_default(void);
int m19_sink_scan_snd(const char *path);
/* The chord, checked at the switch to the stream: everything R5b's verdict checked that is known then. */
int m19_sink_qualify_chord(const m11_speaker_plan *plan, const m11_speaker_report *r, int census_rc, unsigned census_why,
                           int resources_busy, int unmap_attempted, const m19_stream_status *st);
int m19_sink_qualify_session(int phase, int fail_step, int rc, int session_ran, int session_rc,
                                const m11_speaker_plan *plan, const m11_speaker_report *r,
                                int census_rc, unsigned census_why, int resources_busy,
                                int terminal_action, unsigned anchors_held, unsigned anchor_fds_open,
                                int pool_held, unsigned regions_in_pool, int unmap_attempted);
void m19_sink_terminate(void); /* SIGTERM: ends the stream like the guard */
int m19_sink_run(const struct m19_sink_config *cfg);

#endif
