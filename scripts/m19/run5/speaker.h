/* M19 R5b session speaker holder: runs one bounded speaker clip inside the Ubuntu systemd session under
 * 100% of M11 Run31's safety gates (long-session SERVREG PD monitor, cmdline strict-IOMMU gate, rotating
 * /dev/kmsg intent journal, sealed endpoint/ION anchors, private heap node and sealed dma-buf pool, private
 * /dev/m11-snd ALSA nodes unlinked on open, factory Re apply+readback while amps are Disable, -10 dBFS
 * clip ceiling and volume_level <= 8, Disable-first teardown readback, zero UNMAP, and post-MAP retaining
 * fd hold until hardware reset).
 */
#ifndef M19_SPEAKER_H
#define M19_SPEAKER_H

#ifndef M11_CUSTODIAN_NATIVE
#error "m19 speaker requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif

#include "custodian_entry_native.h"
#include "snd_backend_native.h"
#include "speaker_session_native.h"
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

struct m19_speaker_config {
    const char *started_path;         /* "/run/m19/speaker.started" */
    const char *plan_path;            /* "/run/m19/speaker/plan.bin" */
    const char *plan_sha_path;        /* "/run/m19/speaker/plan.sha256" */
    const char *report_path;          /* "/run/m19/speaker.report" */
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
    uint32_t amp_window_ms;           /* production 12000 */
    unsigned write_buffers;           /* production 4 */
    uint32_t buffer_ms;               /* production 40 */
    uint64_t boot_epoch;              /* 0 = derived at entry */
    void (*session_ready_fn)(void *user, m11_entry *entry); /* NULL in production; test PTY handshake */
    void *session_ready_user;
    int return_from_hold;             /* 0 in production (never returns after m11_entry_run); 1 in tests */
};

struct m19_speaker_config m19_speaker_config_default(void);
int m19_speaker_scan_snd(const char *path);
int m19_speaker_run(const struct m19_speaker_config *cfg);

#endif
