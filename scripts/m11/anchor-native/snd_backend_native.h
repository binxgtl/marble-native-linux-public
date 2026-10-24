/* P5 W3 (docs/m11-argon-speaker-run-design.md): the speaker back ends and amplifier controls through
 * PID1-private ALSA nodes. Built only in the reviewed M11_CUSTODIAN_NATIVE build; never part of a candidate
 * until the operator's review (CP2, criterion 9).
 *
 * Rules:
 *  - metadata only from the kernel: <proc_pcm> ("CC-DD: <name> ...") names each back end exactly and
 *    says playback or capture; <sys_sound>/pcmC<card>D<dev><p|c>/dev and <sys_sound>/controlC<card>/dev
 *    give MAJ:MIN;
 *  - the nodes are made by PID1 before the seal (the seal refuses mknod), in a directory this call makes
 *    (0700), as 0600 character nodes; never under /dev/snd. The control node is opened at once and both it
 *    and the directory entry go before success; a PCM node stays until m11_snd_pcm_open opens it and removes
 *    it, so no node outlives its open;
 *  - the PCM open is the stock AGM device_open (tinyalsa pcm_open, PCM_OUT/PCM_IN without MMAP): O_RDWR,
 *    HW_PARAMS (format, access RW_INTERLEAVED, channels, rate, periods fixed, period size min) and
 *    SW_PARAMS (tstamp enable, avail_min = period, the given start and stop thresholds, boundary as
 *    tinyalsa computes it). Prepare is a separate call (AGM device_prepare, after graph start). The
 *    stream is never started and no frame is ever written or read through these fds;
 *  - amplifier controls are enumerated mixer controls written by item name and read back; a read-back
 *    that differs is -EIO;
 *  - any failure leaves no node behind and holds no fd it made in that call.
 */
#ifndef M11_SND_BACKEND_NATIVE_H
#define M11_SND_BACKEND_NATIVE_H
#ifndef M11_CUSTODIAN_NATIVE
#error "snd_backend_native requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef struct {
    int (*open_fn)(const char *path, int flags);
    int (*fstat_fn)(int fd, struct stat *st);
    int (*close_fn)(int fd);
    int (*ioctl_fn)(int fd, unsigned long req, void *arg);
    int (*mknod_fn)(const char *path, mode_t mode, dev_t dev);
    int (*unlink_fn)(const char *path);
    int (*mkdir_fn)(const char *path, mode_t mode);
    int (*rmdir_fn)(const char *path);
    /* whole small text file into buf (NUL-terminated); the byte count or a negative errno */
    ssize_t (*read_text_fn)(const char *path, char *buf, size_t cap);
} m11_snd_sys;

typedef struct {
    const char *proc_pcm;   /* "/proc/asound/pcm" */
    const char *sys_sound;  /* "/sys/class/sound" */
    const char *dir;        /* "/run/m11/snd": made here, 0700 */
    unsigned card;          /* 0 */
} m11_snd_paths;

#define M11_SND_RX 0
#define M11_SND_TX 1

typedef struct {
    char name[64];
    unsigned device;
    dev_t rdev;
    char node[128];
    int node_made;
    int fd;
    unsigned rate, channels, period, periods;
    int prepared;
} m11_snd_pcm;

typedef struct {
    const m11_snd_sys *sys;
    m11_snd_paths paths;
    int dir_made;
    dev_t ctl_rdev;
    int ctl_fd;
    m11_snd_pcm pcm[2];
    unsigned ctl_writes, ctl_readbacks;
} m11_snd_backend;

/* The production paths. */
m11_snd_paths m11_snd_paths_default(void);

/* Before the seal: resolve the RX (playback) and TX (capture) back ends by exact name, make the private
 * directory and the three nodes, open the control node and remove its entry. 0, or a negative errno with
 * nothing left behind. */
int m11_snd_prepare(m11_snd_backend *, const m11_snd_sys *sys /* NULL = libc */, const m11_snd_paths *,
                    const char *rx_name, const char *tx_name);

/* Write an enumerated control (count 1 or 2, every value the same item) by item name, then read it back. */
int m11_snd_ctl_set(m11_snd_backend *, const char *control, const char *item);
/* Read an enumerated control's current item name (value 0) into out. */
int m11_snd_ctl_get(m11_snd_backend *, const char *control, char *out, size_t cap);

/* AGM device_open: open and remove the node, HW_PARAMS, SW_PARAMS. format: SNDRV_PCM_FORMAT_*. */
int m11_snd_pcm_open(m11_snd_backend *, int which, unsigned rate, unsigned channels, unsigned format,
                     unsigned period, unsigned periods, unsigned start_threshold, unsigned stop_threshold);
/* AGM device_prepare. */
int m11_snd_pcm_prepare(m11_snd_backend *, int which);
/* AGM device_stop + device_close: DROP, then close. */
int m11_snd_pcm_close(m11_snd_backend *, int which);
/* Close every fd and remove every node and the directory this backend made. */
void m11_snd_release(m11_snd_backend *);

#endif
