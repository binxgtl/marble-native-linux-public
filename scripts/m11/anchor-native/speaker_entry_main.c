/* P5: the speaker candidate's PID1 binary (docs/m11-argon-speaker-run-design.md, W6). Never part of a
 * candidate until the operator's review and GO (CP2, criterion 9); CI links it and checks that it refuses to
 * act outside PID1.
 *
 * custodian_entry_main.c (P4) with four additions, in order:
 *  1. before anything else: the staged plan, /m11/speaker/plan.bin, read whole, its SHA256 equal to
 *     /m11/speaker/plan.sha256, and parsed. A bad plan holds here, before the environment phase: nothing
 *     audio was opened and the ADSP was never started;
 *  2. the journal rotates every 9 records (every TX is journaled before it is sent, and /dev/kmsg drops what
 *     goes past a burst of 10 per open file);
 *  3. P2's pre-seal hook makes the private ALSA nodes and opens the control (the owner seal refuses mknod;
 *     the spawner already exists, so it never holds an ALSA fd). A failure there is P2 step 6: nothing
 *     sealed, the retaining end;
 *  4. the session: the speaker session (speaker_session_native.h) with the runner's custodian, its MAPs
 *     through m11_crunner_map (census, MAP intent, PDR settle), the runner's PDR settle after every other
 *     custodian call and wait, its records in the same journal, and the composed census once more after it.
 * The end is the runner's: after any MAP intent it is RESET_RETAINING_ANCHORS (post-MAP hold), after the
 * evidence is sealed. */
#ifndef M11_CUSTODIAN_NATIVE
#error "speaker_entry_main requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#define _GNU_SOURCE
#include "custodian_entry_native.h"
#include "p4_env_native.h"
#include "speaker_session_native.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "p4/sha256.h"

#define PLAN_PATH "/m11/speaker/plan.bin"
#define PLAN_SHA_PATH "/m11/speaker/plan.sha256"
#define PLAN_MAX (2u << 20)

static m11_entry entry;
static m11_p4_env env;
static uint8_t plan_buf[PLAN_MAX];
static size_t plan_len;
static char plan_sha[65];
static m11_speaker_plan plan;
static m11_snd_backend snd;
static m11_speaker_report report;

static void hold(const char *why, int step, int rc) __attribute__((noreturn));
static void hold(const char *why, int step, int rc) {
    char b[160];
    int n = snprintf(b, sizeof b, "<3>M11P5 v=1 pid1 hold: %s step=%d rc=%d\n", why, step, rc);
    int fd = open("/dev/kmsg", O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0 && n > 0 && (size_t)n < sizeof b) { ssize_t w = write(fd, b, (size_t)n); (void)w; }
    for (;;) pause();
}

/* a whole regular file of at most cap bytes */
static int read_whole(const char *path, uint8_t *buf, size_t cap, size_t *len) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -errno;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 || (size_t)st.st_size > cap) { close(fd); return -EFBIG; }
    size_t n = 0;
    while (n < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + n, (size_t)st.st_size - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { close(fd); return -EIO; }
        n += (size_t)r;
    }
    close(fd);
    *len = n;
    return 0;
}

/* 1. the plan: whole, its SHA256 as staged ("<64 hex>" then a newline or sha256sum's "  name"), parsed */
static int load_plan(void) {
    char want[160];
    size_t wn = 0;
    int rc = read_whole(PLAN_PATH, plan_buf, sizeof plan_buf, &plan_len);
    if (rc) return rc;
    if ((rc = read_whole(PLAN_SHA_PATH, (uint8_t *)want, sizeof want - 1, &wn))) return rc;
    if (wn < 65 || (want[64] != '\n' && want[64] != ' ')) return -EBADMSG;
    Sha256 s;
    sha_init(&s);
    sha_update(&s, (const char *)plan_buf, plan_len);
    sha_hex(s, plan_sha);
    plan_sha[64] = 0;
    if (memcmp(plan_sha, want, 64)) return -EBADMSG;
    return m11_speaker_plan_parse(plan_buf, plan_len, &plan);
}

/* 3. before the owner seal */
static int snd_hook(void *user) {
    (void)user;
    const m11_snd_paths p = m11_snd_paths_default();
    return m11_snd_prepare(&snd, NULL, &p, plan.backend[0].name, plan.backend[1].name);
}

/* 4. the session */
static int map_cb(void *user, size_t bytes, unsigned *slot) {
    m11_entry *e = user;
    return m11_crunner_map(&e->runner, bytes, m11_entry_now_ms(), slot);
}
static void settle_cb(void *user) {
    m11_entry *e = user;
    (void)m11_pdr_loop_settle(&e->runner.loop, m11_entry_now_ms());
}
static uint64_t now_cb(void *user) { (void)user; return m11_entry_now_ms(); }
static void record_cb(void *user, const char *line) {
    m11_entry *e = user;
    char rec[224];
    int n = snprintf(rec, sizeof rec, "<6>M11SPK v=1 boot=%llu %s\n", (unsigned long long)e->boot_epoch, line);
    if (n <= 0 || (size_t)n >= sizeof rec || e->sink.append_fn(e->sink.user, rec, (size_t)n)) e->record_failures++;
    else e->records++;
}
static int session(void *user, m11_entry *e) {
    (void)user;
    char line[160];
    snprintf(line, sizeof line, "phase=spk plan sha=%.16s bytes=%zu pcm=%u level=%u", plan_sha, plan_len, plan.pcm.len,
             plan.volume_level);
    record_cb(e, line);
    const m11_speaker_io io = {.cust = &e->runner.cust, .map_fn = map_cb, .user = e, .snd = &snd, .plan = &plan,
        .record_fn = record_cb, .settle_fn = settle_cb, .now_fn = now_cb, .wait_timeout_ms = 1000,
        .eos_timeout_ms = 3000, .amp_window_ms = 12000, .region_bytes = 65536, .write_buffers = 4, .buffer_ms = 40};
    int rc = m11_speaker_session_run(&io, &report);
    const int census = m11_crunner_census(&e->runner);
    snprintf(line, sizeof line, "phase=spk session rc=%d census=%d ctl_writes=%u readbacks=%u", rc, census, snd.ctl_writes,
             snd.ctl_readbacks);
    record_cb(e, line);
    return rc;
}

int main(int argc, char **argv) {
    (void)argv;
    if (getpid() != 1 || argc != 1) return 2; /* safe CI execution: never acts outside PID1 */
    umask(077);
    int step = 0, rc;
    if ((rc = load_plan())) hold("speaker plan refused", 0, rc);
    m11_entry_config c = m11_entry_config_default();
    c.journal_rotate = 9;
    c.boot.pre_seal_fn = snd_hook;
    c.session_fn = session;
    m11_p4_env_config ec = m11_p4_env_config_default(&c.boot);
    if ((rc = m11_p4_env_run(&env, &ec, &step))) hold("environment phase failed", step, rc);
    c.helper_pids[0] = env.locator;
    c.helper_pids[1] = env.relay;
    (void)m11_entry_run(&entry, &c);
    hold("entry returned", 0, 0); /* only reached if an end returned: PID1 holds everything it has */
}
