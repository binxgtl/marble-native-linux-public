/* Production P3 PID1 entry — see custodian_entry_native.h. */
#define _GNU_SOURCE
#include "custodian_entry_native.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

static int entry_started_once;

/* Post-seal jobs run in the spawner (P2); the job layout is the Run23 runner's control job. The
 * candidate that provides /m11/control is a later step; the entry runs no job itself. */
static const char *const control_job[] = {"/bin/busybox", "sh", "/m11/control", NULL};
static const char *const *const spawner_jobs[] = {control_job};

m11_entry_config m11_entry_config_default(void) {
    m11_entry_config c = {
        .boot = m11_boot_config_default(), .qrtr = NULL, .pd_ready_budget_ms = 10000,
        .cmdline_path = "/proc/cmdline", .journal_path = "/dev/kmsg", .journal_require_kmsg = 1,
        .require_pid1 = 1, .pool_count = 2, .pool_len = 65536, .pool_base = 200, .sys = NULL,
        .timeout_ms = 1000, .recovery_budget_ms = 5000, .hold_idle_ms = 1000, .src_port = 0x0100u,
        .boot_epoch = 0, .terminal_ops = m11_terminal_ops_default(), .proc_root = NULL,
        .session_fn = NULL, .session_user = NULL};
    c.boot.spawner_commands = spawner_jobs;
    c.boot.spawner_count = 1;
    return c;
}

uint64_t m11_entry_now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

static int read_text(const char *path, char *b, size_t cap) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    size_t n = 0;
    for (;;) {
        if (n + 1 >= cap) { close(fd); return -EFBIG; }
        ssize_t r = read(fd, b + n, cap - 1 - n);
        if (r < 0) { if (errno == EINTR) continue; int e = -errno; close(fd); return e; }
        if (r == 0) break;
        n += (size_t)r;
    }
    close(fd);
    b[n] = 0;
    return 0;
}

static uint64_t derive_epoch(void) {
    uint64_t v = 0;
    if (getrandom(&v, sizeof v, GRND_NONBLOCK) == (ssize_t)sizeof v && v) return v;
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME, &t)) return 1;
    v = (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
    return v ? v : 1;
}

/* The MAP intent: the P1 session stops acknowledging a PD DOWN. Never released in this boot. */
static void map_intent(void *user) {
    m11_entry *e = user;
    m11_pds_resources_busy(&e->pdmon.pds);
}

static unsigned anchors_held(const m11_entry *e) {
    return (unsigned)(e->boot.endpoint.state == M11_ANCHOR_HELD) + (unsigned)(e->boot.ion.state == M11_ANCHOR_HELD);
}

/* A boot that never reached the runner: nothing is closed (a bound anchor stays held), the record
 * names the phase, PID1 ends through exit_fn. */
static int entry_fail(m11_entry *e, const char *phase, int step, int rc) {
    e->fail_step = step; e->fail_rc = rc;
    int n = snprintf(e->record, sizeof e->record,
                     "<6>M11TERMINAL v=2 boot=%llu action=START_FAILED end=pid1_exit phase=%s step=%d rc=%d "
                     "anchors_held=%u/2 boot_stage=%d note=entry_failed\n",
                     (unsigned long long)e->boot_epoch, phase, step, rc, anchors_held(e), e->boot.stage);
    if (e->journal_fd >= 0 && n > 0 && (size_t)n < sizeof e->record) (void)e->sink.append_fn(e->sink.user, e->record, (size_t)n);
    e->cfg.terminal_ops.exit_fn(e->cfg.terminal_ops.user);
    return -EFAULT;
}

int m11_entry_run(m11_entry *e, const m11_entry_config *cfg) {
    if (!e || !cfg || !cfg->cmdline_path || !cfg->journal_path || !cfg->pd_ready_budget_ms ||
        cfg->pd_ready_budget_ms > 10000u || !cfg->hold_idle_ms || !cfg->terminal_ops.exit_fn ||
        !cfg->terminal_ops.reboot_fn) return -EINVAL;
    if (cfg->require_pid1 && getpid() != 1) return -EPERM;
    if (entry_started_once) return -EALREADY; /* never wipe an entry that may hold the boot */
    entry_started_once = 1;
    memset(e, 0, sizeof *e);
    e->cfg = *cfg;
    e->journal_fd = -1;
    e->pdmon.fd = -1;
    e->boot.heap.fd = -1;
    e->boot_epoch = cfg->boot_epoch ? cfg->boot_epoch : derive_epoch();

    /* 2. the journal sink, before the spawner exists */
    int fd = open(cfg->journal_path, O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return entry_fail(e, "journal", 2, -errno);
    e->journal_fd = fd;
    struct stat st;
    if (fstat(fd, &st)) return entry_fail(e, "journal", 2, -errno);
    if (cfg->journal_require_kmsg && (!S_ISCHR(st.st_mode) || st.st_rdev != makedev(1, 11))) {
        e->journal_fd = -1; /* not the kernel log: nothing is written to it */
        return entry_fail(e, "journal", 2, -ENODEV);
    }
    int rc = m11_intent_sink_fd(&e->jfd, fd, &e->sink);
    if (rc) { e->journal_fd = -1; return entry_fail(e, "journal", 2, rc); }
    e->phase = M11_ENTRY_JOURNAL;

    /* 3. the effective cmdline, before anything else is opened */
    if ((rc = read_text(cfg->cmdline_path, e->cmdline, sizeof e->cmdline))) return entry_fail(e, "cmdline", 3, rc);
    if (!m11_custodian_cmdline_allowed(e->cmdline)) return entry_fail(e, "cmdline", 3, -EPERM);
    e->phase = M11_ENTRY_CMDLINE;

    /* 4. the P1 monitor: READY within the bring-up budget */
    if ((rc = m11_pdmon_open(&e->pdmon, cfg->qrtr, m11_entry_now_ms(), cfg->pd_ready_budget_ms)))
        return entry_fail(e, "pd_up", 4, rc);
    if ((rc = m11_pdmon_wait_up(&e->pdmon, cfg->pd_ready_budget_ms))) return entry_fail(e, "pd_up", 4, rc);
    e->phase = M11_ENTRY_PD_UP;

    /* 5. the P2 boot with the same monitor */
    int step = 0;
    if ((rc = m11_boot_run(&e->boot, &cfg->boot, &e->pdmon.monitor, m11_entry_now_ms(), &step)))
        return entry_fail(e, "boot", step, rc);
    e->phase = M11_ENTRY_BOOT;

    /* 6. the runner; its own START_FAILED end covers a failed start */
    m11_crunner_config rc_cfg = {.endpoint = &e->boot.endpoint, .ion = &e->boot.ion, .heap_fd = e->boot.heap.fd,
        .heap_rdev = e->boot.heap.rdev, .pool_count = cfg->pool_count, .pool_len = cfg->pool_len,
        .pool_base = cfg->pool_base, .sys = cfg->sys, .pd = &e->pdmon.monitor, .journal = &e->sink,
        .terminal_ops = cfg->terminal_ops, .cmdline = e->cmdline, .boot_epoch = e->boot_epoch,
        .timeout_ms = cfg->timeout_ms, .recovery_budget_ms = cfg->recovery_budget_ms, .src_port = cfg->src_port,
        .proc_root = cfg->proc_root, .map_intent_fn = map_intent, .map_intent_user = e};
    if ((rc = m11_crunner_start(&e->runner, &rc_cfg, m11_entry_now_ms(), &step))) {
        e->fail_step = step; e->fail_rc = rc;
        if (e->runner.cfg.terminal_ops.exit_fn) return m11_crunner_end(&e->runner, m11_entry_now_ms());
        return entry_fail(e, "runner", step, rc); /* refused before it took the configuration */
    }
    e->phase = M11_ENTRY_RUNNER;

    /* 7. the session (none in production) */
    if (cfg->session_fn) e->session_rc = cfg->session_fn(cfg->session_user, e);
    e->phase = M11_ENTRY_SESSION;

    /* 8. close, then the G8 end; a HOLD waits on the monitor and asks again */
    (void)m11_crunner_close(&e->runner);
    e->phase = M11_ENTRY_END;
    for (;;) {
        rc = m11_crunner_end(&e->runner, m11_entry_now_ms());
        if (rc != -EBUSY) return rc;
        e->hold_rounds++;
        int irc = m11_crunner_idle(&e->runner, cfg->hold_idle_ms, m11_entry_now_ms());
        if (irc && irc != -ENETRESET && irc != -EOWNERDEAD) { /* a poll error: never spin */
            struct timespec t = {(time_t)(cfg->hold_idle_ms / 1000u), (long)(cfg->hold_idle_ms % 1000u) * 1000000L};
            while (nanosleep(&t, &t) && errno == EINTR) {}
        }
    }
}
