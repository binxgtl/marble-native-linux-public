/* Production P3 PID1 entry — see custodian_entry_native.h. */
#define _GNU_SOURCE
#include "custodian_entry_native.h"
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int entry_started_once;

/* Post-seal jobs run in the spawner (P2); the job layout is the Run23 runner's control job. The
 * candidate that provides /m11/control is a later step; the entry runs no job itself. */
static const char *const control_job[] = {"/bin/busybox", "sh", "/m11/control", NULL};
static const char *const checkpoint_job[] = {"/sbin/m11-checkpoint", NULL};
static const char *const *const spawner_jobs[] = {control_job, checkpoint_job};
/* B5/P4: Run23's teardown after its final closes, in its order, with its deadlines and markers. */
static const m11_entry_job run23_teardown[] = {
    {.kind = M11_TD_JOB, .arg = "seal", .deadline_ms = 10000, .index = 0},
    {.kind = M11_TD_REAP, .deadline_ms = 5000, .slot = 1},                       /* the kmsg relay */
    {.kind = M11_TD_CHECK, .arg = "/run/m11-instrumentation/logger.done"},      /* evidence on the host */
    {.kind = M11_TD_JOB, .arg = "usb_stop", .deadline_ms = 10000, .index = 0},
    {.kind = M11_TD_JOB, .arg = "stop_adsp", .deadline_ms = 40000, .index = 0},
    {.kind = M11_TD_CREATE, .arg = "/run/m11/pd.stop"},
    {.kind = M11_TD_REAP, .deadline_ms = 5000, .slot = 0},                       /* the PD locator */
    {.kind = M11_TD_CHECK, .arg = "/run/m11/pd.done"},
    {.kind = M11_TD_JOB, .arg = "common", .deadline_ms = 10000, .index = 0},
    {.kind = M11_TD_JOB, .arg = "green", .deadline_ms = 10000, .index = 1},     /* the result checkpoint */
    {.kind = M11_TD_JOB, .arg = "unmount", .deadline_ms = 10000, .index = 0}};
static void hold_forever(void *user) { (void)user; for (;;) pause(); }

m11_entry_config m11_entry_config_default(void) {
    m11_entry_config c = {
        .boot = m11_boot_config_default(), .qrtr = NULL, .pd_ready_budget_ms = 10000,
        .cmdline_path = "/proc/cmdline", .journal_path = "/dev/kmsg", .journal_require_kmsg = 1,
        .require_pid1 = 1, .pool_count = 2, .pool_len = 65536, .pool_base = 200, .sys = NULL,
        .timeout_ms = 1000, .recovery_budget_ms = 5000, .hold_idle_ms = 1000, .src_port = 0x0100u,
        .boot_epoch = 0, .terminal_ops = m11_terminal_ops_default(), .proc_root = NULL,
        .session_fn = NULL, .session_user = NULL};
    c.boot.spawner_commands = spawner_jobs;
    c.boot.spawner_count = 2;
    c.terminal_ops.hold_fn = hold_forever;
    c.teardown_jobs = run23_teardown;
    c.teardown_count = sizeof run23_teardown / sizeof run23_teardown[0];
    c.pd_retire_budget_ms = 2000;
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

/* B6: one compact record per phase, one write each, never blocking (a sink failure is counted). */
static void phase_record(m11_entry *e, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void phase_record(m11_entry *e, const char *fmt, ...) {
    if (e->journal_fd < 0) return;
    char body[160];
    va_list ap; va_start(ap, fmt);
    int k = vsnprintf(body, sizeof body, fmt, ap);
    va_end(ap);
    if (k < 0 || (size_t)k >= sizeof body) { e->record_failures++; return; }
    int n = snprintf(e->record, sizeof e->record, "<6>M11ENTRY v=1 boot=%llu %s\n", (unsigned long long)e->boot_epoch, body);
    if (n <= 0 || (size_t)n >= sizeof e->record || e->sink.append_fn(e->sink.user, e->record, (size_t)n)) e->record_failures++;
    else e->records++;
}

/* The gate-relevant tokens, for the record only (the verdict comes from the kernel-faithful gate):
 * the last whitespace-separated "key=" token's value, sanitized, or "absent". The cmdline itself is
 * never journaled (it carries the device serial). */
static void token_value(const char *cmdline, const char *key, char *out, size_t cap) {
    snprintf(out, cap, "absent");
    size_t kl = strlen(key);
    for (const char *p = cmdline; *p;) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        const char *s = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        if ((size_t)(p - s) >= kl && !strncmp(s, key, kl)) {
            size_t n = 0;
            for (const char *v = s + kl; v < p && n + 1 < cap; v++, n++) {
                char c = *v;
                out[n] = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == '_' ? c : '?';
            }
            out[n] = 0;
            if (!n) snprintf(out, cap, "empty");
        }
    }
}
static uint32_t crc32_text(const char *s) {
    uint32_t c = 0xffffffffu;
    for (; *s; s++) {
        c ^= (unsigned char)*s;
        for (int i = 0; i < 8; i++) c = c & 1u ? (c >> 1) ^ 0xedb88320u : c >> 1;
    }
    return ~c;
}

int m11_entry_cmdline_summary(const char *cmdline, char *out, size_t cap) {
    const int allowed = m11_custodian_cmdline_allowed(cmdline);
    char strict[16], passthrough[16];
    token_value(cmdline, "iommu.strict=", strict, sizeof strict);
    token_value(cmdline, "iommu.passthrough=", passthrough, sizeof passthrough);
    snprintf(out, cap, "allowed=%d len=%zu strict=%s passthrough=%s crc32=%08x", allowed, strlen(cmdline), strict,
             passthrough, (unsigned)crc32_text(cmdline));
    return allowed;
}

/* Nothing audio was ever opened: no bind was attempted on either anchor (an attempt may have
 * retained an fd it obtained) and no heap fd is held. Only then may a failed boot reboot. */
static int nothing_opened(const m11_entry *e) {
    return !e->boot.endpoint.bind_attempted && !e->boot.ion.bind_attempted && e->boot.heap.fd < 0;
}

/* A boot that never reached the runner. Nothing is closed. B4: when nothing audio was ever opened
 * the end is reboot(2), as Run23 rebooted a boot whose PD never came UP; once a bind was attempted
 * the only end is the retaining one (PID1 exit). A reboot_fn that returns falls through to it. */
static int entry_fail(m11_entry *e, const char *phase, int step, int rc) {
    e->fail_step = step; e->fail_rc = rc;
    const int reboot = nothing_opened(e);
    int n = snprintf(e->record, sizeof e->record,
                     "<6>M11TERMINAL v=2 boot=%llu action=START_FAILED end=%s phase=%s step=%d rc=%d "
                     "anchors_held=%u/2 boot_stage=%d note=entry_failed\n",
                     (unsigned long long)e->boot_epoch, reboot ? "reboot" : "pid1_exit", phase, step, rc,
                     anchors_held(e), e->boot.stage);
    if (e->journal_fd >= 0 && n > 0 && (size_t)n < sizeof e->record) {
        if (e->sink.append_fn(e->sink.user, e->record, (size_t)n)) e->record_failures++;
        else e->records++;
    }
    if (reboot) {
        e->reboot_rc = e->cfg.terminal_ops.reboot_fn(e->cfg.terminal_ops.user);
        phase_record(e, "phase=reboot_failed rc=%d", e->reboot_rc);
    }
    e->cfg.terminal_ops.exit_fn(e->cfg.terminal_ops.user);
    return -EFAULT;
}

/* The runner's terminal ops: the caller's exit/reboot/hold under the caller's user, plus the
 * entry's own B5 teardown. */
static void ops_exit(void *u) { m11_entry *e = u; e->cfg.terminal_ops.exit_fn(e->cfg.terminal_ops.user); }
static int ops_reboot(void *u) { m11_entry *e = u; return e->cfg.terminal_ops.reboot_fn(e->cfg.terminal_ops.user); }
static void ops_hold(void *u) { m11_entry *e = u; e->cfg.terminal_ops.hold_fn(e->cfg.terminal_ops.user); }

static uint64_t mono_ms(void) { return m11_entry_now_ms(); }
/* One typed teardown step; 0 or a negative errno. Never kills anything. */
static int teardown_step(m11_entry *e, const m11_entry_job *j) {
    char b[8]; struct stat st;
    switch (j->kind) {
    case M11_TD_JOB: {
        int status = 0;
        int rc = m11_spawner_run_flags(&e->boot.spawner, j->index, j->arg, j->deadline_ms, M11_SPAWN_NO_KILL, &status);
        return rc ? rc : status ? -ECHILD : 0; /* a stuck job is never killed */
    }
    case M11_TD_CHECK: /* evidence or a helper's completion marker */
        if (lstat(j->arg, &st) || !S_ISREG(st.st_mode) || read_text(j->arg, b, sizeof b) || strcmp(b, "1\n")) return -ENODATA;
        return 0;
    case M11_TD_CREATE: {
        int fd = open(j->arg, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) return -errno;
        ssize_t n = write(fd, "1\n", 2);
        int cr = close(fd);
        return n == 2 && !cr ? 0 : -EIO;
    }
    case M11_TD_REAP: {
        pid_t pid = j->slot < M11_ENTRY_HELPERS ? e->cfg.helper_pids[j->slot] : 0;
        if (pid <= 1) return -ESRCH;
        uint64_t until = mono_ms() + j->deadline_ms;
        for (;;) {
            int status;
            pid_t got = waitpid(pid, &status, WNOHANG);
            if (got == pid) return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -ECHILD;
            if (got < 0 && errno != EINTR) return -errno;
            if (mono_ms() >= until) return -ETIMEDOUT; /* left running: the boot holds */
            struct timespec t = {0, 10 * 1000000L};
            (void)nanosleep(&t, NULL);
        }
    }
    default:
        return -EINVAL;
    }
}

/* B5: called by the G8 orderly end only, after both final closes and its record. */
static int entry_teardown(void *u) {
    m11_entry *e = u;
    const m11_entry_config *c = &e->cfg;
    e->teardown_step = 0;
    /* the gate, again here: never mapped, no MAP intent, census clean, both anchors final-closed */
    if (e->runner.map_intents || e->runner.census_failed || e->runner.boot.dsp_map_attempted ||
        e->boot.endpoint.state != M11_ANCHOR_OWNER_FDS_DROPPED || e->boot.ion.state != M11_ANCHOR_OWNER_FDS_DROPPED) {
        phase_record(e, "phase=teardown refused=1 intents=%u census_failed=%d", e->runner.map_intents, e->runner.census_failed);
        return e->teardown_rc = -EPERM;
    }
    /* the PD listener withdrawn while the ADSP still runs (Run23 retired before the transport teardown) */
    int rc = m11_pdmon_retire(&e->pdmon, c->pd_retire_budget_ms);
    phase_record(e, "phase=teardown pd_retire=%d steps=%u", rc, c->teardown_count); /* the last record */
    if (rc) return e->teardown_rc = rc;
    for (unsigned i = 0; i < c->teardown_count; i++) {
        const m11_entry_job *j = &c->teardown_jobs[i];
        e->teardown_step = (int)i + 1;
        if ((rc = teardown_step(e, j))) return e->teardown_rc = rc; /* nothing after a failed step */
    }
    e->teardown_step = (int)c->teardown_count + 1;
    if ((rc = m11_spawner_stop(&e->boot.spawner))) return e->teardown_rc = rc;
    return e->teardown_rc = 0;
}

int m11_entry_run(m11_entry *e, const m11_entry_config *cfg) {
    if (!e || !cfg || !cfg->cmdline_path || !cfg->journal_path || !cfg->pd_ready_budget_ms ||
        cfg->pd_ready_budget_ms > 10000u || !cfg->hold_idle_ms || !cfg->terminal_ops.exit_fn ||
        !cfg->terminal_ops.reboot_fn ||
        (cfg->teardown_count && (!cfg->teardown_jobs || !cfg->terminal_ops.hold_fn || !cfg->pd_retire_budget_ms ||
                                 cfg->pd_retire_budget_ms > M11_PDS_TXN_TIMEOUT_MS))) return -EINVAL;
    for (unsigned i = 0; i < cfg->teardown_count; i++) { /* every step well formed before anything starts */
        const m11_entry_job *j = &cfg->teardown_jobs[i];
        if (j->kind == M11_TD_JOB ? !j->arg || j->index >= cfg->boot.spawner_count :
            j->kind == M11_TD_REAP ? j->slot >= M11_ENTRY_HELPERS || !j->deadline_ms :
            (j->kind == M11_TD_CHECK || j->kind == M11_TD_CREATE) ? !j->arg : 1) return -EINVAL;
    }
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
    phase_record(e, "phase=journal pid=%ld kmsg=%d", (long)getpid(), S_ISCHR(st.st_mode) && st.st_rdev == makedev(1, 11));

    /* 3. the effective cmdline, before anything else is opened */
    if ((rc = read_text(cfg->cmdline_path, e->cmdline, sizeof e->cmdline))) return entry_fail(e, "cmdline", 3, rc);
    char summary[112];
    const int allowed = m11_entry_cmdline_summary(e->cmdline, summary, sizeof summary);
    phase_record(e, "phase=cmdline %s", summary);
    if (!allowed) return entry_fail(e, "cmdline", 3, -EPERM);
    e->phase = M11_ENTRY_CMDLINE;

    /* 4. the P1 monitor: READY within the bring-up budget */
    const uint64_t pd_start = m11_entry_now_ms();
    if ((rc = m11_pdmon_open(&e->pdmon, cfg->qrtr, pd_start, cfg->pd_ready_budget_ms)) == 0)
        rc = m11_pdmon_wait_up(&e->pdmon, cfg->pd_ready_budget_ms);
    phase_record(e, "phase=pd_up rc=%d pds=%d fault=%d datagrams=%u ms=%llu", rc, (int)e->pdmon.pds.phase,
                 (int)e->pdmon.pds.fault, e->pdmon.datagrams, (unsigned long long)(m11_entry_now_ms() - pd_start));
    if (rc) return entry_fail(e, "pd_up", 4, rc);
    e->phase = M11_ENTRY_PD_UP;

    /* 5. the P2 boot with the same monitor */
    int step = 0;
    rc = m11_boot_run(&e->boot, &cfg->boot, &e->pdmon.monitor, m11_entry_now_ms(), &step);
    phase_record(e, "phase=boot rc=%d step=%d stage=%d ep=%u:%u ion=%u:%u heap=%u:%u", rc, step, e->boot.stage,
                 major(e->boot.endpoint_rdev), minor(e->boot.endpoint_rdev), major(e->boot.ion_rdev),
                 minor(e->boot.ion_rdev), major(e->boot.heap.rdev), minor(e->boot.heap.rdev));
    if (rc) return entry_fail(e, "boot", step, rc);
    e->phase = M11_ENTRY_BOOT;

    /* 6. the runner; its own START_FAILED end covers a failed start */
    m11_crunner_config rc_cfg = {.endpoint = &e->boot.endpoint, .ion = &e->boot.ion, .heap_fd = e->boot.heap.fd,
        .heap_rdev = e->boot.heap.rdev, .pool_count = cfg->pool_count, .pool_len = cfg->pool_len,
        .pool_base = cfg->pool_base, .sys = cfg->sys, .pd = &e->pdmon.monitor, .journal = &e->sink,
        .terminal_ops = {.exit_fn = ops_exit, .reboot_fn = ops_reboot, .user = e, .panic_path = cfg->terminal_ops.panic_path,
                         .teardown_fn = cfg->teardown_count ? entry_teardown : NULL,
                         .hold_fn = cfg->terminal_ops.hold_fn ? ops_hold : NULL},
        .cmdline = e->cmdline, .boot_epoch = e->boot_epoch,
        .timeout_ms = cfg->timeout_ms, .recovery_budget_ms = cfg->recovery_budget_ms, .src_port = cfg->src_port,
        .proc_root = cfg->proc_root, .map_intent_fn = map_intent, .map_intent_user = e};
    if ((rc = m11_crunner_start(&e->runner, &rc_cfg, m11_entry_now_ms(), &step))) {
        e->fail_step = step; e->fail_rc = rc;
        if (e->runner.cfg.terminal_ops.exit_fn) return m11_crunner_end(&e->runner, m11_entry_now_ms());
        return entry_fail(e, "runner", step, rc); /* refused before it took the configuration */
    }
    e->phase = M11_ENTRY_RUNNER;
    phase_record(e, "phase=runner stage=%d why=%u pool=%u", e->runner.stage, e->runner.census_why, e->runner.pool.count);

    /* 7. the session (none in production) */
    if (cfg->session_fn) e->session_rc = cfg->session_fn(cfg->session_user, e);
    e->phase = M11_ENTRY_SESSION;
    phase_record(e, "phase=session present=%d rc=%d intents=%u", cfg->session_fn != NULL, e->session_rc, e->runner.map_intents);

    /* 8. close, then the G8 end; a HOLD waits on the monitor and asks again */
    (void)m11_crunner_close(&e->runner);
    e->phase = M11_ENTRY_END;
    for (;;) {
        rc = m11_crunner_end(&e->runner, m11_entry_now_ms());
        if (rc != -EBUSY) return rc;
        if (!e->hold_rounds++) phase_record(e, "phase=hold action=%s", m11_terminal_action_name(e->runner.term.action)); /* once */
        int irc = m11_crunner_idle(&e->runner, cfg->hold_idle_ms, m11_entry_now_ms());
        if (irc && irc != -ENETRESET && irc != -EOWNERDEAD) { /* a poll error: never spin */
            struct timespec t = {(time_t)(cfg->hold_idle_ms / 1000u), (long)(cfg->hold_idle_ms % 1000u) * 1000000L};
            while (nanosleep(&t, &t) && errno == EINTR) {}
        }
    }
}
