/* P4 item 1 stand-in test: the environment phase over a scratch directory (the working directory of
 * each case), shell stand-ins for /m11/prepare and /m11/control (the control "start" publishes the
 * fake sysfs metadata, as the ADSP start makes the endpoint class appear), a compiled ELF stand-in
 * for both helpers (argv[2]) and a regular file for the kmsg records. As root (sudo): the helpers
 * drop to uid 65534 with no capabilities. Each case runs in a child (the phase is one-shot). */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-p4-env-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "p4_env_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

static char base[256], dir[320], helper_bin[512];
static int report_fd = -1;
static m11_boot_config BOOT;
static m11_p4_env_config C;
static m11_p4_env E;

static void put(const char *rel, const char *text, mode_t mode) {
    char path[700], d[700];
    snprintf(path, sizeof path, "%s/%s", dir, rel);
    snprintf(d, sizeof d, "%s", path);
    for (char *s = d + strlen(dir) + 1; (s = strchr(s, '/')); s++) { *s = 0; (void)mkdir(d, 0755); *s = '/'; }
    FILE *f = fopen(path, "w"); assert(f && fputs(text, f) >= 0 && fclose(f) == 0);
    assert(chmod(path, mode) == 0);
}
static const char *PROC = "Character devices:\n  1 msm_audio_ion\n  1 msm_audio_ion_cma\n  5 aud_pasthru_adsp\n\n";
/* control: logs its argument; "start" publishes the endpoint and ION metadata unless no-endpoint
 * exists; amp_gate writes the gate result (enabled when amp-bad exists); fails where fail-<arg>
 * exists; "start" sleeps when slow-start exists */
static const char *CONTROL =
    "echo \"$1\" >> env-jobs\n"
    "case \"$1\" in\n"
    "start) [ -e slow-start ] && sleep 2\n"
    "  if [ ! -e no-endpoint ]; then mkdir -p sys/class/aud_pasthru_adsp/aud_pasthru_adsp sys/dev/char/5:2 \\\n"
    "    sys/class/msm_audio_ion/msm_audio_ion sys/dev/char/1:3 sys/class/msm_audio_ion_cma/msm_audio_ion_cma sys/dev/char/1:5\n"
    "  printf '5:2\\n' > sys/class/aud_pasthru_adsp/aud_pasthru_adsp/dev; printf 'DEVNAME=aud_pasthru_adsp\\n' > sys/dev/char/5:2/uevent\n"
    "  printf '1:3\\n' > sys/class/msm_audio_ion/msm_audio_ion/dev; printf 'DEVNAME=msm_audio_ion\\n' > sys/dev/char/1:3/uevent\n"
    "  printf '1:5\\n' > sys/class/msm_audio_ion_cma/msm_audio_ion_cma/dev; printf 'DEVNAME=msm_audio_ion_cma\\n' > sys/dev/char/1:5/uevent\n"
    "  fi;;\n"
    "amp_gate) if [ -e amp-bad ]; then printf 'switches-enabled\\n' > amp-gate.result; else printf 'switches-disabled\\n' > amp-gate.result; fi;;\n"
    "esac\n"
    "[ ! -e \"fail-$1\" ]\n";
static const char *PREPARE = "echo prepare >> env-jobs\n[ ! -e fail-prepare ]\n";

static void world(void) {
    static unsigned seq;
    snprintf(dir, sizeof dir, "%s/c%ld-%u", base, (long)getpid(), seq++);
    assert(mkdir(dir, 0777) == 0 && chmod(dir, 0777) == 0 && chdir(dir) == 0); /* helpers may run as 65534 */
    put("prepare", PREPARE, 0755); put("control", CONTROL, 0755); put("proc_devices", PROC, 0644); put("kmsg", "", 0644);
    put("not-elf", "#!/bin/sh\nexit 0\n", 0755);
    BOOT = (m11_boot_config){.sys = "sys", .proc_devices = "proc_devices",
        .endpoint = {"aud_pasthru_adsp", "aud_pasthru_adsp", "ep_node", 1}, .ion = {"msm_audio_ion", "msm_audio_ion", "ion_node", 0},
        .ion_cma = {"msm_audio_ion_cma", "msm_audio_ion_cma", "cma_node", 0}};
    BOOT.endpoint.require_minor0 = 0;
    C = m11_p4_env_config_default(&BOOT);
    C.shell = "/bin/sh"; C.shell_argv0 = "sh"; C.shell_arg = NULL;
    C.prepare = "prepare"; C.control = "control"; C.helper_log = "helpers.log"; C.helper_log_tmpfs = 0;
    C.locator = helper_bin; C.relay = helper_bin; C.helper_images_root = 0; C.drop_helpers = 0;
    C.locator_ready = "pd.endpoint"; C.relay_ready = "logger.ready"; C.amp_result = "amp-gate.result"; C.kmsg = "kmsg";
    C.prepare_ms = 5000; C.journal_ms = 5000; C.marker_ms = 2000; C.probe_ms = 5000; C.start_ms = 5000; C.usb_ms = 5000;
    C.amp_ms = 5000; C.endpoint_ms = 300; C.ion_ms = 300;
}
static void text(const char *path, char *b, size_t cap) {
    snprintf(b, cap, "-");
    int fd = open(path, O_RDONLY); if (fd < 0) return;
    ssize_t n = read(fd, b, cap - 1); close(fd);
    if (n <= 0) { snprintf(b, cap, "-"); return; }
    b[n] = 0;
    for (char *p = b; *p; p++) if (*p == '\n') *p = p[1] ? ',' : 0;
}
static void report(int rc, int step) {
    char jobs[300], loc[120], rel[120], km[1200], b[2000];
    text("env-jobs", jobs, sizeof jobs); text("pd.endpoint", loc, sizeof loc); text("logger.ready", rel, sizeof rel);
    text("kmsg", km, sizeof km);
    int n = snprintf(b, sizeof b, "ENV rc=%d step=%d estep=%d locator=%d relay=%d alive=%d/%d ep=%u:%u ion=%u:%u cma=%u:%u jobs=%s loc=[%s] rel=[%s] kmsg=[%s]\n",
                     rc, step, E.step, E.locator > 0, E.relay > 0, E.locator > 0 && !kill(E.locator, 0), E.relay > 0 && !kill(E.relay, 0),
                     major(E.endpoint), minor(E.endpoint), major(E.ion), minor(E.ion), major(E.ion_cma), minor(E.ion_cma),
                     jobs, loc, rel, km);
    if (n > 0) (void)!write(report_fd, b, (size_t)n < sizeof b ? (size_t)n : sizeof b - 1);
}
static void go(void) {
    int step = 99, rc = m11_p4_env_run(&E, &C, &step);
    report(rc, step);
    int again = m11_p4_env_run(&E, &C, &step);
    char b[48]; snprintf(b, sizeof b, "AGAIN rc=%d\n", again); (void)!write(report_fd, b, strlen(b));
    _exit(0);
}
static void c_ok(void) { world(); go(); }
static void c_prepare_fails(void) { world(); put("fail-prepare", "", 0644); go(); }
static void c_not_elf(void) { world(); C.locator = "not-elf"; go(); }
static void c_image_not_root(void) { world(); C.helper_images_root = 1; go(); }
static void c_no_marker(void) { world(); C.locator_ready = "never"; C.marker_ms = 300; go(); }
static void c_amp_enabled(void) { world(); put("amp-bad", "", 0644); go(); }
static void c_no_endpoint(void) { world(); put("no-endpoint", "", 0644); go(); }
static void c_slow_start(void) { world(); put("slow-start", "", 0644); C.start_ms = 300; go(); }
static void c_log_not_tmpfs(void) { world(); C.helper_log_tmpfs = 1; go(); }
static void c_drop(void) { world(); C.drop_helpers = 1; go(); }

static int run(void (*fn)(void), char *rep, size_t cap) {
    int p[2]; assert(pipe(p) == 0);
    fflush(stdout);
    pid_t c = fork(); assert(c >= 0);
    if (c == 0) { close(p[0]); report_fd = p[1]; fn(); _exit(98); }
    close(p[1]);
    size_t have = 0; ssize_t n;
    while (have + 1 < cap && (n = read(p[0], rep + have, cap - 1 - have)) > 0) have += (size_t)n;
    rep[have] = 0; close(p[0]);
    int st; assert(waitpid(c, &st, 0) == c);
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT) abort();
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}
static int rm_one(const char *p, const struct stat *s, int f, struct FTW *w) { (void)s; (void)f; (void)w; return remove(p); }

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    assert(argc == 3);
    snprintf(base, sizeof base, "%s/m11-p4env-XXXXXX", argv[1]);
    assert(mkdtemp(base) && chmod(base, 0755) == 0);
    snprintf(helper_bin, sizeof helper_bin, "%s", argv[2]);

    m11_boot_config bd = m11_boot_config_default();
    m11_p4_env_config d = m11_p4_env_config_default(&bd);
    assert(!strcmp(d.shell, "/bin/busybox") && !strcmp(d.shell_arg, "sh") && !strcmp(d.prepare, "/m11/prepare") &&
           !strcmp(d.control, "/m11/control") && !strcmp(d.locator, "/sbin/m11-pd-mapper") && !strcmp(d.relay, "/sbin/m11-kmsg-relay") &&
           d.helper_log_tmpfs && d.helper_images_root && d.drop_helpers && !strcmp(d.amp_result, "/run/m11/amp-gate.result") &&
           !strcmp(d.locator_ready, "/run/m11/pd.endpoint") && !strcmp(d.relay_ready, "/run/m11-instrumentation/logger.ready") &&
           d.prepare_ms == 90000 && d.start_ms == 40000 && d.usb_ms == 40000 && d.amp_ms == 60000 && d.endpoint_ms == 30000 && d.boot == &bd);
    printf("PASS P4 environment defaults: Run23's scripts, helpers, markers and deadlines; checked root images, tmpfs log, dropped helpers\n");

    char rep[4096]; int st;
    st = run(c_ok, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "ENV rc=0 step=0 estep=8 locator=1 relay=1 alive=1/1 ep=5:2 ion=1:3 cma=1:5"));
    assert(strstr(rep, "jobs=prepare,journal,probe,start,usb_start,amp_gate ") && strstr(rep, "AGAIN rc=-114"));
    assert(strstr(rep, " fds=0]") && strstr(rep, "M11P4 v=1 env step=8 metadata rc=0"));
    printf("PASS P4 environment in Run23's order: prepare, journal, locator + marker + probe, relay + marker, ADSP start, USB, amplifier gate, endpoint/ION metadata; helpers alive with only stdio; one-shot\n");

    st = run(c_prepare_fails, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "ENV rc=-10 step=1 estep=0 locator=0 relay=0") && strstr(rep, "jobs=prepare "));
    printf("PASS P4 environment: a failing prepare stops before anything else\n");

    st = run(c_not_elf, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "ENV rc=-1 step=4 estep=3 locator=0 relay=0") && strstr(rep, "jobs=prepare,journal "));
    printf("PASS P4 environment: a helper image that is not an ELF is refused before it runs\n");

    st = run(c_image_not_root, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    if (geteuid() != 0) assert(st == 0 && strstr(rep, "ENV rc=-1 step=4 estep=3 locator=0"));
    printf("PASS P4 environment: a helper image not owned by root (production rule) is refused\n");

    st = run(c_no_marker, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "ENV rc=-110 step=4 estep=3 locator=1 relay=0 alive=1/0") && strstr(rep, "jobs=prepare,journal "));
    printf("PASS P4 environment: a locator that never reports ready stops the phase (it is left running, never killed)\n");

    st = run(c_amp_enabled, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "ENV rc=-1 step=7 estep=6") && strstr(rep, "jobs=prepare,journal,probe,start,usb_start,amp_gate "));
    printf("PASS P4 environment: amplifier switches not read back disabled stop the phase before any endpoint work\n");

    st = run(c_no_endpoint, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "ENV rc=-2 step=8 estep=7"));
    printf("PASS P4 environment: no endpoint metadata within its deadline stops the phase (nothing made or opened)\n");

    st = run(c_slow_start, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
    assert(st == 0 && strstr(rep, "ENV rc=-110 step=6 estep=5"));
    printf("PASS P4 environment: a job past its deadline stops the phase and is not killed\n");

    struct statfs fs; assert(statfs(base, &fs) == 0);
    if (fs.f_type != TMPFS_MAGIC) {
        st = run(c_log_not_tmpfs, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
        assert(st == 0 && strstr(rep, "ENV rc=-1 step=3 estep=2 locator=0"));
        printf("PASS P4 environment: a helper log off tmpfs (production rule) is refused\n");
    } else printf("SKIP helper log off tmpfs: the scratch directory is tmpfs\n");

    if (geteuid() == 0) {
        st = run(c_drop, rep, sizeof rep); printf("INFO st=%d %s", st, rep);
        assert(st == 0 && strstr(rep, "ENV rc=0 step=0 estep=8 locator=1 relay=1 alive=1/1"));
        assert(strstr(rep, "loc=[uid=65534 caps=0000000000000000 fds=0]") && strstr(rep, "rel=[uid=65534 caps=0000000000000000 fds=0]"));
        printf("PASS P4 environment as root: both helpers run as uid 65534 with no capabilities and only stdio\n");
    } else printf("SKIP helper privilege drop: not root\n");

    (void)nftw(base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    printf("PASS P4 environment phase (%s)\n", geteuid() == 0 ? "root" : "unprivileged");
    return 0;
}
