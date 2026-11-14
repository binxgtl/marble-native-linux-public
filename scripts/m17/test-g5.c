/* M17 G5: the native path's PID 1 runtime, its module loader, the daily session's starter and the volume keys, on
 * synthetic trees, fake commands and FIFOs standing in for evdev nodes. No device. Run under ASan/UBSan too (test.sh). */
#define _GNU_SOURCE
#include "cmd.h"
#include "load.h"
#include "native.h"
#include "select.h"
#include "session.h"
#include "volkeys.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);                                   \
            failures++;                                                                                                \
        }                                                                                                              \
    } while (0)

static char base[256];

static const char *at(const char *rel) {
    static char paths[8][512];
    static unsigned next;
    char *path = paths[next++ % 8];
    snprintf(path, 512, "%s/%s", base, rel);
    return path;
}

static void mkdirs(const char *path) {
    char dir[512];
    snprintf(dir, sizeof dir, "%s", path);
    for (char *p = dir + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(dir, 0755);
            *p = '/';
        }
}

static void put(const char *rel, const char *text) {
    const char *path = at(rel);
    mkdirs(path);
    FILE *f = fopen(path, "w");
    assert(f);
    fputs(text, f);
    fclose(f);
}

/* A shell script; "@/" in body stands for base and a slash ("$@" stays the shell's). */
static void script(const char *rel, const char *body) {
    char text[8192];
    size_t used = (size_t)snprintf(text, sizeof text, "#!/bin/sh\n");
    for (const char *p = body; *p && used + 300 < sizeof text; p++) {
        if (p[0] == '@' && p[1] == '/')
            used += (size_t)snprintf(text + used, sizeof text - used, "%s", base);
        else
            text[used++] = *p;
    }
    text[used] = 0;
    put(rel, text);
    assert(!chmod(at(rel), 0755));
}

static char *slurp(const char *rel) {
    static char text[4][1 << 20];
    static unsigned next;
    char *out = text[next++ % 4];
    out[0] = 0;
    int fd = open(at(rel), O_RDONLY);
    if (fd < 0)
        return out;
    size_t used = 0;
    for (ssize_t got; used + 1 < sizeof text[0] && (got = read(fd, out + used, sizeof text[0] - 1 - used)) > 0;)
        used += (size_t)got;
    out[used] = 0;
    close(fd);
    return out;
}

static int exists(const char *rel) {
    return !access(at(rel), F_OK);
}

static void clean(void) {
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", base);
    assert(!system(cmd));
    mkdir(base, 0755);
}

/* Waits up to ms for rel to hold `lines` lines. */
static int wait_lines(const char *rel, unsigned lines, unsigned ms) {
    for (unsigned waited = 0;; waited += 20) {
        unsigned count = 0;
        for (const char *p = slurp(rel); *p; p++)
            count += *p == '\n';
        if (count >= lines)
            return 1;
        if (waited >= ms)
            return 0;
        usleep(20000);
    }
}

/* ---- The volume keys' decisions ---- */

static void test_vk(void) {
    struct m17_vk v;
    m17_vk_init(&v, 120, 400, 150);
    /* A tap steps once, on its release. */
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEUP, 1, 0) == M17_VK_NONE && m17_vk_due(&v) == 120);
    CHECK(m17_vk_tick(&v, 100) == M17_VK_NONE);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEUP, 0, 50) == M17_VK_UP);
    CHECK(m17_vk_due(&v) == 0 && m17_vk_tick(&v, 1000) == M17_VK_NONE);
    /* Held: once after the grace, then after the delay, then every repeat; the kernel's repeat is ignored. */
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEDOWN, 1, 1000) == M17_VK_NONE);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEDOWN, 2, 1100) == M17_VK_NONE);
    CHECK(m17_vk_tick(&v, 1119) == M17_VK_NONE);
    CHECK(m17_vk_tick(&v, 1120) == M17_VK_DOWN && m17_vk_due(&v) == 1520);
    CHECK(m17_vk_tick(&v, 1519) == M17_VK_NONE);
    CHECK(m17_vk_tick(&v, 1520) == M17_VK_DOWN && m17_vk_due(&v) == 1670);
    CHECK(m17_vk_tick(&v, 1670) == M17_VK_DOWN);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEDOWN, 0, 1700) == M17_VK_NONE && m17_vk_due(&v) == 0);
    CHECK(m17_vk_tick(&v, 5000) == M17_VK_NONE);
    /* Both inside the grace: one screenshot, no step, nothing until both are up. */
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEUP, 1, 3000) == M17_VK_NONE);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEDOWN, 1, 3050) == M17_VK_SHOT);
    CHECK(m17_vk_tick(&v, 4000) == M17_VK_NONE && m17_vk_due(&v) == 0);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEUP, 0, 4100) == M17_VK_NONE);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEUP, 1, 4200) == M17_VK_NONE);
    CHECK(m17_vk_tick(&v, 4500) == M17_VK_NONE);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEUP, 0, 4600) == M17_VK_NONE);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEDOWN, 0, 4700) == M17_VK_NONE);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEDOWN, 1, 4800) == M17_VK_NONE);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEDOWN, 0, 4810) == M17_VK_DOWN);
    /* The other key while one repeats is the chord too, and the repeat stops. */
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEUP, 1, 5000) == M17_VK_NONE);
    CHECK(m17_vk_tick(&v, 5120) == M17_VK_UP);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEDOWN, 1, 5200) == M17_VK_SHOT);
    CHECK(m17_vk_tick(&v, 5600) == M17_VK_NONE);
    /* Unknown keys and values, a press twice, and a release without a press change nothing. */
    m17_vk_reset(&v);
    CHECK(m17_vk_key(&v, 116, 1, 6000) == M17_VK_NONE && m17_vk_due(&v) == 0);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEUP, 7, 6000) == M17_VK_NONE && m17_vk_due(&v) == 0);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEUP, 0, 6000) == M17_VK_NONE);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEUP, 1, 6000) == M17_VK_NONE);
    CHECK(m17_vk_key(&v, M17_KEY_VOLUMEUP, 1, 6100) == M17_VK_NONE && m17_vk_due(&v) == 6120);
    m17_vk_reset(&v);
    CHECK(m17_vk_due(&v) == 0 && !v.up && !v.down && m17_vk_key(&v, M17_KEY_VOLUMEUP, 0, 6200) == M17_VK_NONE);
    /* The volume: 5 a step on a 5 grid, within 0..100. */
    CHECK(m17_vk_volume(63, M17_VK_UP) == 65 && m17_vk_volume(63, M17_VK_DOWN) == 60);
    CHECK(m17_vk_volume(65, M17_VK_UP) == 70 && m17_vk_volume(65, M17_VK_DOWN) == 60);
    CHECK(m17_vk_volume(0, M17_VK_DOWN) == 0 && m17_vk_volume(3, M17_VK_DOWN) == 0 && m17_vk_volume(-1, M17_VK_UP) == 5);
    CHECK(m17_vk_volume(98, M17_VK_UP) == 100 && m17_vk_volume(100, M17_VK_UP) == 100 && m17_vk_volume(150, M17_VK_DOWN) == 100);
    CHECK(m17_vk_volume(40, M17_VK_SHOT) == 40);
    CHECK(m17_vk_parse_volume("Volume: front-left: 39322 /  60% / -13.31 dB,   front-right: 39322 /  60% / -13.31 dB\n") == 60);
    CHECK(m17_vk_parse_volume("100%") == 100 && m17_vk_parse_volume("x 7%") == 7);
    CHECK(m17_vk_parse_volume("none") == -1 && m17_vk_parse_volume("%") == -1 && m17_vk_parse_volume("1234%") == -1);
}

/* ---- Commands and records ---- */

static void test_cmd(void) {
    clean();
    char out[256];
    const char *echo[] = {"/bin/sh", "-c", "printf 'running extra\\n'; exit 3", NULL};
    CHECK(m17_run(echo, NULL, out, sizeof out, 5000) == 3 && !strcmp(out, "running extra\n"));
    const char *env_argv[] = {"/bin/sh", "-c", "printf '%s' \"$M17_TEST\"", NULL};
    const char *env[] = {"M17_TEST=given", "PATH=/usr/bin:/bin", NULL};
    CHECK(m17_run(env_argv, env, out, sizeof out, 5000) == 0 && !strcmp(out, "given"));
    char small[4];
    CHECK(m17_run(echo, NULL, small, sizeof small, 5000) == 3 && !strcmp(small, "run"));
    const char *slow[] = {"/bin/sh", "-c", "exec sleep 5", NULL};
    uint64_t start = m17_cmd_now_ms();
    CHECK(m17_run(slow, NULL, out, sizeof out, 200) == -1 && m17_cmd_now_ms() - start < 3000);
    const char *missing[] = {"/nonexistent/m17", NULL};
    CHECK(m17_run(missing, NULL, out, sizeof out, 2000) == 127);
    char word[16];
    m17_first_word("  running\n", word, sizeof word);
    CHECK(!strcmp(word, "running"));
    m17_first_word("", word, sizeof word);
    CHECK(!strcmp(word, "none"));
    m17_first_word("a;b", word, sizeof word);
    CHECK(!strcmp(word, "a"));
    m17_first_word("abcdefghijklmnopqrstuvwxyz", word, sizeof word);
    CHECK(!strcmp(word, "abcdefghijklmno"));
    CHECK(m17_append(at("record.log"), "one\n", 6) == 0 && m17_append(at("record.log"), "two\n", 6) == 0);
    CHECK(!strcmp(slurp("record.log"), "one\ntwo\n"));
    CHECK(m17_append(at("record.log"), "three\n", 6) == 0);
    CHECK(!strcmp(slurp("record.log"), "three\n") && !strcmp(slurp("record.log.1"), "one\ntwo\n"));
    struct stat st;
    CHECK(!stat(at("record.log"), &st) && (st.st_mode & 0777) == 0600);
    CHECK(!symlink(at("record.log"), at("link.log")) && m17_append(at("link.log"), "x\n", 100) == -EINVAL);
    CHECK(!strcmp(slurp("record.log"), "three\n"));
}

/* ---- The module loader ---- */

static char fail_name[64];
static int fail_rc;

/* The kernel stand-in: the module's name from the descriptor, appended to proc/modules. */
static int fake_finit(int fd, const char *params) {
    CHECK(params && !*params);
    char link[64], path[512];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof path - 1);
    if (n <= 0)
        return -EBADF;
    path[n] = 0;
    const char *name = strrchr(path, '/') + 1;
    if (*fail_name && !strcmp(name, fail_name) && fail_rc != -EEXIST)
        return fail_rc;
    char key[64], line[128];
    m17_module_key(name, key, sizeof key);
    snprintf(line, sizeof line, "%s 4096 0 - Live 0x0\n", key);
    FILE *f = fopen(at("proc/modules"), "a");
    assert(f);
    fputs(line, f);
    fclose(f);
    return *fail_name && !strcmp(name, fail_name) ? fail_rc : 0;
}

static char load_log[8192];
static void log_line(const char *line) {
    strncat(load_log, line, sizeof load_log - strlen(load_log) - 2);
    strcat(load_log, "\n");
}

static int loader(const char *closure, const char *list, const char *proc, unsigned rows, unsigned total, struct m17_load *l) {
    clean();
    put("closure.tsv", closure);
    put("modules.list", list);
    put("proc/modules", proc);
    for (const char *name = "a.ko\0b-x.ko\0c.ko\0d.ko\0"; *name; name += strlen(name) + 1) {
        char rel[64];
        snprintf(rel, sizeof rel, "lib/%s", name);
        put(rel, "module");
    }
    load_log[0] = 0;
    static char closure_path[512], list_path[512], proc_path[512], lib_path[512];
    snprintf(closure_path, sizeof closure_path, "%s", at("closure.tsv"));
    snprintf(list_path, sizeof list_path, "%s", at("modules.list"));
    snprintf(proc_path, sizeof proc_path, "%s", at("proc/modules"));
    snprintf(lib_path, sizeof lib_path, "%s", at("lib"));
    *l = (struct m17_load){.closure = closure_path, .list = list_path, .proc_modules = proc_path, .lib = lib_path, .rows = rows, .total = total,
                           .finit = fake_finit, .log = log_line};
    return m17_load_run(l);
}

static void test_load(void) {
    char key[32];
    m17_module_key("qcom-pon.ko", key, sizeof key);
    CHECK(!strcmp(key, "qcom_pon"));
    m17_module_key("msm_drm.ko", key, sizeof key);
    CHECK(!strcmp(key, "msm_drm"));
    m17_module_key("a-b-c", key, sizeof key);
    CHECK(!strcmp(key, "a_b_c"));
    static const char closure[] = "load\tmodule\tsize\n0\ta.ko\t1\n1\tb-x.ko\t1\n2\tc.ko\t1\n3\td.ko\t1\n";
    static const char list[] = "a.ko\nk-1.ko\nk-2.ko\n";
    static const char proc[] = "a 1 0 - Live 0x0\nk_1 1 0 - Live 0x0\nk_2 1 0 - Live 0x0\n";
    struct m17_load l;
    fail_name[0] = 0;
    /* The closure's first rows in order, the loaded ones skipped; then exactly the union. */
    CHECK(loader(closure, list, proc, 3, 5, &l) == 0 && l.loaded == 2 && l.already == 1 && l.union_count == 5 && l.present == 5);
    CHECK(strstr(load_log, "M17 load b-x.ko rc=0\nM17 load c.ko rc=0\n") && strstr(load_log, " OK\n") && !strstr(load_log, "d.ko"));
    CHECK(strstr(slurp("proc/modules"), "b_x 4096"));
    /* EEXIST is the kernel's "already": tolerated. */
    snprintf(fail_name, sizeof fail_name, "c.ko");
    fail_rc = -EEXIST;
    CHECK(loader(closure, list, proc, 3, 5, &l) == 0 && l.loaded == 1 && l.already == 2);
    /* Any other failure stops at once. */
    fail_rc = -ENOENT;
    CHECK(loader(closure, list, proc, 3, 5, &l) == 1 && strstr(load_log, "M17 load c.ko rc=-2") && l.loaded == 1);
    fail_name[0] = 0;
    /* A module the kernel holds beyond the union, the union not the expected count, or a listed one missing. */
    CHECK(loader(closure, list, "a 1 0 - Live 0x0\nk_1 1 0 - Live 0x0\nk_2 1 0 - Live 0x0\nz 1 0 - Live 0x0\n", 3, 5, &l) == 1 &&
          strstr(load_log, "kernel=6 FAIL"));
    CHECK(loader(closure, list, proc, 3, 6, &l) == 1);
    CHECK(loader(closure, list, "a 1 0 - Live 0x0\nk_1 1 0 - Live 0x0\n", 3, 5, &l) == 1 && l.present == 4);
    /* Malformed inputs load nothing. */
    CHECK(loader("load\tname\n0\ta.ko\n", list, proc, 1, 3, &l) == 1 && !l.loaded);
    CHECK(loader(closure, "a.ko\na.ko\n", proc, 3, 5, &l) == 1 && !l.loaded);
    CHECK(loader("load\tmodule\n0\t../a.ko\n", list, proc, 1, 3, &l) == 1 && !l.loaded);
    CHECK(loader(closure, list, proc, 5, 7, &l) == 1 && !l.loaded);
    CHECK(loader(closure, "", proc, 3, 5, &l) == 1 && !l.loaded);
    CHECK(loader(closure, list, "a 1 0 - Live 0x0\na 1 0 - Live 0x0\n", 3, 5, &l) == 1 && !l.loaded);
}

/* ---- Redaction and the log file ---- */

static void test_redact(void) {
    /* Synthetic values only; the addresses are put together here, so no source line holds one. */
    char text[512], mixed[32];
    snprintf(mixed, sizeof mixed, "%02x:%02x-%02x:%02x:%02x:%02x", 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
    snprintf(text, sizeof text,
             "6,1,2,-;Kernel command line: console=x androidboot.serialno=synthetic123 foo\n"
             "6,2,3,-;usb serialno=fixture\n"
             "wlan: mac %02x:%02x:%02x:%02x:%02x:%02x ok\n"
             "mac2 %02X-%02X-%02X-%02X-%02X-%02X and %s\n"
             "boot androidboot.serialno=synthetic-0123456789\n"
             "not-a-mac %02x:%02x:%02x:%02x:%02x\n"
             "\n"
             "last serialno",
             0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, mixed, 0x12, 0x34, 0x56, 0x78, 0x9a);
    size_t size = m17_redact(text, strlen(text));
    text[size] = 0;
    char want[512];
    snprintf(want, sizeof want,
             "6,1,2,-;Kernel command line: [redacted]\n"
             "6,2,3,-;usb serialnoxxxxxxxx\n"
             "wlan: mac xx:xx:xx:xx:xx:xx ok\n"
             "mac2 xx-xx-xx-xx-xx-xx and %s\n"
             "boot androidboot.serialno [redacted]\n"
             "not-a-mac %02x:%02x:%02x:%02x:%02x\n"
             "\n"
             "last serialno",
             mixed, 0x12, 0x34, 0x56, 0x78, 0x9a);
    CHECK(!strcmp(text, want));
    char empty[1] = "";
    CHECK(m17_redact(empty, 0) == 0);
}

static void test_write_log(void) {
    clean();
    mkdirs(at("wl/var/lib/x"));
    char dir[512];
    snprintf(dir, sizeof dir, "%s", at("wl/var/lib/m19"));
    CHECK(m17_write_log(dir, "native.log", "one", 3) == 0 && !strcmp(slurp("wl/var/lib/m19/native.log"), "one") &&
          !exists("wl/var/lib/m19/native.log.1"));
    CHECK(m17_write_log(dir, "native.log", "two", 3) == 0 && !strcmp(slurp("wl/var/lib/m19/native.log"), "two") &&
          !strcmp(slurp("wl/var/lib/m19/native.log.1"), "one") && !exists("wl/var/lib/m19/.native.log.tmp"));
    struct stat st;
    CHECK(!stat(at("wl/var/lib/m19/native.log"), &st) && (st.st_mode & 0777) == 0600);
    /* A stale temporary is replaced. */
    put("wl/var/lib/m19/.native.log.tmp", "stale");
    CHECK(m17_write_log(dir, "native.log", "three", 5) == 0 && !strcmp(slurp("wl/var/lib/m19/native.log"), "three") &&
          !exists("wl/var/lib/m19/.native.log.tmp"));
    /* A link anywhere on the way, a missing middle, a relative path or a bad name: nothing written. */
    CHECK(!symlink(at("wl/var"), at("wl2")));
    char linked[512];
    snprintf(linked, sizeof linked, "%s", at("wl2/lib/m19"));
    CHECK(m17_write_log(linked, "native.log", "x", 1) < 0);
    snprintf(linked, sizeof linked, "%s", at("nothere/lib/m19"));
    CHECK(m17_write_log(linked, "native.log", "x", 1) == -ENOENT && !exists("nothere"));
    CHECK(m17_write_log("relative/m19", "native.log", "x", 1) == -EINVAL);
    CHECK(m17_write_log(dir, "a/b", "x", 1) == -EINVAL && m17_write_log(dir, ".hidden", "x", 1) == -EINVAL);
    CHECK(m17_write_log(dir, "", "x", 1) == -EINVAL);
    snprintf(linked, sizeof linked, "%s/../m19", at("wl/var/lib"));
    CHECK(m17_write_log(linked, "native.log", "x", 1) == -EINVAL);
    CHECK(!strcmp(slurp("wl/var/lib/m19/native.log"), "three"));
}

/* ---- The native runtime ---- */

static struct m19_step nat_steps[5];
static char paths[16][512];

static struct m17_native native_bench(const char *boot_rc, const char *adsp_rc, const char *const step_rc[5], unsigned owned_ms) {
    clean();
    put("nat/boot.rc", boot_rc);
    put("nat/adsp.rc", adsp_rc);
    script("nat/bootstrap", "echo M17TEST bootstrap >&2\nexit $(cat @/nat/boot.rc)\n");
    script("nat/adsp", "exit $(cat @/nat/adsp.rc)\n");
    script("nat/display", "echo \"$@\" >>@/nat/display.txt\n");
    static const char *names[5] = {"S1", "S2", "S3", "S4-always", "S5-owned"};
    for (unsigned i = 0; i < 5; i++) {
        char rel[64], body[256];
        snprintf(rel, sizeof rel, "nat/step%u", i);
        snprintf(body, sizeof body, "echo %s >>@/nat/steps.txt\n%s\n", names[i], step_rc[i]);
        script(rel, body);
        snprintf(paths[i], sizeof paths[i], "%s", at(rel));
        nat_steps[i] = (struct m19_step){names[i], paths[i], 5000, M19_STEP_REQUIRED};
    }
    nat_steps[3].flags |= M19_STEP_ALWAYS;
    nat_steps[4].flags |= M19_STEP_OWNED;
    nat_steps[4].ms = owned_ms;
    put("nat/kmsg", "6,1,2,-;Kernel command line: androidboot.serialno=SYNTHETIC_SECRET x\n6,2,3,-;hello kernel\n");
    put("nat/bootstrap.log", "M17TEST boot log\n");
    mkdirs(at("nat/data/ubuntu/var/lib/x"));
    snprintf(paths[5], 512, "%s", at("nat/bootstrap"));
    snprintf(paths[6], 512, "%s", at("nat/adsp"));
    snprintf(paths[7], 512, "%s", at("nat/display"));
    snprintf(paths[8], 512, "%s", at("nat/kmsg"));
    snprintf(paths[9], 512, "%s", at("nat/bootstrap.log"));
    snprintf(paths[10], 512, "%s", at("nat/logcat.txt"));
    snprintf(paths[11], 512, "%s", at("nat/data/ubuntu/var/lib/m19"));
    return (struct m17_native){.bootstrap = paths[5], .adsp = paths[6], .display = paths[7], .kmsg = paths[8], .boot_log = paths[9],
                               .logcat = paths[10], .log_dir = paths[11], .log_name = "m17-native.log", .steps = nat_steps, .step_count = 5,
                               .bootstrap_ms = 5000, .adsp_ms = 5000, .display_ms = 5000, .blue_ms = 1, .final_ms = 600000};
}

static void test_native(void) {
    static const char *const ok[5] = {"exit 0", "exit 0", "exit 0", "exit 0", "exit 0"};
    struct m17_native n = native_bench("0", "0", ok, 5000);
    CHECK(m17_native_main(&n) == M17_END_PASS && n.all_ok && !n.write_warning && n.log_rc == 0 && n.adsp_rc == 0);
    CHECK(!strcmp(slurp("nat/steps.txt"), "S1\nS2\nS3\nS4-always\nS5-owned\n"));
    CHECK(wait_lines("nat/display.txt", 2, 3000) && !strcmp(slurp("nat/display.txt"), "000000ff 1\n0000ff00 600000\n"));
    const char *log = slurp("nat/data/ubuntu/var/lib/m19/m17-native.log");
    static const char head[] = "M17 native log v1\nsummary all_ok=1 write_warning=0 adsp_rc=0 ownership_unresolved=0\nstep S1 ran=1 rc=0 ms=";
    CHECK(!strncmp(log, head, sizeof head - 1));
    CHECK(strstr(log, "step S5-owned ran=1 rc=0") && strstr(log, "M17 bootstrap.log\nM17TEST boot log\nM17 kernel log\n"));
    CHECK(strstr(log, "Kernel command line: [redacted]") && !strstr(log, "SYNTHETIC_SECRET") && strstr(log, "hello kernel"));
    CHECK(strstr(log, "M17NAT start") && strstr(log, "M17NAT step S3 OK rc=0") && strstr(log, "M17 logcat\n(absent)\n"));
    CHECK(strstr(slurp("nat/kmsg"), "M17NAT log rc=0"));

    /* A required step fails: the rest stop but the ALWAYS one; YELLOW; the log says why. */
    static const char *const fails[5] = {"exit 0", "exit 4", "exit 0", "exit 0", "exit 0"};
    n = native_bench("0", "0", fails, 5000);
    CHECK(m17_native_main(&n) == M17_END_NOT_PASS && !n.all_ok && n.ran[1] && !n.ran[2] && n.ran[3] && !n.ran[4]);
    CHECK(!strcmp(slurp("nat/steps.txt"), "S1\nS2\nS4-always\n") && n.results[1] == -1 && n.results[2] == -1);
    CHECK(wait_lines("nat/display.txt", 2, 3000) && !strcmp(slurp("nat/display.txt"), "000000ff 1\n00ffff00 600000\n"));
    log = slurp("nat/data/ubuntu/var/lib/m19/m17-native.log");
    CHECK(strstr(log, "summary all_ok=0") && strstr(log, "step S2 ran=1 rc=-1") && strstr(log, "step S3 ran=0 rc=-1"));

    /* The bootstrap holds: nothing else runs, nothing is painted, nothing written. */
    n = native_bench("1", "0", ok, 5000);
    CHECK(m17_native_main(&n) == M17_END_BOOTSTRAP && !exists("nat/steps.txt") && !exists("nat/display.txt"));
    CHECK(!exists("nat/data/ubuntu/var/lib/m19") && n.adsp_rc == -1);

    /* The ADSP fails: BLUE, then RED; no step. */
    n = native_bench("0", "3", ok, 5000);
    CHECK(m17_native_main(&n) == M17_END_ADSP && n.adsp_rc == -1 && !exists("nat/steps.txt"));
    CHECK(wait_lines("nat/display.txt", 2, 3000) && !strcmp(slurp("nat/display.txt"), "000000ff 1\n00ff0000 600000\n"));

    /* A write warning in the kernel log is not a PASS (R1's check). */
    n = native_bench("0", "0", ok, 5000);
    FILE *f = fopen(at("nat/kmsg"), "a");
    assert(f);
    fputs("6,9,9,-;" M19_WRITE_WARNING " (sda1)\n", f);
    fclose(f);
    CHECK(m17_native_main(&n) == M17_END_NOT_PASS && n.write_warning && !n.all_ok);
    CHECK(strstr(slurp("nat/data/ubuntu/var/lib/m19/m17-native.log"), "summary all_ok=0 write_warning=1"));

    /* The owned step runs past its limit: its group is killed and reaped, and the run stops there. */
    static const char *const slow[5] = {"exit 0", "exit 0", "exit 0", "exit 0", "exec sleep 30"};
    n = native_bench("0", "0", slow, 300);
    CHECK(m17_native_main(&n) == M17_END_NOT_PASS && n.results[4] == -ETIMEDOUT && !n.ownership_unresolved);

    /* The owned step's leader succeeds but leaves a process in its group behind: never a success (R1's rule). */
    static const char *const stray[5] = {"exit 0", "exit 0", "exit 0", "exit 0", "sleep 30 &\nexit 0"};
    n = native_bench("0", "0", stray, 5000);
    CHECK(m17_native_main(&n) == M17_END_NOT_PASS && n.results[4] == -ECHILD && !n.ownership_unresolved);

    /* No place for the log (/data not mounted): still a PASS, the log's failure recorded. */
    n = native_bench("0", "0", ok, 5000);
    snprintf(paths[11], 512, "%s", at("nat/nodata/ubuntu/var/lib/m19"));
    n.log_dir = paths[11];
    CHECK(m17_native_main(&n) == M17_END_PASS && n.log_rc == -ENOENT && strstr(slurp("nat/kmsg"), "M17NAT log rc=-2"));
}

/* ---- The session's starter ---- */

static struct m17_session session_bench(int desktop, const char *sink_state, const char *ce_line) {
    clean();
    put("ses/proc/100/comm", "xfce4-panel\n");
    put("ses/proc/7/comm", "Xorg\n");
    if (desktop)
        put("ses/proc/101/comm", "xfdesktop\n");
    put("ses/proc/self", "");
    put("ses/X0", "");
    put("ses/boot_id", "0f0f-boot\n");
    put("ses/osrelease", "5.10.236-gb97c62c4e7d1\n");
    put("ses/sink.state", sink_state);
    put("ses/ce.line", ce_line);
    script("ses/systemctl", "echo \"$@\" >>@/ses/calls.txt\n"
                            "case \"$1 $2\" in\n"
                            "'start marble-sink.service') printf 'state=%s\\nchord_ok=1\\n' \"$(cat @/ses/sink.state)\" >@/ses/sink.report;;\n"
                            "'start marble-pulse.service') : >@/ses/pulse.up;;\n"
                            "'start marble-ce.service') cat @/ses/ce.line >@/ses/ce.result;;\n"
                            "'is-system-running '*) echo running;;\n"
                            "'is-active '*) echo active;;\n"
                            "esac\n");
    script("ses/pactl", "[ -e @/ses/pulse.up ] || exit 1\n"
                        "[ \"$*\" = 'list short sinks' ] && printf '0\\tmarble_speaker\\tmodule-pipe-sink.c\\ts16le 2ch 48000Hz\\tIDLE\\n'\n");
    script("ses/nmcli", "echo connected\n");
    static char p[16][512];
    const char *rels[] = {"ses/systemctl", "ses/pactl", "ses/nmcli", "ses/proc", "ses/X0", "ses/sink.report", "ses/ce.result", "ses/boot_id",
                          "ses/osrelease", "ses/guard-tripped", "ses/m17-session.log"};
    for (unsigned i = 0; i < sizeof rels / sizeof rels[0]; i++)
        snprintf(p[i], sizeof p[i], "%s", at(rels[i]));
    static const char *const env[] = {"PATH=/usr/bin:/bin", NULL};
    return (struct m17_session){.systemctl = p[0], .pactl = p[1], .nmcli = p[2], .proc = p[3], .x_socket = p[4], .sink_report = p[5],
                                .ce_result = p[6], .boot_id = p[7], .osrelease = p[8], .guard_marker = p[9], .log = p[10],
                                .sink_unit = "marble-sink.service", .pulse_unit = "marble-pulse.service", .ce_unit = "marble-ce.service",
                                .keys_unit = "m17-volkeys.service", .guard_unit = "m19-r3-guard.service", .sink_name = "marble_speaker",
                                .panel_comm = "xfce4-panel", .desktop_comm = "xfdesktop", .pulse_env = env, .desktop_ms = 1500,
                                .sink_ms = 2000, .pulse_ms = 2000, .ce_ms = 2000, .command_ms = 5000, .poll_ms = 20};
}

static void test_session(void) {
    struct m17_session_result r;
    struct m17_session s = session_bench(1, "streaming", "M19_CE status=OK entries=3\n");
    CHECK(m17_session_main(&s, &r) == 0 && r.desktop_ok && r.streaming && r.pulse_sink && r.ce_seen && !strcmp(r.ce_status, "OK"));
    CHECK(!strcmp(slurp("ses/calls.txt"), "start marble-sink.service\nstart marble-pulse.service\nstart marble-ce.service\n"
                                          "is-system-running\nis-active m17-volkeys.service\nis-active m19-r3-guard.service\n"));
    const char *log = slurp("ses/m17-session.log");
    CHECK(strstr(log, " M17 session start boot=0f0f-boot release=5.10.236-gb97c62c4e7d1 x=1 desktop=1 desktop_s=0 sink_rc=0 "
                      "sink=streaming pulse_rc=0 pulse_sink=1 ce_rc=0\n"));
    CHECK(strstr(log, " M17 session settled ce=OK ce_seen=1 ce_s=0 system=running keys=active guard=active guard_tripped=0 "
                      "network=connected\n"));

    /* No desktop: nothing started, the record says so. */
    s = session_bench(0, "streaming", "M19_CE status=OK\n");
    CHECK(m17_session_main(&s, &r) == 1 && r.x_ok && !r.desktop_ok && r.sink_rc == -1 && r.ce_rc == -1);
    CHECK(!strstr(slurp("ses/calls.txt"), "start") && strstr(slurp("ses/m17-session.log"), "desktop=0 desktop_s=1 sink_rc=-1 sink=none"));

    /* The sink fails: no PulseAudio, the keypad still. */
    s = session_bench(1, "failed", "M19_CE status=OK\n");
    CHECK(m17_session_main(&s, &r) == 1 && !r.streaming && r.pulse_rc == -1 && r.ce_rc == 0);
    CHECK(!strstr(slurp("ses/calls.txt"), "marble-pulse") && strstr(slurp("ses/m17-session.log"), "sink=failed pulse_rc=-1"));

    /* Only an upper-case status word reaches the record. */
    s = session_bench(1, "streaming", "M19_CE status=ok;reboot\n");
    CHECK(m17_session_main(&s, &r) == 0 && r.ce_seen && !strcmp(r.ce_status, "none"));
    CHECK(strstr(slurp("ses/m17-session.log"), "ce=none ce_seen=1") && !strstr(slurp("ses/m17-session.log"), "reboot"));
}

/* ---- The volume keys' daemon ---- */

#define CAP_UP "8000000000000 0\n"
#define CAP_DOWN "4000000000000 0\n"

static void key_device(const char *event, const char *name, const char *caps) {
    char rel[256];
    snprintf(rel, sizeof rel, "vk/sys/class/input/%s/device/name", event);
    put(rel, name);
    snprintf(rel, sizeof rel, "vk/sys/class/input/%s/device/capabilities/key", event);
    put(rel, caps);
    snprintf(rel, sizeof rel, "vk/sys/class/input/%s/dev", event);
    put(rel, "13:65\n");
    snprintf(rel, sizeof rel, "vk/dev/input/%s", event);
    mkdirs(at(rel));
    assert(!mkfifo(at(rel), 0600));
}

static void send_events(int fd, const struct input_event *events, size_t count) {
    CHECK(write(fd, events, count * sizeof *events) == (ssize_t)(count * sizeof *events));
}

static struct input_event ev(unsigned type, unsigned code, int value) {
    struct input_event e;
    memset(&e, 0, sizeof e);
    e.type = (unsigned short)type;
    e.code = (unsigned short)code;
    e.value = value;
    return e;
}

static void test_volkeys(void) {
    clean();
    key_device("event0", "gpio-keys\n", CAP_UP);
    key_device("event12", "pmic_resin\n", CAP_DOWN);
    key_device("event2", "goodix_ts\n", "0\n");
    script("vk/pactl", "[ \"$1\" = get-sink-volume ] && { echo 'Volume: front-left: 39322 /  60% / -13.31 dB'; exit 0; }\n"
                       "echo \"$@\" >>@/vk/pactl.txt\n");
    script("vk/shooter", "echo \"$@ bus=$DBUS_SESSION_BUS_ADDRESS display=$DISPLAY\" >>@/vk/shot.txt\n");
    put("vk/bus", "unix:path=/run/m19/test-bus\n");
    put("vk/kmsg", "");
    static char p[8][512];
    const char *rels[] = {"vk/sys", "vk/dev", "vk/pactl", "vk/shooter", "vk/Pictures", "vk/keys.log", "vk/kmsg", "vk/bus"};
    for (unsigned i = 0; i < 8; i++)
        snprintf(p[i], sizeof p[i], "%s", at(rels[i]));
    static const char *const pulse_env[] = {"PATH=/usr/bin:/bin", NULL};
    static const char *const x_env[] = {"DISPLAY=:0", "PATH=/usr/bin:/bin", NULL};
    struct m17_volkeys k = {.sys = p[0], .dev = p[1], .pactl = p[2], .shooter = p[3], .shots = p[4], .log = p[5], .kmsg = p[6],
                            .pulse_env = pulse_env, .x_env = x_env, .session_bus = p[7], .find_ms = 2000, .command_ms = 5000, .make_nodes = 0};
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        alarm(20);
        _exit(m17_volkeys_main(&k));
    }
    int up = open(at("vk/dev/input/event0"), O_WRONLY), down = open(at("vk/dev/input/event12"), O_WRONLY);
    CHECK(up >= 0 && down >= 0);
    /* A tap of Volume Up: one step, from 60 % to 65 %, unmuted first. */
    struct input_event tap[] = {ev(EV_KEY, M17_KEY_VOLUMEUP, 1), ev(EV_SYN, SYN_REPORT, 0), ev(EV_KEY, M17_KEY_VOLUMEUP, 0),
                                ev(EV_SYN, SYN_REPORT, 0)};
    send_events(up, tap, 4);
    CHECK(wait_lines("vk/pactl.txt", 2, 5000));
    CHECK(!strcmp(slurp("vk/pactl.txt"), "set-sink-mute @DEFAULT_SINK@ 0\nset-sink-volume @DEFAULT_SINK@ 65%\n"));
    /* A tap of Volume Down: 60 % to 55 %. */
    struct input_event tap_down[] = {ev(EV_KEY, M17_KEY_VOLUMEDOWN, 1), ev(EV_KEY, M17_KEY_VOLUMEDOWN, 0)};
    send_events(down, tap_down, 2);
    CHECK(wait_lines("vk/pactl.txt", 3, 5000) && strstr(slurp("vk/pactl.txt"), "set-sink-volume @DEFAULT_SINK@ 55%\n"));
    /* Both: one screenshot of the whole screen into the pictures directory, with the session's bus. */
    struct input_event press_up[] = {ev(EV_KEY, M17_KEY_VOLUMEUP, 1)}, press_down[] = {ev(EV_KEY, M17_KEY_VOLUMEDOWN, 1)};
    send_events(up, press_up, 1);
    usleep(20000);
    send_events(down, press_down, 1);
    CHECK(wait_lines("vk/shot.txt", 1, 5000));
    char want[700];
    snprintf(want, sizeof want, "-f -s %s bus=unix:path=/run/m19/test-bus display=:0\n", at("vk/Pictures"));
    CHECK(!strcmp(slurp("vk/shot.txt"), want));
    struct stat st;
    CHECK(!stat(at("vk/Pictures"), &st) && S_ISDIR(st.st_mode));
    struct input_event release_up[] = {ev(EV_KEY, M17_KEY_VOLUMEUP, 0)}, release_down[] = {ev(EV_KEY, M17_KEY_VOLUMEDOWN, 0)};
    send_events(up, release_up, 1);
    send_events(down, release_down, 1);
    usleep(200000); /* both releases read before what follows on Volume Up's node */
    /* SYN_DROPPED forgets what was down. */
    struct input_event dropped[] = {ev(EV_KEY, M17_KEY_VOLUMEUP, 1), ev(EV_SYN, SYN_DROPPED, 0), ev(EV_KEY, M17_KEY_VOLUMEUP, 0)};
    send_events(up, dropped, 3);
    usleep(400000);
    /* The keys gone: the daemon says so and ends, for systemd to start it again. */
    close(up);
    close(down);
    int status = -1;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 1);
    const char *log = slurp("vk/keys.log");
    CHECK(strstr(log, " ready up=event0 down=event12\n") && strstr(log, " up volume=60->65 rc=0\n") && strstr(log, " down volume=60->55 rc=0\n"));
    CHECK(strstr(log, " shot pid=") && strstr(log, " keys lost\n"));
    unsigned steps = 0;
    for (const char *s = slurp("vk/pactl.txt"); (s = strstr(s, "set-sink-volume")); s++)
        steps++;
    CHECK(steps == 2);
    CHECK(strstr(slurp("vk/kmsg"), "<6>M17KEYS ready up=event0 down=event12\n"));
    /* No keys at all: it gives up after find_ms. */
    clean();
    mkdirs(at("vk/sys/class/input/x"));
    k.find_ms = 300;
    CHECK(m17_volkeys_main(&k) == 1 && strstr(slurp("vk/keys.log"), "keys missing up=-2 down=-2"));
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    snprintf(base, sizeof base, "%s/m17-g5-%d", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
    mkdir(base, 0755);
    test_vk();
    test_cmd();
    test_load();
    test_redact();
    test_write_log();
    test_native();
    test_session();
    test_volkeys();
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", base);
    if (system(cmd))
        failures++;
    if (failures) {
        fprintf(stderr, "M17 G5 tests: %d failed\n", failures);
        return 1;
    }
    printf("M17 G5 native runtime, loader, session and volume keys PASS\n");
    return 0;
}
