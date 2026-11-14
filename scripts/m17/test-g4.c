/* M17 G4: the selector's menu drawing, its module options and list, and its flow behind fake operations. No device.
 * Run under ASan/UBSan too (test.sh). */
#define _GNU_SOURCE
#include "kms.h"
#include "menu.h"
#include "modules.h"
#include "selector.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);                                   \
            failures++;                                                                                                \
        }                                                                                                              \
    } while (0)

/* ---- The menu ---- */

static uint32_t px(const uint32_t *p, unsigned x, unsigned y) {
    return p[(size_t)y * M17_MENU_W + x];
}

static void test_menu(void) {
    uint32_t *p = malloc((size_t)M17_MENU_W * M17_MENU_H * 4u);
    CHECK(p != NULL);
    m17_menu_draw(p, M17_MENU_W, 10000, 10000, 1);
    CHECK(px(p, 0, 0) == M17_MENU_BG && px(p, M17_MENU_W - 1, M17_MENU_H - 1) == M17_MENU_BG);
    /* Android's band, Ubuntu's band, and a full bar. */
    CHECK(px(p, 95, 705) == M17_MENU_ANDROID && px(p, 95, 1255) == M17_MENU_NATIVE);
    CHECK(px(p, M17_MENU_BAR_X, M17_MENU_BAR_Y) == M17_MENU_BAR && px(p, M17_MENU_BAR_X + M17_MENU_BAR_W - 1, M17_MENU_BAR_Y) == M17_MENU_BAR);
    CHECK(px(p, M17_MENU_BAR_X + M17_MENU_BAR_W, M17_MENU_BAR_Y) == M17_MENU_BG);
    /* Text is drawn in the bands: some text-coloured pixel inside each. */
    unsigned text_android = 0, text_native = 0, text_seconds = 0;
    for (unsigned y = 700; y < 1100; y++)
        for (unsigned x = 90; x < 990; x++) text_android += px(p, x, y) == M17_MENU_TEXT;
    for (unsigned y = 1250; y < 1650; y++)
        for (unsigned x = 90; x < 990; x++) text_native += px(p, x, y) == M17_MENU_TEXT;
    for (unsigned y = 1820; y < 1820 + 7 * 16; y++)
        for (unsigned x = 0; x < M17_MENU_W; x++) text_seconds += px(p, x, y) == M17_MENU_TEXT;
    CHECK(text_android > 1000 && text_native > 1000 && text_seconds > 1000);
    /* "10" is two glyphs: wider than "3". */
    unsigned ten = text_seconds;
    m17_menu_draw(p, M17_MENU_W, 2500, 10000, 1);
    text_seconds = 0;
    for (unsigned y = 1820; y < 1820 + 7 * 16; y++)
        for (unsigned x = 0; x < M17_MENU_W; x++) text_seconds += px(p, x, y) == M17_MENU_TEXT;
    CHECK(text_seconds > 0 && text_seconds < ten);
    /* A quarter of the time: a quarter of the bar. */
    CHECK(px(p, M17_MENU_BAR_X + M17_MENU_BAR_W / 4 - 2, M17_MENU_BAR_Y + 1) == M17_MENU_BAR);
    CHECK(px(p, M17_MENU_BAR_X + M17_MENU_BAR_W / 4 + 2, M17_MENU_BAR_Y + 1) == M17_MENU_BG);
    /* No native path in this build: Ubuntu's band is not lit. */
    m17_menu_draw(p, M17_MENU_W, 10000, 10000, 0);
    CHECK(px(p, 95, 1255) == M17_MENU_BG);
    CHECK(m17_menu_bar_width(10000, 10000) == M17_MENU_BAR_W && m17_menu_bar_width(20000, 10000) == M17_MENU_BAR_W);
    CHECK(m17_menu_bar_width(0, 10000) == 0 && m17_menu_bar_width(5000, 0) == 0 && m17_menu_bar_width(5000, 10000) == M17_MENU_BAR_W / 2);
    /* A glyph's pixels where they belong: 'I' at (0,0) scale 1 lights (1,0),(2,0),(3,0) and (2,3), not (0,3). */
    memset(p, 0, (size_t)M17_MENU_W * 8u * 4u);
    m17_menu_text(p, M17_MENU_W, 0, 0, 1, 7, "I?");
    CHECK(px(p, 1, 0) == 7 && px(p, 2, 0) == 7 && px(p, 3, 0) == 7 && px(p, 0, 0) == 0 && px(p, 2, 3) == 7 && px(p, 0, 3) == 0);
    CHECK(px(p, 6, 0) == 0 && px(p, 8, 3) == 0); /* '?' is blank */
    /* 'L' is not symmetric: its column is the left one. */
    memset(p, 0, (size_t)M17_MENU_W * 8u * 4u);
    m17_menu_text(p, M17_MENU_W, 0, 0, 1, 7, "L");
    CHECK(px(p, 0, 0) == 7 && px(p, 4, 0) == 0 && px(p, 4, 6) == 7);
    /* Clipping: text at the panel's edge writes nothing outside it. */
    m17_menu_text(p, M17_MENU_W, M17_MENU_W - 3, M17_MENU_H - 3, 10, 7, "W");
    free(p);
}

/* ---- Module options and the list ---- */

static char loads[2048];
static int fail_eexist, fail_other;
static int load(const char *path, const char *params) {
    char item[600];
    snprintf(item, sizeof item, "%s[%s];", strrchr(path, '/') + 1, params);
    strncat(loads, item, sizeof loads - strlen(loads) - 1);
    if (fail_eexist && strstr(path, "qcom-pon.ko")) return -EEXIST;
    if (fail_other && strstr(path, "msm_drm.ko")) return -ENOENT;
    return 0;
}

static void test_modules(void) {
    char out[256];
    const char *cmdline = "console=ttyMSM0 msm_drm.dsi_display0=qcom,mdss_dsi_m16t_36_0d_0b_dsc_vid msm-drm.x=1 "
                          "qcom_pon.a=\"b c\" qcom-pon.d=2 msm_drmx.y=3 msm_drm. .z=1 msm_drm=4 androidboot.mode=normal";
    CHECK(!m17_module_params(cmdline, "msm_drm.ko", out, sizeof out) && !strcmp(out, "dsi_display0=qcom,mdss_dsi_m16t_36_0d_0b_dsc_vid x=1"));
    CHECK(!m17_module_params(cmdline, "/lib/modules/qcom-pon.ko", out, sizeof out) && !strcmp(out, "a=\"b c\" d=2"));
    CHECK(!m17_module_params(cmdline, "gpi.ko", out, sizeof out) && !strcmp(out, ""));
    CHECK(!m17_module_params(NULL, "gpi.ko", out, sizeof out) && !strcmp(out, ""));
    CHECK(m17_module_params(cmdline, "msm_drm.ko", out, 10) == -ENAMETOOLONG);

    struct m17_modules m = {.dir = "/lib/modules", .cmdline = "msm_drm.dsi_display0=p qcom_pon.q=1", .load = load};
    unsigned loaded, already;
    loads[0] = 0;
    CHECK(m17_load_modules(&m, "# the list\nspmi-pmic-arb.ko\n\nmsm_drm.ko\r\nqcom-pon.ko\nbad/name.ko\n", &loaded, &already) == 1);
    CHECK(loaded == 3 && already == 0);
    CHECK(!strcmp(loads, "spmi-pmic-arb.ko[];msm_drm.ko[dsi_display0=p];qcom-pon.ko[q=1];"));
    loads[0] = 0;
    fail_eexist = 1;
    fail_other = 1;
    CHECK(m17_load_modules(&m, "msm_drm.ko\nqcom-pon.ko", &loaded, &already) == 1 && loaded == 0 && already == 1);
    fail_eexist = fail_other = 0;
}

/* ---- The flow ---- */

struct fake {
    char calls[512];
    char log[2048];
    int mount_rc, cmdline_rc, bootconfig_rc, modules_failed, card_rc, keys_rc, menu_rc, close_rc, exec_rc;
    const char *cmdline, *bootconfig;
    enum m17_choice choice;
    enum m17_reason why;
    int native;
};

static void call(struct fake *f, const char *name) {
    strncat(f->calls, name, sizeof f->calls - strlen(f->calls) - 2);
    strcat(f->calls, ",");
}
static void f_log(void *u, const char *line) {
    struct fake *f = u;
    strncat(f->log, line, sizeof f->log - strlen(f->log) - 2);
    strcat(f->log, "\n");
}
static int f_mount(void *u) { call(u, "mount"); return ((struct fake *)u)->mount_rc; }
static int f_cmdline(void *u, char *b, unsigned room) {
    struct fake *f = u;
    call(f, "cmdline");
    snprintf(b, room, "%s", f->cmdline ? f->cmdline : "");
    return f->cmdline_rc;
}
static int f_bootconfig(void *u, char *b, unsigned room) {
    struct fake *f = u;
    call(f, "bootconfig");
    /* A failed read leaves a charger mode behind: the selector must not read it. */
    snprintf(b, room, "%s", f->bootconfig_rc ? "androidboot.mode = \"charger\"\n" : f->bootconfig ? f->bootconfig : "");
    return f->bootconfig_rc;
}
static int f_modules(void *u, const char *cmdline) { (void)cmdline; call(u, "modules"); return ((struct fake *)u)->modules_failed; }
static int f_card(void *u) { call(u, "card"); return ((struct fake *)u)->card_rc; }
static int f_keys(void *u) { call(u, "keys"); return ((struct fake *)u)->keys_rc; }
static int f_menu(void *u) { call(u, "menu"); return ((struct fake *)u)->menu_rc; }
static enum m17_choice f_window(void *u, struct m17_window *w) {
    struct fake *f = u;
    call(f, "window");
    if (f->choice == M17_UNDECIDED) return w->choice;
    w->choice = f->choice;
    w->why = f->why;
    return w->choice;
}
static int f_close(void *u) { call(u, "close"); return ((struct fake *)u)->close_rc; }
static int f_unmount(void *u) { call(u, "unmount"); return 0; }
static int f_exec(void *u) { call(u, "android"); return ((struct fake *)u)->exec_rc; }
static int f_native(void *u) { call(u, "native"); return -2; }

static int flow(struct fake *f, struct m17_selector_result *r) {
    struct m17_selector_ops o = {.user = f, .log = f_log, .mount_early = f_mount, .read_cmdline = f_cmdline, .read_bootconfig = f_bootconfig,
                                 .load_modules = f_modules, .wait_card = f_card, .wait_keys = f_keys, .menu_open = f_menu, .window = f_window,
                                 .menu_close = f_close, .unmount_early = f_unmount, .exec_android = f_exec,
                                 .run_native = f->native ? f_native : NULL};
    return m17_selector_run(&o, r);
}

static struct fake fresh(void) {
    struct fake f;
    memset(&f, 0, sizeof f);
    f.cmdline = "msm_drm.dsi_display0=x androidboot.mode=normal";
    f.bootconfig = "androidboot.mode = \"normal\"\n";
    f.choice = M17_UNDECIDED;
    f.exec_rc = -ENOENT;
    return f;
}

static void test_flow(void) {
    struct m17_selector_result r;
    struct fake f;

    /* The window times out: the menu is closed before Android. */
    f = fresh();
    f.choice = M17_ANDROID;
    f.why = M17_WHY_TIMEOUT;
    CHECK(flow(&f, &r) == -ENOENT);
    CHECK(!strcmp(f.calls, "mount,cmdline,bootconfig,modules,card,keys,menu,window,close,unmount,android,"));
    CHECK(r.normal && r.card && r.keys && r.menu && r.choice == M17_ANDROID && r.why == M17_WHY_TIMEOUT && !r.native_ran);
    CHECK(strstr(f.log, "M17SEL choice=android why=timeout menu_closed=0"));

    /* Not a normal boot: nothing loaded, nothing shown. */
    f = fresh();
    f.bootconfig = "androidboot.mode = \"charger\"\n";
    flow(&f, &r);
    CHECK(!strcmp(f.calls, "mount,cmdline,bootconfig,unmount,android,") && !r.normal && r.why == M17_WHY_MODE);
    f = fresh();
    f.cmdline = "androidboot.alarmboot=true";
    flow(&f, &r);
    CHECK(!strcmp(f.calls, "mount,cmdline,bootconfig,unmount,android,") && r.why == M17_WHY_MODE);
    /* No bootconfig at all is fine; no command line, or failed mounts, are not. */
    f = fresh();
    f.bootconfig_rc = -ENOENT;
    f.choice = M17_ANDROID;
    f.why = M17_WHY_VOLUME_UP;
    flow(&f, &r);
    CHECK(r.normal && strstr(f.calls, "window"));
    f = fresh();
    f.cmdline_rc = -ENOENT;
    flow(&f, &r);
    CHECK(!r.normal && !strstr(f.calls, "modules"));
    f = fresh();
    f.mount_rc = -EBUSY;
    flow(&f, &r);
    CHECK(!r.normal && !strcmp(f.calls, "mount,cmdline,bootconfig,unmount,android,"));

    /* No card, no keys, no menu: Android, and only an opened menu is closed. */
    f = fresh();
    f.card_rc = -1;
    flow(&f, &r);
    CHECK(!strcmp(f.calls, "mount,cmdline,bootconfig,modules,card,unmount,android,") && r.why == M17_WHY_NO_KEYS);
    f = fresh();
    f.keys_rc = -1;
    flow(&f, &r);
    CHECK(!strcmp(f.calls, "mount,cmdline,bootconfig,modules,card,keys,unmount,android,") && r.why == M17_WHY_NO_KEYS);
    f = fresh();
    f.menu_rc = -1;
    flow(&f, &r);
    CHECK(!strcmp(f.calls, "mount,cmdline,bootconfig,modules,card,keys,menu,unmount,android,") && r.why == M17_WHY_NO_MENU);
    /* Failed modules are logged and the selector goes on. */
    f = fresh();
    f.modules_failed = 2;
    f.choice = M17_ANDROID;
    f.why = M17_WHY_VOLUME_UP;
    flow(&f, &r);
    CHECK(r.modules_failed == 2 && strstr(f.calls, "window") && strstr(f.log, "modules_failed=2"));

    /* Volume Down without a native path in this build: still Android, after the menu is closed. */
    f = fresh();
    f.choice = M17_NATIVE;
    f.why = M17_WHY_VOLUME_DOWN;
    flow(&f, &r);
    CHECK(!strcmp(f.calls, "mount,cmdline,bootconfig,modules,card,keys,menu,window,close,unmount,android,"));
    CHECK(r.choice == M17_NATIVE && !r.native_ran && strstr(f.log, "native-unavailable"));
    /* With one (G5): the early mounts undone, then native; a native start that returns (it failed) goes to Android. */
    f = fresh();
    f.native = 1;
    f.choice = M17_NATIVE;
    f.why = M17_WHY_VOLUME_DOWN;
    flow(&f, &r);
    CHECK(!strcmp(f.calls, "mount,cmdline,bootconfig,modules,card,keys,menu,window,close,unmount,native,android,") && r.native_ran);
    CHECK(strstr(f.log, "M17SEL native unmount=0") && strstr(f.log, "M17SEL native failed rc=-2: android"));

    /* An unverified teardown is recorded, and Android still follows. */
    f = fresh();
    f.close_rc = M17_KMS_UNSAFE_ROLLBACK;
    f.choice = M17_ANDROID;
    f.why = M17_WHY_VOLUME_UP;
    flow(&f, &r);
    CHECK(r.menu_closed == M17_KMS_UNSAFE_ROLLBACK && strstr(f.calls, "close,unmount,android") && strstr(f.log, "menu_closed=2"));
    /* G4b: the panel handed on lit with a black frame is recorded, and Android follows. */
    f = fresh();
    f.close_rc = M17_KMS_LIT_BLACK;
    f.choice = M17_ANDROID;
    f.why = M17_WHY_TIMEOUT;
    flow(&f, &r);
    CHECK(r.menu_closed == M17_KMS_LIT_BLACK && strstr(f.calls, "close,unmount,android") && strstr(f.log, "menu_closed=3"));
    /* A window that returns undecided still ends in Android. */
    f = fresh();
    flow(&f, &r);
    CHECK(r.choice == M17_ANDROID && strstr(f.calls, "android"));
}

int main(void) {
    test_menu();
    test_modules();
    test_flow();
    if (failures) {
        fprintf(stderr, "M17 G4 tests: %d failed\n", failures);
        return 1;
    }
    printf("M17 G4 tests PASS\n");
    return 0;
}
