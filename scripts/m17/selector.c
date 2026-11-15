/* M17 selector flow (selector.h). */
#include "selector.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

__attribute__((format(printf, 2, 3))) static void say(const struct m17_selector_ops *o, const char *format, ...) {
    char line[256];
    va_list a;
    va_start(a, format);
    vsnprintf(line, sizeof line, format, a);
    va_end(a);
    if (o->log) o->log(o->user, line);
}

static int to_android(const struct m17_selector_ops *o) {
    int u = o->unmount_early(o->user);
    say(o, "M17SEL android unmount=%d", u);
    return o->exec_android(o->user);
}

int m17_selector_run(const struct m17_selector_ops *o, struct m17_selector_result *r) {
    static char cmdline[4096], bootconfig[8192];
    memset(r, 0, sizeof *r);
    r->choice = M17_UNDECIDED;
    int m = o->mount_early(o->user);
    say(o, "M17SEL start mounts=%d", m);
    int c = o->read_cmdline(o->user, cmdline, sizeof cmdline), b = o->read_bootconfig(o->user, bootconfig, sizeof bootconfig);
    r->normal = !m && !c && m17_normal_boot(cmdline, b ? NULL : bootconfig);
    if (!r->normal) {
        r->choice = M17_ANDROID;
        r->why = M17_WHY_MODE;
        say(o, "M17SEL choice=android why=mode mounts=%d cmdline=%d bootconfig=%d", m, c, b);
        return to_android(o);
    }
    r->modules_failed = o->load_modules(o->user, cmdline);
    r->card = !o->wait_card(o->user);
    r->keys = r->card && !o->wait_keys(o->user);
    r->menu = r->keys && !o->menu_open(o->user);
    say(o, "M17SEL ready modules_failed=%d card=%d keys=%d menu=%d", r->modules_failed, r->card, r->keys, r->menu);
    struct m17_window w;
    m17_window_open(&w, 0, M17_WINDOW_MS, 0);
    if (!r->keys) m17_window_fail(&w, M17_WHY_NO_KEYS);
    else if (!r->menu) m17_window_fail(&w, M17_WHY_NO_MENU);
    else (void)o->window(o->user, &w);
    if (r->menu) r->menu_closed = o->menu_close(o->user);
    r->choice = w.choice == M17_UNDECIDED ? M17_ANDROID : w.choice;
    r->why = w.why;
    say(o, "M17SEL choice=%s why=%s menu_closed=%d", m17_choice_name(r->choice), m17_reason_name(r->why), r->menu_closed);
    if (r->choice == M17_NATIVE && o->run_native) {
        /* G5: native starts as Android would, from a root with nothing mounted (M19's init mounts its own). Only a failed
         * start returns, and then Android follows. */
        r->native_ran = 1;
        int u = o->unmount_early(o->user);
        say(o, "M17SEL native unmount=%d", u);
        int rc = o->run_native(o->user);
        say(o, "M17SEL native failed rc=%d: android", rc);
        return o->exec_android(o->user);
    }
    if (r->choice == M17_NATIVE) say(o, "M17SEL native-unavailable in this build: android");
    return to_android(o);
}
