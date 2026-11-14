#!/usr/bin/env python3
"""Mutation check for M17: every mutant of scripts/m17/select.c, g3.c, selector.c, menu.c and modules.c must fail test.sh
(normal and ASan/UBSan)."""
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

MUTANTS = (
    # The boot mode: anything but a plain normal boot goes to Android.
    ('select.c', '    if (is(k, kn, "androidboot.mode")) return is(v, vn, "normal");', '    if (is(k, kn, "androidboot.mode")) return 1;'),
    ('select.c', '    if (is(k, kn, "androidboot.alarmboot")) return is(v, vn, "false") || is(v, vn, "0");',
     '    if (is(k, kn, "androidboot.alarmboot")) return 1;'),
    ('select.c', '        (*v)++;\n        *n -= 2;\n', ''),
    ('select.c', '            if (*s == \'"\') quoted = !quoted;\n', ''),
    ('select.c', '            while (v < ve && isspace((unsigned char)*v)) v++;\n', ''),
    ('select.c', '    return (!cmdline || cmdline_normal(cmdline)) && (!bootconfig || bootconfig_normal(bootconfig));',
     '    return (!cmdline || cmdline_normal(cmdline)) || (!bootconfig || bootconfig_normal(bootconfig));'),
    # The window: press edges only, Volume Up first, both means Android, a choice is final, the deadline.
    ('select.c', '        if (value) return decide(w, M17_ANDROID, M17_WHY_VOLUME_UP);\n', ''),
    ('select.c', 'return w->up_down ? decide(w, M17_ANDROID, M17_WHY_BOTH) : decide(w, M17_NATIVE, M17_WHY_VOLUME_DOWN);',
     'return decide(w, M17_NATIVE, M17_WHY_VOLUME_DOWN);'),
    ('select.c', '(value != 0 && value != 1)', '(value != 0 && value != 1 && value != 2)'),
    ('select.c', '    } else if (code == M17_KEY_VOLUMEDOWN && value == 1) {', '    } else if (code == M17_KEY_VOLUMEDOWN) {'),
    ('select.c', '    if (w->choice == M17_UNDECIDED && now_ms >= w->deadline_ms)', '    if (w->choice == M17_UNDECIDED && now_ms > w->deadline_ms)'),
    ('select.c', '    if (w->choice == M17_UNDECIDED) {\n        w->choice = choice;', '    if (1) {\n        w->choice = choice;'),
    # The keys: by exact name, one device only, the key in its bitmap, a character device when asked.
    ('select.c', '            strcmp(text, name))', '            strncmp(text, name, strlen(name)))'),
    ('select.c', '    if (matches > 1) return -EEXIST;\n', ''),
    ('select.c', '    return (int)((words[count - 1u - index] >> (code % 64u)) & 1u);', '    return (int)((words[index] >> (code % 64u)) & 1u);'),
    ('select.c', '        if (count == 16 || !isxdigit((unsigned char)*s)) return 0;', '        if (!isxdigit((unsigned char)*s)) return 0;'),
    ('select.c', '    if (require_chr && (fstat(fd, &st)', '    if (require_chr && 0 && (fstat(fd, &st)'),
    # The loop: no keys, no menu, broken or dropped events and a closed device all go to Android.
    ('select.c', '        m17_window_fail(w, M17_WHY_NO_KEYS);\n        goto out;\n', '        goto out;\n'),
    ('select.c', '    if (l->menu && l->menu(l->user, shown) < 0) {\n        m17_window_fail(w, M17_WHY_NO_MENU);\n        goto out;',
     '    if (l->menu && l->menu(l->user, shown) < 0) {\n        goto out;'),
    ('select.c', '            if (ev[i].type == EV_SYN && ev[i].code == SYN_DROPPED) return -1;\n', ''),
    ('select.c', 'if (ev[i].type == EV_KEY && ev[i].code == k->code && ', 'if (ev[i].type == EV_KEY && '),
    ('select.c', '        if (n == 0 || n % (ssize_t)sizeof ev[0]) return -1;', '        if (n == 0) return -1;'),
    ('select.c', '            else if (!(p[i].revents & POLLIN) && (p[i].revents & (POLLERR | POLLHUP | POLLNVAL))) m17_window_fail(w, M17_WHY_READ_ERROR);\n',
     ''),
    # G3 K1-keys: both modules in order, each wait its own, both keys pressed and released, edges only, the device's own
    # key, broken and dropped events, the selector's view, ambiguity named, no endless window without keys.
    ('g3.c', '    r->reboot_mode_rc = load_module(g, "reboot-mode.ko");\n', ''),
    ('g3.c', 'M17_KEY_VOLUMEDOWN, g->down_wait_ms, down_event);', 'M17_KEY_VOLUMEDOWN, g->up_wait_ms, down_event);'),
    ('g3.c', 'r->up_found && r->down_found && r->up_press && r->up_release && ', 'r->up_found && r->down_found && r->up_press && '),
    ('g3.c', 'r->down_press && r->down_release && !r->read_error;', 'r->down_press && !r->read_error;'),
    ('g3.c', 'r->down_press && r->down_release && !r->read_error;', 'r->down_press && r->down_release;'),
    ('g3.c', '            if (ev[i].value == 1) (*k->press)++;', '            if (ev[i].value >= 1) (*k->press)++;'),
    ('g3.c', '            if (ev[i].type != EV_KEY || ev[i].code != k->dev.code) continue;', '            if (ev[i].type != EV_KEY) continue;'),
    ('g3.c', '            if (ev[i].type == EV_SYN && ev[i].code == SYN_DROPPED) return -1;\n', ''),
    ('g3.c', '        if (n == 0 || n % (ssize_t)sizeof ev[0]) return -1;', '        if (n == 0) return -1;'),
    ('g3.c', '            (void)m17_window_tick(w, now);\n', ''),
    ('g3.c', '        if (rc == -EEXIST) {\n            say(g, "M17 G3 ambiguous %s", name);\n            return -1;\n        }\n', ''),
    ('g3.c', '        if (!count) break; /* no key at all: nothing to wait for */\n', ''),
    # G4 the selector: a normal boot needs mounts and a mode; the menu only when the keys are there, and closed only when
    # opened; native only with a native path; Android always after the early mounts are undone; undecided is Android.
    ('selector.c', '    r->normal = !m && !c && m17_normal_boot(cmdline, b ? NULL : bootconfig);',
     '    r->normal = !c && m17_normal_boot(cmdline, b ? NULL : bootconfig);'),
    ('selector.c', 'm17_normal_boot(cmdline, b ? NULL : bootconfig);', 'm17_normal_boot(cmdline, bootconfig);'),
    ('selector.c', '    r->keys = r->card && !o->wait_keys(o->user);', '    r->keys = !o->wait_keys(o->user);'),
    ('selector.c', '    if (r->menu) r->menu_closed = o->menu_close(o->user);', '    r->menu_closed = o->menu_close(o->user);'),
    ('selector.c', '    if (r->choice == M17_NATIVE && o->run_native) {', '    if (r->choice == M17_NATIVE) {'),
    ('selector.c', '    if (r->choice == M17_NATIVE) say(o, "M17SEL native-unavailable in this build: android");\n    return to_android(o);',
     '    if (r->choice == M17_NATIVE) say(o, "M17SEL native-unavailable in this build: android");\n    return o->exec_android(o->user);'),
    ('selector.c', '    r->choice = w.choice == M17_UNDECIDED ? M17_ANDROID : w.choice;', '    r->choice = w.choice;'),
    # The modules: options by canonical name and whole quoted words, a loaded module is no failure, no paths.
    ('modules.c', "out[j++] = in[i] == '-' ? '_' : in[i];", 'out[j++] = in[i];'),
    ('modules.c', '            if (*s == \'"\') quoted = !quoted;\n', ''),
    ('modules.c', '                if (rc == -EEXIST) (*already)++;\n                else if (rc) failed++;', '                if (rc) failed++;'),
    ('modules.c', ' || memchr(s, \'/\', len)) {', ') {'),
    # The menu: the bar as wide as the time left, Ubuntu's band only with a native path, glyphs the right way round,
    # nothing drawn outside the panel.
    ('menu.c', '    return (unsigned)((unsigned long long)M17_MENU_BAR_W * left_ms / total_ms);', '    return M17_MENU_BAR_W;'),
    ('menu.c', 'native_available ? M17_MENU_NATIVE : M17_MENU_BG', 'M17_MENU_NATIVE'),
    ('menu.c', 'if (g->rows[r] & (0x10u >> c))', 'if (g->rows[r] & (0x01u << c))'),
    ('menu.c', '    if (w > M17_MENU_W - x) w = M17_MENU_W - x;\n', ''),
)


def run(number, name, old, new):
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / 'm17'
        shutil.copytree(HERE, target, ignore=shutil.ignore_patterns('__pycache__'))
        path = target / name
        text = path.read_text(encoding='utf-8')
        assert text.count(old) == 1, f'mutant {number} does not apply exactly once to {name}: {old!r}'
        path.write_text(text.replace(old, new), encoding='utf-8', newline='\n')
        try:
            result = subprocess.run(['bash', str(target / 'test.sh'), str(Path(directory) / 'out')], stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=300, start_new_session=True, env=dict(os.environ, M17_STATIC='0'))
            return result.returncode != 0
        except subprocess.TimeoutExpired:
            return True


def main():
    with tempfile.TemporaryDirectory() as directory:
        check = subprocess.run(['bash', str(HERE / 'test.sh'), directory], stdin=subprocess.DEVNULL, capture_output=True, timeout=300,
                               env=dict(os.environ, M17_STATIC='0'))
        if check.returncode:
            print(check.stdout.decode('utf-8', 'replace') + check.stderr.decode('utf-8', 'replace'))
            raise SystemExit('the unmutated tests fail')
    survivors = []
    with concurrent.futures.ThreadPoolExecutor(max(1, min(4, os.cpu_count() or 1))) as pool:
        futures = {pool.submit(run, number, name, old, new): (number, name, old) for number, (name, old, new) in enumerate(MUTANTS, 1)}
        for future in concurrent.futures.as_completed(futures):
            number, name, old = futures[future]
            if not future.result():
                survivors.append((number, name, old))
    for number, name, old in sorted(survivors):
        print(f'SURVIVED {number} {name}: {old!r}')
    print(f'M17 mutants killed: {len(MUTANTS) - len(survivors)} of {len(MUTANTS)}')
    return 1 if survivors else 0


if __name__ == '__main__':
    sys.exit(main())
