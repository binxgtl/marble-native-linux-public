#!/usr/bin/env python3
"""M18's copies of M17's files (docs/m18-performance-polish.md, R1): each is its original with exact substitutions,
each of which must match the stated number of times. Nothing else differs.

  copies.py write    (re)writes every copy from its original
  copies.py check    fails unless every copy is exactly what write would produce
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HEAD_C = '/* M18 R1: {orig}, with the exact substitutions in scripts/m18/copies.py. */\n'

COPIES = {
    # No blue on a daily boot, and no green: colour only on failure (red, yellow).
    'scripts/m18/native.c': ('scripts/m17/native.c', [
        ('', HEAD_C.format(orig='scripts/m17/native.c'), 0),
        ('    show_blue(n);\n',
         '    if (n->blue_ms) /* M18 R1: a daily boot shows no blue (blue_ms 0) */\n        show_blue(n);\n', 1),
        ('    (void)paint(n, n->all_ok ? GREEN : YELLOW, n->final_ms);\n',
         '    if (!n->all_ok) /* M18 R1: colour on failure only; a PASS leaves the selector\'s panel as it is */\n'
         '        (void)paint(n, YELLOW, n->final_ms);\n', 1),
    ]),
    # No keypad at startup: without a CE unit the session starts none (the menu's entry opens it, scripts/m18/r1plan.py).
    'scripts/m18/session.c': ('scripts/m17/session.c', [
        ('', HEAD_C.format(orig='scripts/m17/session.c'), 0),
        ('        r->ce_rc = systemctl(s, "start", s->ce_unit, NULL, 0);\n',
         '        if (s->ce_unit) /* M18 R1: no CE unit, no keypad at startup */\n'
         '            r->ce_rc = systemctl(s, "start", s->ce_unit, NULL, 0);\n', 1),
    ]),
    'scripts/m18/native-main.c': ('scripts/m17/native-main.c', [
        ('', HEAD_C.format(orig='scripts/m17/native-main.c'), 0),
        ('.blue_ms = 3000,', '.blue_ms = 0,', 1),
        ('.ce_unit = "marble-ce.service",', '.ce_unit = NULL,', 1),
    ]),
    # The payload as a plain tar: the ramdisk is compressed already, and busybox's xz took the bootstrap's first second.
    'scripts/m18/native-bootstrap': ('scripts/m17/native-bootstrap', [
        ('#!/bin/busybox sh\n',
         '#!/bin/busybox sh\n# M18 R1: M17 G5\'s, with the payload a plain tar (scripts/m18/copies.py); the ramdisk is compressed already.\n', 1),
        ('/m19/payload.tar.xz', '/m19/payload.tar', 3),
        ('$BB tar -xJpf ', '$BB tar -xpf ', 1),
        # the old root stays in RAM for the whole session (the TEE island lives there): the 32 MB archive goes once unpacked
        ('$BB tar -xpf /m19/payload.tar -C / || hold payload-archive-extract\n',
         '$BB tar -xpf /m19/payload.tar -C / || hold payload-archive-extract\n$BB rm -f /m19/payload.tar || hold payload-archive-remove\n', 1),
    ]),
    # M17's single boot, for M18's candidates: its manifests and its reservation marker under m18.
    'scripts/m18/one-shot.ps1': ('scripts/m17/one-shot.ps1', [
        ('# M17: the single boot of a frozen G3 or later image (docs/m17-g3.md, docs/m17-g4.md).',
         '# M18: M17\'s single boot (scripts/m17/one-shot.ps1, with the substitutions in scripts/m18/copies.py), for a frozen M18 image.\n'
         '# M17: the single boot of a frozen G3 or later image (docs/m17-g3.md, docs/m17-g4.md).', 1),
        ("if($ManifestPath -notmatch '^manifests/m17-g[3-9][a-z]-candidate\\.json$'){throw 'Manifest must be a new g3a..g9z candidate'}",
         "if($ManifestPath -notmatch '^manifests/m18-r[1-9][a-z]-candidate\\.json$'){throw 'Manifest must be a new r1a..r9z candidate'}", 1),
        ('$marker=Join-Path $root "artifacts/m17/$($manifest.label)-candidate/execution-reserved.json"',
         '$marker=Join-Path $root "artifacts/m18/$($manifest.label)-candidate/execution-reserved.json"', 1),
    ]),
    # M17's tests on the copies: a PASS paints only blue, then (blue_ms 0) nothing; a session without a CE unit.
    'scripts/m18/test-r1.c': ('scripts/m17/test-g5.c', [
        ('', '/* M18 R1: scripts/m17/test-g5.c on M18\'s copies, with the exact substitutions in scripts/m18/copies.py. */\n', 0),
        ('    CHECK(wait_lines("nat/display.txt", 2, 3000) && !strcmp(slurp("nat/display.txt"), "000000ff 1\\n0000ff00 600000\\n"));\n',
         '    CHECK(wait_lines("nat/display.txt", 1, 3000) && !strcmp(slurp("nat/display.txt"), "000000ff 1\\n"));\n', 1),
        ('    CHECK(m17_native_main(&n) == M17_END_PASS && n.log_rc == -ENOENT && strstr(slurp("nat/kmsg"), "M17NAT log rc=-2"));\n'
         '    CHECK(wait_lines("nat/display.txt", 2, 3000));\n',
         '    CHECK(m17_native_main(&n) == M17_END_PASS && n.log_rc == -ENOENT && strstr(slurp("nat/kmsg"), "M17NAT log rc=-2"));\n'
         '    CHECK(wait_lines("nat/display.txt", 1, 3000) && !strcmp(slurp("nat/display.txt"), "000000ff 1\\n"));\n'
         '\n'
         '    /* M18 R1: blue_ms 0, the daily boot: a PASS paints nothing; a failure paints only its colour. */\n'
         '    n = native_bench("0", "0", ok, 5000);\n'
         '    n.blue_ms = 0;\n'
         '    CHECK(m17_native_main(&n) == M17_END_PASS && n.all_ok);\n'
         '    (void)poll(NULL, 0, 300);\n'
         '    CHECK(!exists("nat/display.txt"));\n'
         '    n = native_bench("0", "0", fails, 5000);\n'
         '    n.blue_ms = 0;\n'
         '    CHECK(m17_native_main(&n) == M17_END_NOT_PASS);\n'
         '    CHECK(wait_lines("nat/display.txt", 1, 3000) && !strcmp(slurp("nat/display.txt"), "00ffff00 600000\\n"));\n'
         '    n = native_bench("0", "3", ok, 5000);\n'
         '    n.blue_ms = 0;\n'
         '    CHECK(m17_native_main(&n) == M17_END_ADSP);\n'
         '    CHECK(wait_lines("nat/display.txt", 1, 3000) && !strcmp(slurp("nat/display.txt"), "00ff0000 600000\\n"));\n', 1),
        ('    CHECK(strstr(slurp("ses/m17-session.log"), "ce=none ce_seen=1") && !strstr(slurp("ses/m17-session.log"), "reboot"));\n',
         '    CHECK(strstr(slurp("ses/m17-session.log"), "ce=none ce_seen=1") && !strstr(slurp("ses/m17-session.log"), "reboot"));\n'
         '\n'
         '    /* M18 R1: no CE unit: no keypad started, nothing waited for, the session still passes. */\n'
         '    s = session_bench(1, "streaming", "M19_CE status=OK\\n");\n'
         '    s.ce_unit = NULL;\n'
         '    CHECK(m17_session_main(&s, &r) == 0 && r.ce_rc == -1 && !r.ce_seen && !strcmp(r.ce_status, "none"));\n'
         '    CHECK(!strstr(slurp("ses/calls.txt"), "marble-ce") && !exists("ses/ce.result"));\n'
         '    CHECK(strstr(slurp("ses/m17-session.log"), " ce_rc=-1\\n") && strstr(slurp("ses/m17-session.log"), "ce=none ce_seen=0 ce_s=0"));\n', 1),
        ('    printf("M17 ', '    printf("M18 R1 on M17\'s tests: M17 ', 1),
    ]),
}


def render(original, substitutions):
    text = (ROOT / original).read_text(encoding='utf-8')
    for old, new, count in substitutions:
        if old == '':
            text = new + text
            continue
        found = text.count(old)
        if found != count:
            raise SystemExit(f'{original}: {old[:60]!r} found {found} times, want {count}')
        text = text.replace(old, new)
    return text


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ''
    if mode not in ('write', 'check'):
        raise SystemExit(__doc__)
    bad = []
    for copy, (original, substitutions) in COPIES.items():
        want = render(original, substitutions)
        path = ROOT / copy
        if mode == 'write':
            path.write_text(want, encoding='utf-8', newline='\n')
        elif not path.is_file() or path.read_text(encoding='utf-8') != want:
            bad.append(copy)
    if bad:
        raise SystemExit(f'M18 copies differ from their originals plus substitutions: {bad}')
    print(f'M18 copies {"written" if mode == "write" else "PASS"}: {len(COPIES)}')


if __name__ == '__main__':
    main()
