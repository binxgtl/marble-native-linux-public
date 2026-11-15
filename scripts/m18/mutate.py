#!/usr/bin/env python3
"""M18 R1: every mutant of M18's own logic must fail test.sh (normal build, no static binaries, the copies check off
because the mutants change the copies on purpose). The daily values themselves (blue_ms 0, no CE unit, the plain tar)
are pinned by the copies' substitutions and test-r1.py, not by mutants."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
M18 = ROOT / 'scripts/m18'

MUTANTS = [
    # native.c: no blue when blue_ms is 0; colour on failure only
    ('native.c', '    if (n->blue_ms) /* M18 R1', '    if (1) /* M18 R1'),
    ('native.c', '    if (!n->all_ok) /* M18 R1', '    if (1) /* M18 R1'),
    ('native.c', '        (void)paint(n, YELLOW, n->final_ms);', '        (void)paint(n, n->all_ok ? GREEN : YELLOW, n->final_ms);\n        (void)paint(n, YELLOW, n->final_ms);'),
    # session.c: no CE unit, no keypad
    ('session.c', '        if (s->ce_unit) /* M18 R1', '        if (1) /* M18 R1'),
    # ce-ready: the boot's broker only with its socket; the island by both of its marks; a stale socket replaced; the wait
    ('ce-ready', '      if [ -S "$sock" ]; then', '      if :; then'),
    ('ce-ready', '        exit 0\n      fi;;', '        :\n      fi;;'),
    ('ce-ready', '"/m19/m19-ce broker /m19-ce/ce.sock "*)', '*m19-ce*)'),
    ('ce-ready', 'if [ -f "$p/root/m19/m19-ce" ] && [ -d "$p/root/m19-ce" ]; then', 'if [ -d "$p/root" ]; then'),
    ('ce-ready', 'if [ -f "$p/root/m19/m19-ce" ] && [ -d "$p/root/m19-ce" ]; then', 'if [ -f "$p/root/m19/m19-ce" ]; then'),
    ('ce-ready', '  rm -f "$sock"\n', ''),
    ('ce-ready', 'if [ -z "$island" ]; then', 'if false; then'),
    ('ce-ready', '    say "broker=none why=no-socket"\n    exit 1', '    say "broker=none why=no-socket"\n    exit 0'),
    ('ce-ready', ' /m19/m19-ce broker /m19-ce/ce.sock \\\n', ' /m19/m19-ce broker /m19-ce/other.sock \\\n'),
    # ce-done: hide only once unlocked, the status line filtered, recorded
    ('ce-done', '  "M19_CE status=OK"*)', '  "M19_CE status="*)'),
    ('ce-done', "sed -i 's/^NoDisplay=false$/NoDisplay=true/'", "sed -i 's/^NoDisplay=true$/NoDisplay=false/'"),
    ('ce-done', " | tr -cd 'A-Za-z0-9_=. -')", ')'),
    ('ce-done', '>>"$LIB/m18-ce.log"', '>"$LIB/m18-ce.log"'),
    # perf-recorder: what each line holds, the rotation, the count
    ('perf-recorder', '$(value "$p/scaling_governor")', '-'),
    ('perf-recorder', '$(value "$z/temp")', '0'),
    ('perf-recorder', '$(value "$b/current_now")', '$(value "$b/voltage_now")'),
    ('perf-recorder', '"$(wc -c <"$LOG")" -ge "$LIMIT"', '"$(wc -c <"$LOG")" -ge 999999999'),
    ('perf-recorder', '[ "$n" -ge "$COUNT" ]', '[ "$n" -gt "$COUNT" ]'),
    ('perf-recorder', "grep -m 1 '^MemAvailable:'", "grep -m 1 '^MemFree:'"),
    # boot-analyze: waits for the start, keeps the previous boot's account
    ('boot-analyze', 'running|degraded) break;;', 'nothing) break;;'),
    ('boot-analyze', '  mv -f "$LOG" "$LOG.1"', '  rm -f "$LOG"'),
    ('boot-analyze', '$ANALYZE critical-chain --no-pager', '$ANALYZE critical-chain'),
]


def main():
    survived = []
    with tempfile.TemporaryDirectory() as out:
        env = {**os.environ, 'M18_STATIC': '0', 'M18_COPIES': '0'}
        base = subprocess.run(['bash', str(M18 / 'test.sh'), out, 'normal'], env=env, capture_output=True, text=True)
        if base.returncode:
            sys.exit('the unmutated tests fail:\n' + base.stdout[-3000:] + base.stderr[-3000:])
        for i, (name, old, new) in enumerate(MUTANTS, 1):
            path = M18 / name
            text = path.read_text(encoding='utf-8')
            if text.count(old) != 1:
                sys.exit(f'mutant {i} ({name}): {old[:50]!r} found {text.count(old)} times')
            path.write_text(text.replace(old, new), encoding='utf-8', newline='\n')
            try:
                r = subprocess.run(['bash', str(M18 / 'test.sh'), out, 'normal'], env=env, capture_output=True, text=True, timeout=600)
            finally:
                path.write_text(text, encoding='utf-8', newline='\n')
            if r.returncode == 0:
                survived.append(f'{i} {name}: {old[:60]!r}')
    for s in survived:
        print('SURVIVED', s)
    print(f'M18 mutants killed: {len(MUTANTS) - len(survived)} of {len(MUTANTS)}')
    sys.exit(1 if survived else 0)


if __name__ == '__main__':
    main()
