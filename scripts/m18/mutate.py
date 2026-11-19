#!/usr/bin/env python3
"""Require each M18 mutant to fail the test suite that exercises its changed code."""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
M18 = ROOT / 'scripts/m18'

C_SUITES = {'native.c': 'native', 'session.c': 'native', 'bye.c': 'spinner', 'shutdown-trace.c': 'shutdown-trace'}
PYTHON_CASES = {
    'ce-ready': ('test-r1.py', 'CeReady'),
    'ce-done': ('test-r1.py', 'CeDone'),
    'perf-recorder': ('test-r1.py', 'Recorder'),
    'boot-analyze': ('test-r1.py', 'Analyze'),
    'governor': ('test-r2.py', 'Governor'),
    'thermal': ('test-r2.py', 'Thermal'),
    'mark': ('test-r3.py', 'Mark'),
    'plan_r3b.py': ('test-r3.py', 'Plan.test_r3b_only_changes_shutdown_observation'),
}

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
    ('ce-ready', '>>"$LIB/m18-ce.log" 2>/dev/null || :', '>/dev/null 2>/dev/null || :'),
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
    # R2 governor: walt first, then schedutil, never anything else; the read-back decides; walt's tunables recorded
    ('governor', '  for g in walt schedutil; do', '  for g in schedutil walt; do'),
    ('governor', '  for g in walt schedutil; do', '  for g in walt schedutil performance; do'),
    ('governor', '  [ "$now" = "$want" ] || rc=1', '  :'),
    ('governor', '    rc=1\n    continue', '    continue'),
    ('governor', 'for f in hispeed_freq hispeed_load target_load_thresh', 'for f in hispeed_freq target_load_thresh'),
    # R2 thermal: load once, a failed load fails the unit, only numbers count as readable
    ('thermal', "if ! grep -q '^qcom_tsens ' \"$PROC/modules\" 2>/dev/null; then", 'if true; then'),
    ('thermal', '    loaded=failed\n    rc=1', '    loaded=failed'),
    ('thermal', "    ''|*[!0-9]*) ;;", "    '') ;;"),
    ('thermal', '  digits=${t#-}', '  digits=$t'),
    ('thermal', 'zones=$((zones + 1))', 'zones=$((zones + 0))'),
    # R3 spinner: the head, its trail and floor, the clear, the dots' shape and bounds, the timeline's file
    ('bye.c', 'const unsigned head = (frame / M18_BYE_STEP_FRAMES) % M18_BYE_DOTS;', 'const unsigned head = frame % M18_BYE_DOTS;'),
    ('bye.c', 'const int level = 255 - 20 * (int)behind;', 'const int level = 255 - 10 * (int)behind;'),
    ('bye.c', 'return (uint32_t)(level < 40 ? 40 : level);', 'return (uint32_t)(level < 0 ? 0 : level);'),
    ('bye.c', '(head + M18_BYE_DOTS - dot % M18_BYE_DOTS) % M18_BYE_DOTS', '(dot % M18_BYE_DOTS + M18_BYE_DOTS - head) % M18_BYE_DOTS'),
    ('bye.c', 'if (!pixels || !width || !height || pitch < width)', 'if (!pixels || !width || !height)'),
    ('bye.c', '        memset(pixels + (size_t)y * pitch + x0, 0, (size_t)(x1 - x0) * sizeof(uint32_t));\n', ''),
    ('bye.c', 'if (ex * ex + ey * ey <= r * r)', 'if (ex * ex + ey * ey < r * r)'),
    ('bye.c', '            if (x < 0 || x >= (int)width)\n                    continue;\n', ''),
    ('bye.c', 'const int box = (int)(M18_BYE_RING + M18_BYE_DOT + 2);', 'const int box = (int)(M18_BYE_RING);'),
    ('bye.c', 'O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC', 'O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC'),
    ('bye.c', 'O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600', 'O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644'),
    # R3 mark: filtered, appended, never failing
    ('mark', "| tr -cd 'A-Za-z0-9-')", ')'),
    ('mark', '>>"$LIB/m18-shutdown.log" 2>/dev/null || :', '>"$LIB/m18-shutdown.log" 2>/dev/null || :'),
    ('mark', '"${word:-none}"', '"$word"'),
    # R3b: shutdown orders a stop, keeps the first log private, and filters the process list.
    ('plan_r3b.py', 'Conflicts=shutdown.target', 'Conflicts=unused.target'),
    ('plan_r3b.py', 'umask 077', 'umask 022'),
    ('shutdown-trace.c', '#define PF_KTHREAD 0x00200000u', '#define PF_KTHREAD 0u'),
    ('shutdown-trace.c', 'pid <= 1 || pid == spinner', 'pid <= 1 || pid == spinner + 1'),
    # boot-analyze: waits for the start, keeps the previous boot's account
    ('boot-analyze', 'running|degraded) break;;', 'nothing) break;;'),
    ('boot-analyze', '  mv -f "$LOG" "$LOG.1"', '  rm -f "$LOG"'),
    ('boot-analyze', '$ANALYZE critical-chain --no-pager', '$ANALYZE critical-chain'),
]


def test_command(name, out):
    if name in C_SUITES:
        return ('bash', str(M18 / 'test.sh'), out, 'normal', C_SUITES[name])
    script, test_case = PYTHON_CASES[name]
    # Equal-length source mutations can otherwise reuse an imported module's baseline bytecode.
    return (sys.executable, '-B', '-X', f'pycache_prefix={Path(out) / "pycache"}', str(M18 / script), test_case)


def main():
    survived = []
    with tempfile.TemporaryDirectory() as out:
        commands = {name: test_command(name, out) for name, _, _ in MUTANTS}
        for command in sorted(set(commands.values())):
            base = subprocess.run(command, capture_output=True, text=True, timeout=90)
            if base.returncode:
                sys.exit(f'unmutated test failed: {command}\n' + base.stdout[-3000:] + base.stderr[-3000:])
        for i, (name, old, new) in enumerate(MUTANTS, 1):
            path = M18 / name
            text = path.read_text(encoding='utf-8')
            if text.count(old) != 1:
                sys.exit(f'mutant {i} ({name}): {old[:50]!r} found {text.count(old)} times')
            path.write_text(text.replace(old, new), encoding='utf-8', newline='\n')
            try:
                r = subprocess.run(commands[name], capture_output=True, text=True, timeout=90)
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
