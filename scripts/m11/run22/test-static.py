#!/usr/bin/env python3
"""Run22 static structure checks (text-level evidence; the control-flow test executes the
runner itself). Each Run22 shell input must differ from its origin only as intended."""
import difflib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
M11 = ROOT / 'scripts/m11'
R22 = M11 / 'run22'
fails = []

def check(cond, what):
    print(('PASS ' if cond else 'FAIL ') + what)
    if not cond:
        fails.append(what)

def code(path):
    text = path.read_text()
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', text)

def changed(a, b):
    """Lines removed from a and added in b."""
    la, lb = a.read_text().splitlines(), b.read_text().splitlines()
    d = list(difflib.unified_diff(la, lb, lineterm='', n=0))
    rem = [x[1:] for x in d if x.startswith('-') and not x.startswith('---')]
    add = [x[1:] for x in d if x.startswith('+') and not x.startswith('+++')]
    return rem, add

runner = code(R22 / 'runner.c')
main = runner[runner.index('int main('):]
def pos(text):
    i = main.find(text)
    assert i >= 0, text
    return i

# Runner structure.
check(pos('fatal_handlers()') < pos('umask(077)') < pos('job("/m11/prepare"'),
      'runner: fatal-signal hold handlers installed before any job')
check('host.receipt' not in runner and 'receipt()' not in runner,
      'runner: no host-receipt gate (receive-only observer)')
check(pos('job("/m11/control","usb_start"') < pos('amp_gate()') < pos('m11_spawner_start(') <
      pos('endpoint()') < pos('m11_audio_bind_endpoint(r,dev)'),
      'runner: amp gate after USB start, before the spawner, the endpoint node and the bind')
gate = runner[runner.index('static int amp_gate(void)'):]
gate = gate[:gate.index('\n}\n')]
check('strcmp(result,"switches-disabled\\n")' in gate and 'job("/m11/control","amp_gate"' in gate,
      'runner: only switches-disabled admits the GPR query')
check(pos('m11_audio_start_pd(') < pos('if (!pdrc) {') < pos('m11_anchor_bind(') <
      pos('m11_anchor_owner_seal(') < pos('m11_audio_attach_anchor('),
      'runner: anchor bind only after PDR UP, sealed at once')
seal = pos('m11_anchor_owner_seal(')
check(not re.search(r'\bjob\(|\bfork\(|\bexecl\(', main[seal:]),
      'runner: no job()/fork()/execl() by PID1 after the seal')
check(pos('m11_anchor_final_close(') < pos('m11_audio_retire(r)') < pos('spawned(JOB_CONTROL,"stop_adsp"'),
      'runner: final close before retire and stop_adsp')
check(pos('m11_anchor_end_boot(') < pos('reboot(RB_AUTOBOOT)'), 'runner: reboot only after end_boot')
crumbs = re.findall(r'crumb\("([a-z_]+)"\)', main)
check(len(crumbs) >= 30 and len(set(crumbs)) == len(crumbs), f'runner: {len(crumbs)} distinct phase breadcrumbs')
handler = runner[runner.index('static void fatal('):runner.index('static int fatal_handlers(')]
check(not re.search(r'\b(printf|snprintf|malloc|record|hold)\(', handler),
      'runner: fatal handler uses async-signal-safe calls only')
check('/dev/snd' not in runner and 'aud_pasthru' not in code(R22 / 'control'),
      'runner/control: no /dev/snd, control never names the endpoint')

# Shell inputs: origin + intended changes only.
rem, add = changed(M11 / 'next/control', R22 / 'control')
check(len(rem) == 1 and rem[0].startswith('# ') and
      sorted(a for a in add if not a.lstrip().startswith('#')) ==
      sorted(['  ;;', ' amp_gate)', '  . /m11/amp-gate', '  amp_gate']),
      'control: next/control plus the amp_gate action only')
rem, add = changed(M11 / 'next/usb', R22 / 'usb')
code_add = [a for a in add if not a.lstrip().startswith('#')]
check(all('M11R22' in a or 'm11r22' in a or 'Run 22' in a or a.strip() == '$BB sleep 3 || return 1' for a in code_add)
      and all(r.lstrip().startswith('#') or 'm11next' in r or 'M11NEXT' in r or 'engineering' in r for r in rem),
      'usb: next/usb with the Run22 identity and the 3 s observer grace only')
rem, add = changed(M11 / 'run16/init', R22 / 'init')
check(len(rem) == 3 and all('16' in r for r in rem) and all('22' in a for a in add),
      'init: run16/init with Run22 names only')
gatesh = (R22 / 'amp-gate').read_text()
snap = lambda t: re.search(r'^amp_snapshot\(\) \{.*?^\}', t, re.S | re.M).group(0)
check(snap(gatesh) == snap((M11 / 'run16/prepare').read_text()),
      'amp-gate: amp_snapshot byte-identical to run16/prepare (and run19/bootstrap)')
reg = (M11 / 'run19/registration').read_text()
for pred in ('/ukee-mtp-snd-card/ && $1 ~ /^[0-9]+$/ {print $1}', '"^${prefix}.*playback" /proc/asound/pcm',
             '"^${prefix}.*capture" /proc/asound/pcm', '[ "$stable" -lt 5 ]', '[ "$i" -lt 300 ]',
             '[ "$amp_state" = both ]', '. /m11/amp-switch', 'amp_switch_stage', 'result=$switch_result'):
    check(pred in gatesh and pred in reg, f'amp-gate: Run19 registration predicate kept: {pred}')
gate_code = '\n'.join(l for l in gatesh.splitlines() if not l.lstrip().startswith('#'))
check('mknod' not in gate_code and '/dev/snd' not in gate_code,
      'amp-gate: creates no node itself (amp-switch makes and removes /dev/m11-snd-control)')
ampsw = (M11 / 'run19/amp-switch').read_text()
check(ampsw.count('/sbin/m11-ampctl disable') == 1 and 'enable' not in ampsw.replace('Enable', ''),
      'amp-switch (staged byte-identical from run19): one disable call, no enable call')
if fails:
    sys.exit(1)
print('PASS Run22 static structure checks')
