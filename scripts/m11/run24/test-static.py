#!/usr/bin/env python3
"""Run24 static structure checks (text-level evidence; the control-flow test executes the
runner itself). Each Run24 shell input must differ from its origin only as intended.

Run24 (docs/m11-run24.md) keeps the Run23 owned path and changes the terminal: on the owned path
PID1 never final-closes the anchors and never reboots; it enrols the native terminal core over both
anchors, runs a read-only capture (cmdline gate verdict + IOMMU map via the spawner), records the
terminal-core decision, seals and ships the evidence, shows the checkpoint and _exit(0)s holding
both anchors. The degraded paths keep the orderly teardown + reboot(2)."""
import difflib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
M11 = ROOT / 'scripts/m11'
R24 = M11 / 'run24'
fails = []

def check(cond, what):
    print(('PASS ' if cond else 'FAIL ') + what)
    if not cond:
        fails.append(what)

def strip_c(text):
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', text)

def code(path):
    return strip_c(path.read_text())

def changed_text(ta, tb):
    """Lines removed from ta and added in tb."""
    d = list(difflib.unified_diff(ta.splitlines(), tb.splitlines(), lineterm='', n=0))
    rem = [x[1:] for x in d if x.startswith('-') and not x.startswith('---')]
    add = [x[1:] for x in d if x.startswith('+') and not x.startswith('+++')]
    return rem, add

def changed(a, b):
    return changed_text(a.read_text(), b.read_text())

def body(text, start):
    """The text of a top-level C function beginning at `start` up to its closing brace line."""
    s = text[text.index(start):]
    return s[:s.index('\n}\n')]

runner = code(R24 / 'runner.c')
main = runner[runner.index('int main('):]
def pos(text):
    i = main.find(text)
    assert i >= 0, text
    return i

# Runner structure (kept from Run23).
check(pos('fatal_handlers()') < pos('umask(077)') < pos('job("/m11/prepare"'),
      'runner: fatal-signal hold handlers installed before any job')
check('host.receipt' not in runner and 'receipt()' not in runner,
      'runner: no host-receipt gate (receive-only observer)')
check(pos('job("/m11/control","usb_start"') < pos('amp_gate()') < pos('m11_spawner_start(') <
      pos('endpoint()') < pos('m11_audio_bind_endpoint(r,dev)'),
      'runner: amp gate after USB start, before the spawner, the endpoint node and the bind')
gate = body(runner, 'static int amp_gate(void)')
check('strcmp(result,"switches-disabled\\n")' in gate and 'job("/m11/control","amp_gate"' in gate,
      'runner: only switches-disabled admits the GPR query')
check(pos('m11_audio_start_pd(') < pos('if (!pdrc) {') < pos('m11_anchor_bind(&anchor,') <
      pos('m11_anchor_bind(&ion_anchor,') < pos('m11_anchor_owner_seal_pairs(') < pos('m11_audio_attach_anchors('),
      'runner: endpoint then ION anchor bind only after PDR UP, one seal over both pairs at once')
seal = pos('m11_anchor_owner_seal_pairs(')
check(pos('m11_audio_bind_endpoint(r,dev)') < pos('mknod("/dev/msm_audio_ion"') < pos('m11_audio_bind_ion(') <
      pos('m11_audio_start_pd('),
      'runner: ION node made and bound after the endpoint bind and before PDR start')
check(not re.search(r'(mknod|unlink|open)\([^;]*cma', runner),
      'runner: the ION CMA twin is identified by sysfs only, never given a node')
check('const char *const nodes[2]={"/dev/aud_pasthru_adsp","/dev/msm_audio_ion"}' in runner,
      'runner: the seal unlinks both nodes')
unl = main[pos('crumb("pd_not_up_unlink")'):]
check(unl.index('unlink("/dev/aud_pasthru_adsp")') < unl.index('unlink("/dev/msm_audio_ion")') < unl.index('crumb("query_returned")'),
      'runner: a boot without PDR UP unlinks both nodes, opening neither')
check('m11_gpr_anchor_attach_ion(&ion_anchor)' in main, 'runner: the query worker drops the ION pair (GPR layer attach)')
rec = runner[runner.index('static int record('):runner.index('static unsigned crumbs;')]
check('m11_journal_stamp(' in rec and '%09llu' not in rec and 'now()' not in rec,
      'runner: journal records stamped at journal.sh clock and granularity (journal_time.h)')
check(not re.search(r'\bioctl\s*\(', runner), 'runner: no ioctl(2) call at all (no ION ioctl)')
check(not re.search(r'\bjob\(|\bfork\(|\bexecl\(', main[seal:]),
      'runner: no job()/fork()/execl() by PID1 after the seal')
crumbs = re.findall(r'crumb\("([a-z_]+)"\)', main)
check(len(crumbs) >= 30 and len(set(crumbs)) == len(crumbs), f'runner: {len(crumbs)} distinct phase breadcrumbs')
handler = runner[runner.index('static void fatal('):runner.index('static int fatal_handlers(')]
check(not re.search(r'\b(printf|snprintf|malloc|record|hold)\(', handler),
      'runner: fatal handler uses async-signal-safe calls only')
check('/dev/snd' not in runner and 'aud_pasthru' not in code(R24 / 'control'),
      'runner/control: no /dev/snd, control never names the endpoint')

# Run24: native terminal core over both anchors.
check('#include "terminal_core.h"' in (R24 / 'runner.c').read_text(), 'runner: links the native terminal core')
check('m11_terminal_core_init(&tc,&boot_ledger,&anchor,&ion_anchor,' in main,
      'runner: the terminal core is enrolled over BOTH anchors (endpoint + ION)')
check(seal < pos('crumb("terminal_enroll")') < pos('m11_audio_attach_anchors(') or
      pos('m11_audio_attach_anchors(') < pos('crumb("terminal_enroll")') < pos('m11_gpr_linux_query('),
      'runner: terminal core enrolled after the seal/attach and before the query')
check('m11_terminal_action_name' not in runner,
      'runner: no offline-only custodian symbol (m11_terminal_action_name) in the native build')
# Run24: the anchors are held to the end on the owned path.
check('m11_anchor_final_close(' not in runner,
      'runner: no final close anywhere (both anchors held to the end on the owned path)')
check(main.count('_exit(0);') == 1, 'runner: exactly one forced PID1 exit')
owned = main[pos('if (held) {'):pos('_exit(0);')]
check('reboot(' not in owned and 'm11_anchor_end_boot(' not in owned and 'm11_audio_retire(' not in owned and
      'stop_adsp' not in owned and 'pd.stop' not in owned and '"unmount"' not in owned,
      'runner: the owned path never reboots, ends an anchor, retires, stops the ADSP/mapper or unmounts')
check(owned.index('spawned(JOB_CONTROL,"seal"') < owned.index('spawned(JOB_CONTROL,"usb_stop"') <
      owned.index('spawned(JOB_CHECKPOINT,color'),
      'runner: owned path stops USB (Run23 observer grace delivers the F frame) after the seal, before the exit')
check(owned.index('capture_cmdline()') < owned.index('capture_iommu()') < owned.index('m11_terminal_core_action(&tc)') <
      owned.index('record("terminal_decision"') < owned.index('spawned(JOB_CONTROL,"seal"') <
      owned.index('spawned(JOB_CHECKPOINT,color') < owned.index('crumb("pid1_exit_forced")'),
      'runner: capture, then the terminal decision, then sealed evidence and the checkpoint, then the forced exit')
check(owned.index('journal_sealed=1') > owned.index('record("terminal_decision"') and
      owned.count('record(') == 2,
      'runner: no journal record after the seal on the owned path (decision + pre_transport_teardown only)')
# Degraded path keeps the orderly teardown.
deg = main[pos('_exit(0);'):]
check(deg.index('spawned(JOB_CONTROL,"usb_stop"') < deg.index('spawned(JOB_CONTROL,"stop_adsp"') <
      deg.index('m11_anchor_end_boot(&anchor,') < deg.index('m11_anchor_end_boot(&ion_anchor,') <
      deg.index('reboot(RB_AUTOBOOT)'),
      'runner: degraded path: USB stop, ADSP stop, both anchors end REBOOT, then reboot(2)')
check('m11_audio_retire(r)' in main[pos('crumb("pd_not_up_unlink")'):pos('if (held) {')],
      'runner: retire only on the degraded (PDR never UP) branch')
# Run24 capture: serial-safe cmdline, IOMMU via the spawner.
cap_c = body(runner, 'static int capture_cmdline(void)')
check('m11_terminal_core_cmdline_allowed(cmdline_buf)' in cap_c and
      not re.search(r'record\([^;]*cmdline_buf', cap_c),
      'runner: cmdline gate runs on the full /proc/cmdline; the raw cmdline (serial) is never journaled')
cap_i = body(runner, 'static int capture_iommu(void)')
check('spawned(JOB_CONTROL,"iommu_capture"' in cap_i and not re.search(r'\bjob\(|\bfork\(', cap_i),
      'runner: the IOMMU helper runs through the pre-bind spawner (no PID1 fork after the seal)')

# Shell inputs: origin + intended changes only.
ctl = (R24 / 'control').read_text()
b0 = ctl.index(' iommu_capture)\n')
b1 = ctl.index('\n  ;;\n', b0) + len('\n  ;;\n')
iommu_blk, ctl_wo = ctl[b0:b1], ctl[:b0] + ctl[b1:]
rem, add = changed_text((M11 / 'next/control').read_text(), ctl_wo)
check(len(rem) == 1 and rem[0].startswith('# ') and
      sorted(a for a in add if not a.lstrip().startswith('#')) ==
      sorted(['  ;;', ' amp_gate)', '  . /m11/amp-gate', '  amp_gate']),
      'control: next/control plus the amp_gate action and the iommu_capture action only')
blk_code = '\n'.join(l for l in iommu_blk.splitlines() if not l.lstrip().startswith('#'))
redirs = re.findall(r'>>?\s*(\S+)', blk_code)
check('out=/run/m11/iommu.txt' in blk_code and redirs and all(r == '"$out"' for r in redirs) and
      not re.search(r'\b(mknod|rm|mv|ln|dd|echo)\b', blk_code) and '/dev/' not in blk_code and
      '/sys/kernel/iommu_groups' in blk_code,
      'control iommu_capture: read-only; its only write is /run/m11/iommu.txt')
rem, add = changed(M11 / 'next/usb', R24 / 'usb')
code_add = [a for a in add if not a.lstrip().startswith('#')]
check(all('M11R24' in a or 'm11r24' in a or 'Run 24' in a or a.strip() == '$BB sleep 3 || return 1' for a in code_add)
      and all(r.lstrip().startswith('#') or 'm11next' in r or 'M11NEXT' in r or 'engineering' in r for r in rem),
      'usb: next/usb with the Run24 identity and the 3 s observer grace only')
rem, add = changed(M11 / 'run16/init', R24 / 'init')
check(len(rem) == 3 and all('16' in r for r in rem) and all('24' in a for a in add),
      'init: run16/init with Run24 names only')
gatesh = (R24 / 'amp-gate').read_text()
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
print('PASS Run24 static structure checks')
