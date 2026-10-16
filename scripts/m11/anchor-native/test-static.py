#!/usr/bin/env python3
"""Static structure checks of the integrated sources (text-level evidence, not a proof of
behaviour; the control-flow and stand-in tests exercise the code itself)."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
native = ROOT / 'scripts/m11/anchor-native'
def code(path):
    """Source text without C comments."""
    text = path.read_text()
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', text)
runner = code(native / 'runner.c')
gpr = code(native / 'gpr_linux.c')
runtime = code(native / 'audio_runtime.c')
fails = []

def check(cond, what):
    print(('PASS ' if cond else 'FAIL ') + what)
    if not cond:
        fails.append(what)

main = runner[runner.index('int main('):]
def pos(text):
    i = main.find(text)
    assert i >= 0, text
    return i
seal = pos('m11_anchor_owner_seal(')
after = main[seal:]
check(not re.search(r'\bjob\(|\bfork\(|\bexecl\(|\bcheckpoint\(', after),
      'runner: no job()/fork()/execl()/checkpoint() by PID1 after the seal')
check(pos('m11_spawner_start(') < pos('m11_audio_bind_endpoint(r,dev)'), 'runner: spawner started before the endpoint bind')
check(pos('m11_audio_bind_endpoint(r,dev)') < pos('m11_audio_start_pd(') < pos('if (!pdrc) {') <
      pos('m11_anchor_bind(') < seal < pos('m11_audio_attach_anchor('),
      'runner: anchor bind (the only open) after the endpoint bind and a qualified PDR UP; seal right after it')
check(pos('} else if (unlink("/dev/aud_pasthru_adsp"))') > seal and
      pos('if (!pdrc && m11_anchor_final_close(&anchor))') > pos('m11_gpr_linux_query('),
      'runner: a boot without PDR UP never opens (node unlinked); the final close only after an open')
check(pos('m11_anchor_final_close(') < pos('m11_audio_retire(r)') < pos('spawned(JOB_CONTROL,"stop_adsp"'),
      'runner: final close before retire and before stop_adsp')
check(pos('m11_anchor_end_boot(') < pos('reboot(RB_AUTOBOOT)'), 'runner: reboot only after end_boot')
check(main.count('spawned(') >= 6 and 'M11_SPAWN_NO_KILL' in runner, 'runner: post-bind jobs via the spawner, never killed')
check('/dev/aud_pasthru_adsp' not in gpr and not re.search(r'\bopen\(', gpr),
      'gpr_linux: the worker has no open(2) and no endpoint path')
lx_close = re.search(r'static int64_t lx_close\(.*?\n', gpr).group(0)
check('close(' not in lx_close.split('{', 1)[1], 'gpr_linux: lx_close returns the borrow without close(2)')
check(gpr.index('m11_anchor_lend_begin(') < gpr.index('pid=fork()') < gpr.index('m11_anchor_lend_started(') < gpr.index('m11_anchor_lend_end('),
      'gpr_linux: lend_begin before the fork, lend_started after it, lend_end after the reap')
child = gpr[gpr.index('static void linux_child('):]
check(child.index('m11_anchor_worker_accept(') < child.index('m11_gpr_worker_hygiene(') <
      child.index('drop_privileges()') < child.index('m11_anchor_linux_confine()') < child.index('m11_gpr_worker('),
      'gpr_linux: accept, hygiene, privilege drop and confinement before any endpoint I/O')
admit = runtime[runtime.index('int m11_audio_admit('):runtime.index('int m11_audio_control(')]
check('/dev/aud_pasthru_adsp' not in admit and 'm11_anchor_check(r->anchor)' in admit,
      'audio_runtime: admission rests on the sealed anchor, not the node path')
check('no_device_fds(1,r->device)' not in runtime and 'pid1_endpoint_fds_ok(r)' in runtime,
      'audio_runtime: PID1 census admits exactly the anchor pair')
# R3: the integrated flow's shell inputs create no ALSA node.
for name in ('scripts/m11/next/control', 'scripts/m11/next/usb', 'scripts/m11/run16/prepare'):
    text = (ROOT / name).read_text()
    nodes = [l for l in text.splitlines() if 'mknod' in l and not l.lstrip().startswith('#')]
    check(not any('snd' in l for l in nodes) and '/dev/snd' not in text,
          f'{name}: no /dev/snd node (mknod lines: {len(nodes)})')
check('/dev/snd' not in runner, 'runner: no /dev/snd')
if fails:
    sys.exit(1)
print('PASS integrated sources: static structure checks')
