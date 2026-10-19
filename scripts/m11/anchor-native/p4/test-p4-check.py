"""P4 host-check tests (docs/m11-argon-p4-assembly.md, item 3), run by CI. Synthetic data only.

  test-p4-check.py [JOURNAL_DIR [--require-c]]

JOURNAL_DIR holds p4-journal-<case>.txt written by the P3 entry test (test-entry-native.c, root
sections): the record lines the C writers produced, checked here by the Python grammar (the CI
cross-check). --require-c fails when any of them is missing."""
import hashlib
import importlib.util
import os
import re
from pathlib import Path
import sys
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_checker():
    """The host check; under test.sh's mutant runs, a one-line mutant of it (M11_P4_CHECK_MUTANT) executed
    as if it were check-capture.py (its evidence.py path resolves from the real location)."""
    mutant = os.environ.get('M11_P4_CHECK_MUTANT')
    if not mutant:
        return load('m11_p4_check', HERE / 'check-capture.py')
    module = types.ModuleType('m11_p4_check')
    module.__file__ = str(HERE / 'check-capture.py')
    sys.modules['m11_p4_check'] = module
    exec(compile(Path(mutant).read_text(encoding='utf-8'), mutant, 'exec'), module.__dict__)
    return module


C = load_checker()
evidence = load('m11_p4_test_evidence', ROOT / 'scripts/m11/instrumentation/evidence.py')
JN, JI = '7' * 32, '9' * 64


def expect_error(fn, *args, contains=''):
    try:
        fn(*args)
    except C.RecordError as exc:
        assert contains in str(exc), (contains, str(exc))
        return str(exc)
    raise AssertionError(f'{fn.__name__} accepted a bad input')


# ---------------------------------------------------------------- capture builder
def frame(kind, seq, body):
    return f'M11I3 {kind} {seq} {len(body)}\n'.encode() + body


def journal(nonce=JN, identity=JI):
    rows = [('session', 'identity', 'metadata', 0, (nonce + ' ' + identity).encode())]
    rows += [(c, 'unsupported', 'metadata', 95, b'not_implemented') for c in evidence.CONDITIONS]
    rows += [('session', 'final_state', 'metadata', 0, b'amp_enable_permitted=0 actuator_implemented=0')]
    raw = b''.join(f'M11I1 {s} 1.00 {c} {op} {impact} {rc} {p.hex()}\n'.encode() for s, (c, op, impact, rc, p) in enumerate(rows))
    return raw + f'M11I1 END {len(rows)} {hashlib.sha256(raw).hexdigest()}\n'.encode()


def kmsg(lines):
    """'<L>message' lines (as the PID1 writers emit them) -> kernel record bodies from PID1, plus noise."""
    out, seq = [], 100
    for i, line in enumerate(lines):
        if i % 3 == 0:  # an unrelated kernel record between PID1's
            out.append(f'6,{seq},{1000 + seq},-,caller=T20;remoteproc: noise {i}\n'.encode())
            seq += 1
        if isinstance(line, bytes):
            out.append(line.replace(b'@SEQ@', str(seq).encode()))
        else:
            level, msg = int(line[1]), line[3:]
            out.append(f'{8 + level},{seq},{1000 + seq},-,caller=T1;{msg}\n'.encode())
        seq += 1
    return out


def capture(bodies, run=b'M11R25', ev=None, final=True):
    ev = journal() if ev is None else ev
    pieces = [frame('S', 0, b'run=' + run + b' nonce=0123456789abcdef0123456789abcdef\n')]
    for b in bodies:
        pieces.append(frame('K', len(pieces), b))
    for at in range(0, len(ev), 16000):
        pieces.append(frame('E', len(pieces), ev[at:at + 16000]))
    covered = b''.join(pieces)
    meta = f'frames={len(pieces)} bytes={len(covered)} events={len(ev)} kernel_drops=0\n'.encode()
    h = hashlib.sha256(covered + b'M11I3 SEAL\n' + meta).hexdigest()
    tail = frame('F', len(pieces), meta[:-1] + f' sha256={h} tty_sha256={h}\n'.encode())
    return covered + (tail if final else b'')


ENV_OK = [f'<5>M11P4 v=1 env step={s} {w} rc=0 locator={int(s >= 4)} relay={int(s >= 5)}' for s, w in C.ENV_STEPS.items()]
B = '<6>M11ENTRY v=1 boot=4242 '
TERM_OK = ('<6>M11TERMINAL v=2 boot=4242 action=ORDERLY_SHUTDOWN end=reboot anchors_held=0/2 anchor_fds_open=0/4 '
           'pool=held panic=unknown reset_path=unknown map_attempted=0 unmap_attempted=0 regions=0 in_pool=0 note=never_mapped')
ENTRY_OK = [B + 'phase=journal pid=1 kmsg=1',
            B + 'phase=cmdline allowed=1 len=1177 strict=absent passthrough=absent crc32=0badc0de',
            B + 'phase=pd_up rc=0 pds=4 fault=0 datagrams=3 ms=118',
            B + 'phase=boot rc=0 step=0 stage=6 ep=242:0 ion=241:0 heap=240:0',
            B + 'phase=runner stage=3 why=0 pool=2',
            B + 'phase=session present=0 rc=0 intents=0',
            TERM_OK,
            B + 'phase=teardown pd_retire=0 steps=11']
STOCK = ('1', 'absent', 'absent')


def verdict(lines, stock=STOCK, **kw):
    _, r = C.check(capture(kmsg(lines), **kw), JN, JI, stock)
    return r['p4_verdict'], r


# ---------------------------------------------------------------- 1. the host check
def test_checker():
    v, r = verdict(ENV_OK + ENTRY_OK)
    assert v == 'never-mapped-orderly' and r['p4_expected'] and r['p4']['b3'] == 'match', r
    assert r['p4']['env_steps'] == [1, 2, 4, 5, 6, 7, 8] and r['p4']['teardown'] == 'pd_retire=0 steps=11', r
    assert verdict(ENV_OK + ENTRY_OK, stock=None)[1]['p4']['b3'] == 'not-compared'
    print('PASS P4 check: the never-mapped orderly shape (env 1,2,4-8, entry phases, G8 reboot, teardown 11 steps), B3 tokens equal to stock')
    rep = lambda lines, i, new: lines[:i] + [new] + lines[i + 1:]
    cases = [
        ('b3 strict differs', ENV_OK + rep(ENTRY_OK, 1, B + 'phase=cmdline allowed=1 len=9 strict=1 passthrough=absent crc32=00000000'), 'b3-cmdline-differs'),
        ('env step missing', ENV_OK[:4] + ENV_OK[5:] + ENTRY_OK, 'env-incomplete'),
        ('env failed, then hold', ENV_OK[:4] + ['<5>M11P4 v=1 env step=6 failed rc=-110 locator=1 relay=1',
                                               '<3>M11P4 v=1 pid1 hold: environment phase failed step=6 rc=-110'], 'env-failed'),
        ('env failed out of order', ENV_OK[:2] + ['<5>M11P4 v=1 env step=6 failed rc=-110 locator=1 relay=1'], 'record-order'),
        ('env record after the entry', ENV_OK[:-1] + ENTRY_OK[:1] + ENV_OK[-1:] + ENTRY_OK[1:], 'record-order'),
        ('env success with rc', rep(ENV_OK, 0, '<5>M11P4 v=1 env step=1 prepare rc=-1 locator=0 relay=0') + ENTRY_OK, 'env-record-invalid'),
        ('env name for the wrong step', rep(ENV_OK, 0, '<5>M11P4 v=1 env step=1 journal rc=0 locator=0 relay=0') + ENTRY_OK, 'env-record-invalid'),
        ('entry returned hold', ENV_OK + ENTRY_OK[:6] + ['<3>M11P4 v=1 pid1 hold: entry returned step=0 rc=0'], 'pid1-held'),
        ('record not from PID1', ENV_OK + [b'14,@SEQ@,1,-,caller=T77;M11ENTRY v=1 boot=4242 phase=journal pid=1 kmsg=1\n'] + ENTRY_OK[1:], 'record-not-from-pid1'),
        ('record without caller', ENV_OK + [b'14,@SEQ@,1,-;M11ENTRY v=1 boot=4242 phase=journal pid=1 kmsg=1\n'] + ENTRY_OK[1:], 'record-not-from-pid1'),
        ('entry at level 5', ENV_OK + ['<5>' + ENTRY_OK[0][3:]] + ENTRY_OK[1:], 'record-level-invalid'),
        ('kernel facility', ENV_OK + [b'6,@SEQ@,1,-,caller=T1;M11ENTRY v=1 boot=4242 phase=journal pid=1 kmsg=1\n'] + ENTRY_OK[1:], 'record-level-invalid'),
        ('malformed entry field', ENV_OK + rep(ENTRY_OK, 2, B + 'phase=pd_up rc=0 pds=4 fault=0 datagrams=3'), 'entry-record-invalid'),
        ('unknown phase', ENV_OK + rep(ENTRY_OK, 4, B + 'phase=runnr stage=3 why=0 pool=2'), 'entry-record-invalid'),
        ('unknown tag text', ENV_OK + ENTRY_OK[:3] + ['<6>M11ENTRY garbage'] + ENTRY_OK[3:], 'p4-record-invalid'),
        ('two boot epochs', ENV_OK + rep(ENTRY_OK, 3, ENTRY_OK[3].replace('boot=4242', 'boot=4243')), 'boot-epoch-mixed'),
        ('phases swapped', ENV_OK + [ENTRY_OK[0], ENTRY_OK[2], ENTRY_OK[1]] + ENTRY_OK[3:], 'record-order'),
        ('phase repeated', ENV_OK + ENTRY_OK[:2] + ENTRY_OK[1:], 'record-order'),
        ('kmsg not the journal', ENV_OK + rep(ENTRY_OK, 0, B + 'phase=journal pid=1 kmsg=0'), 'orderly-shape-invalid'),
        ('MAP intent recorded', ENV_OK + ENTRY_OK[:6] + ['<6>M11INTENT v=1 boot=4242 seq=1 op=0100100c tok=00000001 cd=0 dst=00000001 '
                                                        'fd=7 msw=0 bytes=65536 pool=200 regions=1 flags=0'] + ENTRY_OK[6:], 'orderly-shape-invalid'),
        ('an anchor still held', ENV_OK + rep(ENTRY_OK, 6, TERM_OK.replace('anchors_held=0/2', 'anchors_held=1/2')), 'orderly-shape-invalid'),
        ('session present', ENV_OK + rep(ENTRY_OK, 5, B + 'phase=session present=1 rc=0 intents=0'), 'orderly-shape-invalid'),
        ('teardown missing', ENV_OK + ENTRY_OK[:7], 'orderly-shape-invalid'),
        ('teardown refused', ENV_OK + ENTRY_OK[:7] + [B + 'phase=teardown refused=1 intents=0 census_failed=0'], 'teardown-refused'),
        ('PD withdrawal failed', ENV_OK + ENTRY_OK[:7] + [B + 'phase=teardown pd_retire=-110 steps=11'], 'teardown-failed'),
        ('teardown list not Run23', ENV_OK + ENTRY_OK[:7] + [B + 'phase=teardown pd_retire=0 steps=7'], 'teardown-steps-differ'),
        ('terminal after the teardown', ENV_OK + ENTRY_OK[:6] + [ENTRY_OK[7], ENTRY_OK[6]], 'record-order'),
        ('retaining end', ENV_OK + ENTRY_OK[:6] + [B + 'phase=hold action=HOLD',
                                                  TERM_OK.replace('ORDERLY_SHUTDOWN end=reboot', 'RESET_RETAINING_ANCHORS end=pid1_exit')
                                                  .replace('note=never_mapped', 'note=mapped_boot')], 'retaining-end'),
        ('start failed before a bind', ENV_OK + ENTRY_OK[:2] + [
            '<6>M11TERMINAL v=2 boot=4242 action=START_FAILED end=reboot phase=pd_up step=4 rc=-102 anchors_held=0/2 '
            'boot_stage=0 note=entry_failed'], 'start-failed-reboot'),
        ('runner start failed', ENV_OK + ENTRY_OK[:4] + [
            '<6>M11TERMINAL v=2 boot=4242 action=START_FAILED end=pid1_exit step=2 anchor_fds_open=4/4 pool=none heap_open=1 '
            'note=start_failed'], 'start-failed-pid1_exit'),
        ('no terminal record', ENV_OK + ENTRY_OK[:6], 'terminal-missing'),
        ('no entry at all', ENV_OK, 'entry-missing'),
    ]
    for name, lines, want in cases:
        got, r = verdict(lines)
        assert got == want and not r['p4_expected'], (name, want, got, r['p4'])
        print(f'PASS P4 check rejects {name}: {got}')
    data = capture(kmsg(ENV_OK + ENTRY_OK))
    for name, raw, want in [('Run23 START', capture(kmsg(ENV_OK + ENTRY_OK), run=b'M11R23'), 'invalid-start'),
                            ('no final frame', capture(kmsg(ENV_OK + ENTRY_OK), final=False), 'missing-final'),
                            ('a byte flipped', data[:-80] + bytes([data[-80] ^ 1]) + data[-79:], None),
                            ('journal digest broken', capture(kmsg(ENV_OK + ENTRY_OK), ev=journal()[:-3] + b'00\n'), 'journal-invalid')]:
        _, r = C.check(raw, JN, JI, STOCK)
        assert r['p4_verdict'] == 'transport-invalid' and not r['p4_expected'], (name, r)
        assert want is None or r['error_category'] == want, (name, r['error_category'])
        print(f'PASS P4 transport rejects {name}: {r["error_category"]}')
    _, r = C.check(data, JN, None, STOCK)
    assert r['error_category'] == 'journal-identity-missing' and not r['p4_expected']
    report = C.check(data, JN, JI, STOCK)[1]
    good = {'errors': [], 'failure': None, 'shutdown_clean': True, 'flush_clean': True, 'raw_sha256': report['raw_sha256'],
            'receipt': {'Bytes': len(data), 'Reason': 'terminal-frame'}}
    assert C.validate_receipt(dict(report), good) and not C.validate_receipt(dict(report), good | {'flush_clean': False})
    assert C.stock_tokens('allowed=1 len=1177 strict=absent passthrough=absent crc32=0badc0de\n') == STOCK
    expect_error(C.stock_tokens, 'allowed=1 strict=absent', contains='stock-summary-invalid')
    print('PASS P4 check: the identity is required, the host receipt binds the raw hash, the stock summary is parsed strictly')


# C writer cases (test-entry-native.c, keep_as) and the verdict each must get.
C_CASES = {'helpers-ok': 'never-mapped-orderly', 'never-mapped-td7': 'teardown-steps-differ',
           'map-hold': 'retaining-end', 'intent-after-close': 'retaining-end',
           'cmdline-refused': 'start-failed-reboot', 'reboot-fails': 'reboot-failed',
           'boot-after-bind': 'start-failed-pid1_exit', 'teardown-no-unreg': 'teardown-failed'}


def test_c_writers(directory, required):
    found = 0
    for case, want in C_CASES.items():
        path = Path(directory) / f'p4-journal-{case}.txt'
        if not path.is_file():
            assert not required, f'{path} missing'
            continue
        lines = [ln for ln in path.read_text(encoding='ascii').split('\n') if ln]
        assert lines and all(ln[:3] in ('<6>', '<5>', '<3>') for ln in lines), (case, lines)
        # B3 against the fixture's own cmdline tokens (the stock comparison itself is tested above)
        cmd = [re.search(r' phase=cmdline allowed=([01]) len=[0-9]+ strict=(\S+) passthrough=(\S+) ', ln) for ln in lines]
        stock = next(m.groups() for m in cmd if m)
        # The fixture writes its journal to a file from a process that is not PID1 (pid=N kmsg=0): the
        # check refuses that record as written, and is given the production values only after that.
        journal = [i for i, ln in enumerate(lines) if ' phase=journal ' in ln]
        assert len(journal) == 1 and re.search(r' phase=journal pid=([2-9]|[1-9][0-9]+) kmsg=0$', lines[journal[0]]), (case, lines)
        if want == 'never-mapped-orderly':
            assert verdict(ENV_OK + lines, stock=stock)[0] == 'orderly-shape-invalid', (case, lines)
        lines[journal[0]] = re.sub(r'pid=[0-9]+ kmsg=0$', 'pid=1 kmsg=1', lines[journal[0]])
        got, r = verdict(ENV_OK + lines, stock=stock)
        assert got == want, (case, want, got, r['p4'], lines)
        found += 1
        print(f'PASS P4 check over the C writers ({case}, {len(lines)} records): {got}')
    if not found:
        print('SKIP P4 C-writer cross-check: no journals (the P3 root sections did not run)')


# ---------------------------------------------------------------- 2. the P4 identity in the sources
def test_sources():
    """The full source contracts run in the local staging; CI checks the identity tokens."""
    relay = (HERE / 'kmsg-relay.c').read_text()
    usb = (HERE / 'usb').read_text()
    init = (HERE / 'init').read_text()
    assert relay.count('"run=M11R25 nonce="') == 1 and C.RUN == b'M11R25'
    assert 'G=/config/usb_gadget/m11r25' in usb and "printf '%s' M11R25 >" in usb
    assert init.count('exec /sbin/m11-p4\n') == 1
    for name in ('init', 'prepare', 'usb', 'kmsg-relay.c', 'build.sh'):
        data = (HERE / name).read_bytes()
        assert b'\r' not in data and b'M11R23' not in data and b'm11r23' not in data, name
    print('PASS P4 sources carry the M11R25 identity (relay START, USB gadget) and init execs /sbin/m11-p4')


if __name__ == '__main__':
    test_checker()
    if len(sys.argv) > 1:
        test_c_writers(sys.argv[1], '--require-c' in sys.argv[2:])
    test_sources()
    print('PASS P4 host-check tests (transport, record grammar and classification, C writers when present)')
