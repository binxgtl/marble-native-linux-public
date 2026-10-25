"""P5 host-check tests (docs/m11-argon-speaker-run-design.md, W6), run by CI. Synthetic data only.

  test-p5-check.py [--spk-records FILE]

FILE holds the M11SPK lines the speaker session wrote in the W5 stand-in's happy path
(test-speaker-session-native.c with M11_SPK_RECORDS set): the C writers' own records, parsed here by the
Python grammar and classified as played (the CI cross-check)."""
import hashlib
import importlib.util
import os
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
    """The host check; under test.sh's mutant runs, a one-line mutant of it (M11_P5_CHECK_MUTANT) executed as if it
    were check-capture.py (its evidence.py path resolves from the real location)."""
    mutant = os.environ.get('M11_P5_CHECK_MUTANT')
    if not mutant:
        return load('m11_p5_check', HERE / 'check-capture.py')
    module = types.ModuleType('m11_p5_check')
    module.__file__ = str(HERE / 'check-capture.py')
    sys.modules['m11_p5_check'] = module
    exec(compile(Path(mutant).read_text(encoding='utf-8'), mutant, 'exec'), module.__dict__)
    return module


C = load_checker()
evidence = load('m11_p5_test_evidence', ROOT / 'scripts/m11/instrumentation/evidence.py')
JN, JI = '7' * 32, '9' * 64


# ---------------------------------------------------------------- capture builder (p4/test-p4-check.py's)
def frame(kind, seq, body):
    return f'M11I3 {kind} {seq} {len(body)}\n'.encode() + body


def journal(nonce=JN, identity=JI):
    rows = [('session', 'identity', 'metadata', 0, (nonce + ' ' + identity).encode())]
    rows += [(c, 'unsupported', 'metadata', 95, b'not_implemented') for c in evidence.CONDITIONS]
    rows += [('session', 'final_state', 'metadata', 0, b'amp_enable_permitted=0 actuator_implemented=0')]
    raw = b''.join(f'M11I1 {s} 1.00 {c} {op} {impact} {rc} {p.hex()}\n'.encode() for s, (c, op, impact, rc, p) in enumerate(rows))
    return raw + f'M11I1 END {len(rows)} {hashlib.sha256(raw).hexdigest()}\n'.encode()


def kmsg(lines):
    """'<L>message' lines -> kernel record bodies from PID1 (caller T1), with unrelated kernel noise between."""
    out, seq = [], 100
    for i, line in enumerate(lines):
        if i % 3 == 0:
            out.append(f'6,{seq},{1000 + seq},-,caller=T20;remoteproc: noise {i}\n'.encode())
            seq += 1
        if isinstance(line, bytes):
            out.append(line.replace(b'@SEQ@', str(seq).encode()))
        else:
            level, msg = int(line[1]), line[3:]
            out.append(f'{8 + level},{seq},{1000 + seq},-,caller=T1;{msg}\n'.encode())
        seq += 1
    return out


def capture(bodies, run=b'M11R31', ev=None):
    ev = journal() if ev is None else ev
    pieces = [frame('S', 0, b'run=' + run + b' nonce=0123456789abcdef0123456789abcdef\n')]
    for b in bodies:
        pieces.append(frame('K', len(pieces), b))
    for at in range(0, len(ev), 16000):
        pieces.append(frame('E', len(pieces), ev[at:at + 16000]))
    covered = b''.join(pieces)
    meta = f'frames={len(pieces)} bytes={len(covered)} events={len(ev)} kernel_drops=0\n'.encode()
    h = hashlib.sha256(covered + b'M11I3 SEAL\n' + meta).hexdigest()
    return covered + frame('F', len(pieces), meta[:-1] + f' sha256={h} tty_sha256={h}\n'.encode())


# ---------------------------------------------------------------- the expected P5 boot
ENV_OK = [f'<5>M11P4 v=1 env step={s} {w} rc=0 locator={int(s >= 4)} relay={int(s >= 5)}' for s, w in C.ENV_STEPS.items()]
B = '<6>M11ENTRY v=1 boot=4242 '
S = '<6>M11SPK v=1 boot=4242 phase=spk '
PCM = 960000
HEAD = [B + 'phase=journal pid=1 kmsg=1',
        B + 'phase=cmdline allowed=1 len=1177 strict=absent passthrough=absent crc32=0badc0de',
        B + 'phase=pd_up rc=0 pds=4 fault=0 datagrams=3 ms=118',
        B + 'phase=boot rc=0 step=0 stage=6 ep=242:0 ion=241:0 heap=240:0',
        B + 'phase=runner stage=6 why=0 pool=2']


def intent(seq, op, tail):
    return f'<6>M11INTENT v=1 boot=4242 seq={seq} op={op} tok={seq:08x} cd=0 dst=00000001 {tail}'


def re_rsp(op, req, rc=0, status=0, valid=1, n=0, rsp='0/00000000/0'):
    return S + f're_rsp op={op} req={req} valid={valid} status={status:08x} rc={rc} len={n} rsp={rsp}'


def re_ok(ch, value):
    """The stock write, read command and read of one channel (libawcal aw_audioreach_read_msg_from_dsp)."""
    msg = f'{0x10013D1B + ch:08x}'
    return [re_rsp('01001006', f'28/0/{msg}'), re_rsp('01001006', f'24/1/{msg}'),
            re_rsp('01001007', '8/0/00000000', n=28, rsp=f'4/00000000/{value}')]


def spk_lines(fail=None, re_read=None, amp_off_rc=0, teardown=None, end_bytes=PCM, re_records=None):
    """The session's records: steps 1..22 (or up to a failing step), Re after rx_cfg, teardown, end, session."""
    out = [S + f'plan sha=ec7b1fc40b91d01f bytes=984360 pcm={PCM} level=8']
    q = (26100, 28684)
    n_ok = len(C.SPK_STEPS) if fail is None else fail[0] - 1
    for n in range(1, n_ok + 1):
        name = C.SPK_STEPS[n - 1]
        if name == 'rx_re':
            r = re_read or q
            out += re_ok(0, r[0]) + re_ok(1, r[1]) if re_records is None else re_records
            out.append(S + f're ch0=3/{q[0]}/{r[0]} ch1=3/{q[1]}/{r[1]}')
        out.append(S + f'step={n} {name} rc=0')
    if fail:
        out.append(S + f'step={fail[0]} {C.SPK_STEPS[fail[0] - 1]} rc={fail[1]}')
    amp = fail is None or fail[0] >= C.AMP_ON
    names = teardown if teardown is not None else ([n for n in C.TEARDOWN_ORDER if amp or n != 'amp_off'])
    for t in names:
        out.append(S + (f'teardown=amp_off rc={amp_off_rc} ms=5600' if t == 'amp_off' else f'teardown={t} rc=0'))
    rc, step = (fail[1], fail[0]) if fail else (0, 0)
    sent = 125 if fail is None else 0
    out.append(S + f'end rc={rc} step={step} sent={sent} done={sent} bytes={end_bytes if fail is None else 0} '
               f'amp_off={int(amp and amp_off_rc == 0)} teardown=0 pdr=0')
    out.append(S + f'session rc={rc} census=0 ctl_writes=8 readbacks=8')
    return out


def boot(spk=None, maps=2, extra_intents=(), session=None, terminal=None, seal=True, hold=None):
    spk = spk_lines() if spk is None else spk
    lines = list(ENV_OK)
    if hold:
        return lines + [hold]
    lines += HEAD
    lines += [intent(i + 1, '0100100c', f'fd={30 + i} msw=0 bytes=65536 pool=3 regions=1 flags=4') for i in range(maps)]
    lines += list(extra_intents)
    lines += spk
    lines.append(session or B + f'phase=session present=1 rc={0 if spk[-1].endswith("rc=0 census=0 ctl_writes=8 readbacks=8") else -5} intents={maps}')
    lines.append(terminal or ('<6>M11TERMINAL v=2 boot=4242 action=RESET_RETAINING_ANCHORS end=pid1_exit anchors_held=2/2 '
                              'anchor_fds_open=4/4 pool=held panic=-1 reset_path=immediate map_attempted=1 unmap_attempted=0 '
                              f'regions={maps} in_pool={maps} note=mapped_boot'))
    if seal:
        lines.append(B + 'phase=seal steps=3')
    return lines


def verdict(lines, run=b'M11R31'):
    _, r = C.check(capture(kmsg(lines), run=run), JN, JI, ('1', 'absent', 'absent'))
    return r['p5_verdict'], r


def test_re_response_fields():
    # Run30 independent review: an otherwise played transcript with failed/missing Re data
    # must not qualify, even if the producer later reports a successful session.
    good = re_ok(0, 26100) + re_ok(1, 28684)
    for before, after in (('rsp=4/00000000/', 'rsp=4/00000001/'), ('len=28', 'len=0'),
                          ('rsp=4/', 'rsp=3/'), ('rsp=4/', 'rsp=9/')):
        malformed = [line.replace(before, after) for line in good]
        assert verdict(boot(spk_lines(re_records=malformed)))[0] == 'spk-re-not-verified', (before, after)
    # Both reported sizes permitted by the bounded native contract remain accepted.
    assert verdict(boot(spk_lines(re_records=[x.replace('rsp=4/', 'rsp=8/') for x in good])))[0] == C.EXPECTED
    print('PASS Re response length, parameter size and zero error independently required for played verdict')


def test_checker():
    v, r = verdict(boot())
    assert v == C.EXPECTED and r['p5_expected'] and r['p5']['maps'] == 2 and r['p5']['b3'] == 'match', r
    sp = r['p5']['speaker']
    assert sp['steps_ok'] == 22 and sp['teardown'] == list(C.TEARDOWN_ORDER) and sp['end']['bytes'] == PCM, sp
    assert r['audible_observation'] == 'operator (not machine-checked)'
    print('PASS P5 check: the played shape (env 1,2,4-8; entry; 2 MAPs; 22 speaker steps; Re verified; amplifier off first; '
          'clean end; retaining G8; seal last)')
    for fields in ('valid=1 status=00000000 rc=0', 'valid=1 status=ffffffff rc=-121',
                   'valid=0 status=00000000 rc=-110', 'valid=0 status=00000000 rc=-121'):
        rc = int(fields.rsplit('=', 1)[1])
        lines = spk_lines(fail=(7, rc if rc else -121))
        lines.insert(1, S + 'cfg_rsp dst=00004545 param=08001008 ' + fields)
        v, r = verdict(boot(lines))
        assert v == 'speaker-failed:vi_cfg:amp-never-enabled', (v, fields)
        assert r['p5']['speaker']['cfg_responses'][0]['valid'] == int(fields[6])
    for fields in ('valid=0 status=00000001 rc=-121', 'valid=1 status=00000001 rc=0',
                   'valid=1 status=00000000 rc=-121', 'valid=0 status=00000000 rc=0'):
        lines = spk_lines(fail=(7, -121))
        lines.insert(1, S + 'cfg_rsp dst=00004545 param=08001008 ' + fields)
        assert verdict(boot(lines))[0] == 'spk-cfg-response-invalid', fields
    print('PASS CFG response provenance: matched zero/NACK, timeout and transport errno; contradictory evidence rejected')
    lines = spk_lines()
    lines.insert(1, S + 'cfg_rsp dst=00004545 param=08001008 valid=1 status=00000001 rc=-121')
    assert verdict(boot(lines))[0] == 'spk-cfg-failure-unaccounted'
    # Re: the read command refused (or Run28's GET_CFG of the write envelope) is accounted to rx_re
    refused = spk_lines(fail=(16, -121))
    at = next(i for i, ln in enumerate(refused) if 'step=16 rx_re' in ln)
    refused[at:at] = [re_rsp('01001006', '28/0/10013d1b'),
                      re_rsp('01001006', '24/1/10013d1b', rc=-121, status=0x12)]
    v, r = verdict(boot(refused))
    assert v == 'speaker-failed:rx_re:amp-never-enabled', v
    assert r['p5']['speaker']['re_responses'][1] == dict(op='01001006', size=24, type=1, msg='10013d1b', valid=1,
                                                         status=0x12, rc=-121, len=0, rsp_size=0, err=0, value=0)
    run31 = spk_lines(fail=(16, -121))
    run31[at:at] = [re_rsp('01001006', '28/0/10013d1b'), re_rsp('01001007', '28/0/10013d1b', rc=-121, status=0x12)]
    assert verdict(boot(run31))[0] == 'speaker-failed:rx_re:amp-never-enabled'
    unaccounted = spk_lines(re_records=re_ok(0, 26100)[:2] + [re_rsp('01001007', '8/0/00000000', rc=-121, status=1)] +
                            re_ok(1, 28684))
    assert verdict(boot(unaccounted))[0] == 'spk-re-failure-unaccounted'
    no_cmd = spk_lines(re_records=[x for i, x in enumerate(re_ok(0, 26100) + re_ok(1, 28684)) if i % 3 != 1])
    assert verdict(boot(no_cmd))[0] == 'spk-re-not-verified'
    print('PASS Re response provenance: a refused read command and Run28 GET_CFG fail at rx_re; an unaccounted '
          'failure and a read without its command are rejected')
    # no EOS (stock PCM playback ends with stop; consumed Run30 EOS {0,0}): an EOS record or an eos step is not this session
    lines = spk_lines()
    lines.insert(-3, S + 'eos_rsp tok=0000009b submit=0 tx=4 wait=0 dsp=00000000 ib=0/00000000 ren=1/8/40bd/40bd/1')
    assert verdict(boot(lines))[0] == 'spk-record-invalid'
    lines = spk_lines()
    lines.insert(-3, S + 'step=23 eos rc=0')
    assert verdict(boot(lines))[0] == 'spk-record-order'
    assert verdict(boot(extra_intents=[intent(3, '04001002', 'policy=1')]))[0] == 'unexpected-eos-intent'
    print('PASS P5 check: no EOS in the speaker session (EOS intent, response and step 23 rejected)')
    cases = [
        ('Re read-back failed (amplifier never enabled)', boot(spk_lines(fail=(16, -74))), 'speaker-failed:rx_re:amp-never-enabled'),
        ('RX START refused', boot(spk_lines(fail=(18, -121))), 'speaker-failed:rx_start:amp-never-enabled'),
        ('a buffer refused while playing, amplifier off first', boot(spk_lines(fail=(22, -121))), 'speaker-failed:play:amp-off-verified'),
        ('the Enable did not read back', boot(spk_lines(fail=(20, -5))), 'speaker-failed:amp_on:amp-off-verified'),
        ('amplifier off not verified', boot(spk_lines(amp_off_rc=-5)), 'UNSAFE-amp-off-unverified'),
        ('amplifier enabled, never driven off',
         boot(spk_lines(teardown=[n for n in C.TEARDOWN_ORDER if n != 'amp_off'])), 'UNSAFE-amp-not-driven-off'),
        ('graph stop before amplifier off', boot(spk_lines(teardown=['rx_stop', 'amp_off'])), 'spk-teardown-order'),
        ('Re read back differs', boot(spk_lines(re_read=(26100, 28000))), 'spk-re-not-verified'),
        ('PCM short', boot(spk_lines(end_bytes=PCM - 7680)), 'spk-end-not-clean'),
        ('an UNMAP journaled', boot(extra_intents=[intent(9, '0100100d', 'handle=a0000001')]), 'UNMAP-or-CLOSE_ALL-journaled'),
        ('three MAPs', boot(maps=3), 'played-but-end-shape-invalid'),
        ('seal missing', boot(seal=False), 'retaining-end-unsealed'),
        ('the plan refused before the environment', ['<3>M11P5 v=1 pid1 hold: speaker plan refused step=0 rc=-74'], 'plan-refused'),
        ('environment failed', ENV_OK[:4] + ['<5>M11P4 v=1 env step=6 failed rc=-110 locator=1 relay=1',
                                            '<3>M11P5 v=1 pid1 hold: environment phase failed step=6 rc=-110'], 'env-failed'),
        ('a malformed speaker record', boot(spk_lines()[:3] + [S + 'step=x rc=0'] + spk_lines()[3:]), 'spk-record-invalid'),
        ('a speaker step out of order', boot(spk_lines()[:2] + spk_lines()[3:4] + spk_lines()[2:3] + spk_lines()[4:]), 'spk-record-order'),
        ('the end record missing', boot(spk_lines()[:-2] + spk_lines()[-1:]), 'spk-end-missing'),
    ]
    for what, lines, want in cases:
        got, _ = verdict(lines)
        assert got == want, (what, got, want)
    bodies = kmsg(boot())
    at = next(i for i, b in enumerate(bodies) if b'M11SPK' in b)
    bodies[at] = bodies[at].replace(b'caller=T1;', b'caller=T77;')
    _, r = C.check(capture(bodies), JN, JI, None)
    assert r['p5_verdict'] == 'record-not-from-pid1', r['p5_verdict']
    assert verdict(boot(), run=b'M11R25')[0] == 'transport-invalid'
    assert verdict(boot(), run=b'M11R26')[0] == 'transport-invalid'
    assert verdict(boot(), run=b'M11R30')[0] == 'transport-invalid'
    print(f'PASS P5 check: {len(cases) + 3} other shapes classified by category (failed steps with the amplifier state, '
          'UNSAFE amplifier, Re, PCM, UNMAP, MAP count, seal, plan, environment, grammar, order, caller, run id)')


def test_c_records(path):
    lines = [ln for ln in Path(path).read_text(encoding='ascii').splitlines() if ln]
    assert lines and all(ln.startswith('<6>M11SPK v=1 boot=7 phase=spk ') for ln in lines), lines[:2]
    recs = []
    for ln in lines:
        kind, fields = C.parse_record(ln[3:])
        assert kind == 'spk', ln
        recs.append(fields)
    plan = C.parse_record('M11SPK v=1 boot=7 phase=spk plan sha=0123456789abcdef bytes=1 pcm=96000 level=8')[1]
    session = C.parse_record('M11SPK v=1 boot=7 phase=spk session rc=0 census=0 ctl_writes=8 readbacks=8')[1]
    d = {}
    got = C.speaker([plan] + recs + [session], d)
    assert got == ('played', True), (got, d)
    print(f'PASS P5 check over the C writers: {len(lines)} M11SPK records of the W5 happy path parse and classify as played')


if __name__ == '__main__':
    if sys.argv[1:2] == ['--write-fixture']:  # the expected-shape capture for the Windows receiver test
        Path(sys.argv[2]).write_bytes(capture(kmsg(boot())))
        print(f'wrote the synthetic P5 capture {sys.argv[2]}')
        raise SystemExit(0)
    test_checker()
    test_re_response_fields()
    if len(sys.argv) == 3 and sys.argv[1] == '--spk-records':
        test_c_records(sys.argv[2])
    elif len(sys.argv) != 1:
        raise SystemExit('usage: test-p5-check.py [--spk-records FILE]')
