"""P5 (Run28 speaker candidate) strict host-side evidence check (docs/m11-argon-speaker-run-design.md, W6).

Two layers, both fail closed, no healing or resynchronization:
  1. transport: p4/check-capture.py's, byte for byte, with START run=M11R28 (M11I3 stream, E stream a complete
     instrumentation journal bound to the on-device nonce/identity);
  2. records: every M11P4 (env phase) / M11P5 (PID1 hold) / M11ENTRY / M11INTENT / M11SPK / M11TERMINAL kernel
     record parsed by its exact grammar, written by PID1 (caller=T1, facility user, the writer's level), then
     classified. The expected outcome is "speaker-played-retaining":
       env steps 1,2,4,5,6,7,8 rc=0 in order, then one entry boot with journal kmsg=1, cmdline allowed=1,
       pd_up rc=0, boot rc=0, runner; the speaker records: the plan, steps 1..23 each rc=0 in order (plan,
       amp_off, map, VI back end and graph, RX back end and graph, Re, gate, amp_on, RX prepare, play, EOS), Re
       read back equal on both channels, the teardown amp_off rc=0 FIRST, then rx_stop, rx_be_close, vi_stop,
       vi_be_close, rx_close, vi_close all rc=0, the end record clean (every buffer done, all PCM bytes, EOS 0,
       amp_off=1, no PDR) and the session record rc=0 census=0; the entry session present=1 rc=0 intents=2;
       exactly two MAP intents and no UNMAP or CLOSE_ALL; one M11TERMINAL RESET_RETAINING_ANCHORS
       end=pid1_exit note=mapped_boot holding both anchors, every anchor fd and the pool, map_attempted=1,
       unmap_attempted=0, regions=2; the seal record (3 steps) last.
     Anything else is reported by category, the speaker failures as "speaker-failed:<step>:<amplifier state>"
     and an amplifier not proven off as "UNSAFE-...". Nothing is inferred from a missing record.
  Whether the speaker was AUDIBLE is the operator's observation, never this check's.
  B3: with --stock-summary, the cmdline verdict and the two token values must equal the stock capture's.

The report never contains the cmdline text: the record carries only the gate summary."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

MAX_CAPTURE = 64 * 1024 * 1024
RUN = b'M11R28'
HEADER = re.compile(rb'M11I3 ([SKEWF]) (0|[1-9][0-9]{0,8}) ([1-9][0-9]{0,4})\n\Z')
START = re.compile(rb'run=' + RUN + rb' nonce=([0-9a-f]{32})\n\Z')
FINAL = re.compile(rb'frames=(0|[1-9][0-9]*) bytes=(0|[1-9][0-9]*) events=(0|[1-9][0-9]*) kernel_drops=(0|[1-9][0-9]*) '
                   rb'sha256=([0-9a-f]{64}) tty_sha256=([0-9a-f]{64})\n\Z')


def _load_inspect_journal():
    path = Path(__file__).resolve().parents[2] / 'instrumentation' / 'evidence.py'
    spec = importlib.util.spec_from_file_location('m11_p5_instrumentation_evidence', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect_journal


inspect_journal = _load_inspect_journal()


# ---------------------------------------------------------------- 1. transport (Run23 rule, M11R28)
def decode(data, journal_nonce=None, journal_identity=None):
    """Returns (streams, kernel record bodies, report). Same rule as the Run23 check."""
    journal_error = journal_records = None
    streams = {k: bytearray() for k in 'SKEWF'}
    kbodies = []
    offset = frames = kernels = covered = 0
    prior = nonce = error = category = digest = None
    final = False
    try:
        if len(data) > MAX_CAPTURE:
            raise ValueError('capture-budget')
        while offset < len(data):
            if final:
                raise ValueError('trailing-bytes')
            nl = data.find(b'\n', offset, offset + 64)
            if nl < 0:
                raise ValueError('incomplete-header')
            m = HEADER.fullmatch(data[offset:nl + 1])
            if not m:
                raise ValueError('invalid-header')
            kind, seq, size = m[1].decode(), int(m[2]), int(m[3])
            if seq != frames:
                raise ValueError('sequence-gap-or-duplicate')
            if not 0 < size <= 16384:
                raise ValueError('invalid-length')
            end = nl + 1 + size
            if end > len(data):
                raise ValueError('incomplete-payload')
            body = data[nl + 1:end]
            if frames == 0 and kind != 'S':
                raise ValueError('start-missing')
            if kind == 'S':
                start = START.fullmatch(body)
                if frames or not start or start[1] == b'0' * 32:
                    raise ValueError('invalid-start')
                nonce = start[1].decode()
            if kind == 'K':
                meta = body.partition(b';')[0].split(b',')
                if (not body.endswith(b'\n') or len(meta) not in (4, 5) or any(not x.isdigit() for x in meta[:3]) or
                        meta[3] not in (b'-', b'c') or (len(meta) == 5 and not re.fullmatch(rb'caller=[TC][0-9]+', meta[4]))):
                    raise ValueError('kernel-record-invalid')
                kseq = int(meta[1])
                if prior is not None and kseq != prior + 1:
                    raise ValueError('kernel-sequence-gap-or-duplicate')
                prior = kseq
                kernels += 1
                kbodies.append(bytes(body))
            if kind == 'W':
                raise ValueError('sender-loss-warning')
            if kind == 'F':
                f = FINAL.fullmatch(body)
                if not f:
                    raise ValueError('invalid-final')
                n, b, e, d = map(int, f.groups()[:4])
                metadata = f'frames={n} bytes={b} events={e} kernel_drops={d}\n'.encode()
                digest = hashlib.sha256(data[:offset] + b'M11I3 SEAL\n' + metadata).hexdigest()
                if n != frames or b != offset or e != len(streams['E']):
                    raise ValueError('final-count-mismatch')
                if d:
                    raise ValueError('sender-kernel-loss')
                if f[5].decode() != digest or f[6].decode() != digest:
                    raise ValueError('sender-digest-mismatch')
                covered = offset
                final = True
            streams[kind].extend(body)
            offset = end
            frames += 1
        if not final:
            raise ValueError('missing-final')
        if not kernels:
            raise ValueError('kernel-evidence-missing')
        if journal_nonce is None or journal_identity is None:
            raise ValueError('journal-identity-missing')
        try:
            journal_records = len(inspect_journal(bytes(streams['E']), journal_nonce, journal_identity)['records'])
        except (ValueError, TypeError) as exc:
            journal_error = str(exc)
            raise ValueError('journal-invalid')
    except ValueError as exc:
        category = str(exc)
        error = f'{category} at byte {offset}'
    report = dict(protocol='M11I3', run=RUN.decode(), raw_sha256=hashlib.sha256(data).hexdigest(), raw_bytes=len(data),
                  parsed_bytes=offset, error=error, error_category=category, error_offset=offset if error else None,
                  frames=frames, kernel_records=kernels, last_kernel_sequence=prior, nonce=nonce, covered_bytes=covered,
                  sender_sha256=digest, final_frame_received=final, event_bytes=len(streams['E']),
                  journal_records=journal_records, journal_error=journal_error, event_stream_complete=error is None,
                  host_receipt_valid=False, resynchronization=False)
    return streams, kbodies, report


def validate_receipt(report, receipt):
    r = receipt.get('receipt') or {}
    ok = (report['event_stream_complete'] and receipt.get('errors') == [] and not receipt.get('failure') and
          receipt.get('shutdown_clean') is True and receipt.get('flush_clean') is True and
          receipt.get('raw_sha256') == report['raw_sha256'] and r.get('Bytes') == report['raw_bytes'] and
          r.get('Reason') == 'terminal-frame')
    report['host_receipt_valid'] = bool(ok)
    if not ok and not report['error']:
        report.update(error='receiver-receipt-invalid', error_category='receiver-receipt-invalid',
                      error_offset=report['raw_bytes'])
    return bool(ok)


# ---------------------------------------------------------------- 2. records
INT = r'(-?[0-9]+)'
NAT = r'(0|[1-9][0-9]*)'
TOKEN = r'(absent|empty|[0-9A-Za-z._?-]+)'
ACTION = r'(ORDERLY_SHUTDOWN|HOLD|HOLD_RECONCILE|RESET_RETAINING_ANCHORS|UNSAFE_LAST_CLOSE_OCCURRED)'
ENV_STEPS = {1: 'prepare', 2: 'journal', 4: 'locator', 5: 'relay', 6: 'adsp_usb', 7: 'amp_gate', 8: 'metadata'}
ENV = re.compile(r'M11P4 v=1 env step=([1-8]) (prepare|journal|locator|relay|adsp_usb|amp_gate|metadata|failed) '
                 r'rc=' + INT + r' locator=([01]) relay=([01])')
HOLD = re.compile(r'M11P5 v=1 pid1 hold: (speaker plan refused|environment phase failed|entry returned) step=' + INT +
                  r' rc=' + INT)
ENTRY = re.compile(r'M11ENTRY v=1 boot=([1-9][0-9]*) phase=([a-z_]+)(?: (.*))?')
PHASES = {
    'journal': re.compile(r'pid=' + NAT + r' kmsg=([01])'),
    'cmdline': re.compile(r'allowed=([01]) len=' + NAT + r' strict=' + TOKEN + r' passthrough=' + TOKEN + r' crc32=([0-9a-f]{8})'),
    'pd_up': re.compile(r'rc=' + INT + r' pds=' + NAT + r' fault=' + INT + r' datagrams=' + NAT + r' ms=' + NAT),
    'boot': re.compile(r'rc=' + INT + r' step=' + INT + r' stage=' + INT + r' ep=' + NAT + ':' + NAT + r' ion=' + NAT + ':' + NAT +
                       r' heap=' + NAT + ':' + NAT),
    'runner': re.compile(r'stage=' + INT + r' why=' + NAT + r' pool=' + NAT),
    'session': re.compile(r'present=([01]) rc=' + INT + r' intents=' + NAT),
    'hold': re.compile(r'action=' + ACTION),
    'teardown': re.compile(r'(?:pd_retire=(?P<prc>-?[0-9]+) steps=(?P<steps>0|[1-9][0-9]*)'
                           r'|refused=1 intents=(?P<intents>0|[1-9][0-9]*) census_failed=-?[0-9]+'
                           r'|fail=1 spawner=(?P<spawner>-?[0-9]+) pd=(?P<pd>ready|closed|none) pd_retire=(?P<fprc>-?[0-9]+)'
                           r' steps=(?P<fsteps>0|[1-9][0-9]*))'),
    'seal': re.compile(r'steps=(?P<seal>0|[1-9][0-9]*)'),
    'reboot_failed': re.compile(r'rc=' + INT),
}
ORDER = ('journal', 'cmdline', 'pd_up', 'boot', 'runner', 'session', 'hold', 'teardown', 'seal')
TEARDOWN_STEPS, SEAL_STEPS = '11', '3'
INTENT = re.compile(r'M11INTENT v=1 boot=([1-9][0-9]*) seq=' + NAT + r' op=([0-9a-f]{8}) tok=([0-9a-f]{8}) cd=' + NAT +
                    r' dst=([0-9a-f]{8})(?: (?:fd=[0-9]+ msw=[0-9]+ bytes=[0-9]+ pool=[0-9]+ regions=[0-9]+ flags=[0-9a-f]+'
                    r'|handle=[0-9a-f]{8}|pl=[0-9]+|addr=[0-9]+ msw=[0-9]+ map=[0-9a-f]{8} bytes=[0-9]+|policy=[0-9]+))?')
TERMINAL = re.compile(r'M11TERMINAL v=2 boot=([1-9][0-9]*) action=' + ACTION + r' end=(reboot|pid1_exit) anchors_held=' + NAT +
                      r'/' + NAT + r' anchor_fds_open=' + NAT + r'/' + NAT + r' pool=(none|held|NOT_HELD) panic=(unknown|-?[0-9]+) '
                      r'reset_path=(unknown|immediate|hang|after_[0-9]+s) map_attempted=([01]) unmap_attempted=([01]) '
                      r'regions=' + NAT + r' in_pool=' + NAT + r' note=([a-z_]+(?:=[0-9]+)?)')
START_FAILED = re.compile(r'M11TERMINAL v=2 boot=([1-9][0-9]*) action=START_FAILED end=(reboot|pid1_exit) phase=([a-z_]+) step=' +
                          INT + r' rc=' + INT + r' anchors_held=' + NAT + r'/2 boot_stage=' + INT + r' note=entry_failed')
RUNNER_FAILED = re.compile(r'M11TERMINAL v=2 boot=([1-9][0-9]*) action=START_FAILED end=pid1_exit step=' + INT +
                           r' anchor_fds_open=' + NAT + r'/4 pool=(none|held|NOT_HELD) heap_open=([01]) note=start_failed')
# The speaker session (speaker_session_native.c, speaker_entry_main.c): one record per step, Re, teardown, end.
SPK = re.compile(r'M11SPK v=1 boot=([1-9][0-9]*) phase=spk (.*)')
SPK_RULES = {
    'plan': re.compile(r'plan sha=([0-9a-f]{16}) bytes=' + NAT + r' pcm=' + NAT + r' level=' + NAT),
    'step': re.compile(r'step=' + NAT + r' ([a-z_]+) rc=' + INT),
    'cfg': re.compile(r'cfg=(vi|rx) index=' + NAT + r' rc=' + INT),
    'cfg_rsp': re.compile(r'cfg_rsp dst=([0-9a-f]{8}) param=([0-9a-f]{8}) valid=([01]) status=([0-9a-f]{8}) rc=' + INT),
    're': re.compile(r're ch0=' + NAT + '/' + NAT + '/' + NAT + r' ch1=' + NAT + '/' + NAT + '/' + NAT),
    'teardown': re.compile(r'teardown=(amp_off|rx_stop|rx_be_close|vi_stop|vi_be_close|rx_close|vi_close) '
                           r'(?:rc=' + INT + r'(?: ms=' + NAT + r')?|graph=unknown)'),
    'end': re.compile(r'end rc=' + INT + r' step=' + INT + r' sent=' + NAT + r' done=' + NAT + r' bytes=' + NAT +
                      r' eos=' + INT + r' amp_off=([01]) teardown=' + INT + r' pdr=([01])'),
    'session': re.compile(r'session rc=' + INT + r' census=' + INT + r' ctl_writes=' + NAT + r' readbacks=' + NAT),
}
# M11_SPK_* (speaker_session_native.h) and the name each step records
SPK_STEPS = ('plan', 'amp_off', 'map', 'vi_be_open', 'vi_open', 'vi_cal', 'vi_cfg', 'vi_prepare', 'vi_start', 'vi_reads',
             'vi_be_prepare', 'rx_be_open', 'rx_open', 'rx_cal', 'rx_cfg', 'rx_re', 'rx_prepare', 'rx_start', 'gate',
             'amp_on', 'rx_be_prepare', 'play', 'eos')
GATE, AMP_ON = SPK_STEPS.index('gate') + 1, SPK_STEPS.index('amp_on') + 1
TEARDOWN_ORDER = ('amp_off', 'rx_stop', 'rx_be_close', 'vi_stop', 'vi_be_close', 'rx_close', 'vi_close')
READBACK_VERIFIED = 3  # M11_AW_STAGE_READBACK_VERIFIED
OP_MAP, OP_UNMAP, OP_CLOSE_ALL = '0100100c', '0100100d', '01001013'
TAGS = ('M11P4', 'M11P5', 'M11ENTRY', 'M11INTENT', 'M11SPK', 'M11TERMINAL')
LEVEL = {'env': 5, 'hold': 3, 'entry': 6, 'intent': 6, 'terminal': 6, 'spk': 6}
EXPECTED = 'speaker-played-retaining'


class RecordError(ValueError):
    pass


def kernel_message(body):
    """(facility, level, seq, caller, message) of one /dev/kmsg record body; continuation lines dropped."""
    meta, sep, rest = body.partition(b';')
    if not sep:
        raise RecordError('kernel-record-invalid')
    fields = meta.split(b',')
    prio = int(fields[0])
    caller = fields[4].decode()[len('caller='):] if len(fields) == 5 else None
    message = rest.split(b'\n', 1)[0].decode('ascii', 'replace')
    return prio >> 3, prio & 7, int(fields[1]), caller, message


def parse_record(message):
    """(kind, fields) for a P5 record, None for any other kernel message; RecordError if a P5 tag is malformed."""
    if not any(t in message for t in TAGS):
        return None
    m = ENV.fullmatch(message)
    if m:
        step, what, rc = int(m[1]), m[2], int(m[3])
        if what != 'failed' and (ENV_STEPS.get(step) != what or rc != 0):
            raise RecordError('env-record-invalid')
        return 'env', dict(step=step, what=what, rc=rc, locator=int(m[4]), relay=int(m[5]))
    m = HOLD.fullmatch(message)
    if m:
        return 'hold', dict(why=m[1], step=int(m[2]), rc=int(m[3]))
    m = ENTRY.fullmatch(message)
    if m:
        phase, body = m[2], m[3] or ''
        rule = PHASES.get(phase)
        if not rule or not rule.fullmatch(body):
            raise RecordError('entry-record-invalid')
        g = rule.fullmatch(body)
        return 'entry', dict(boot=m[1], phase=phase, body=body, groups=g.groups(), named=g.groupdict())
    m = SPK.fullmatch(message)
    if m:
        for what, rule in SPK_RULES.items():
            g = rule.fullmatch(m[2])
            if g:
                return 'spk', dict(boot=m[1], what=what, groups=g.groups(), body=m[2])
        raise RecordError('spk-record-invalid')
    m = INTENT.fullmatch(message)
    if m:
        return 'intent', dict(boot=m[1], seq=int(m[2]), op=m[3], dst=m[6])
    m = START_FAILED.fullmatch(message)
    if m:
        return 'terminal', dict(boot=m[1], action='START_FAILED', end=m[2], phase=m[3], step=int(m[4]), rc=int(m[5]),
                                anchors_held=int(m[6]), note='entry_failed')
    m = RUNNER_FAILED.fullmatch(message)
    if m:
        return 'terminal', dict(boot=m[1], action='START_FAILED', end='pid1_exit', phase='runner', step=int(m[2]),
                                anchor_fds_open=int(m[3]), note='start_failed')
    m = TERMINAL.fullmatch(message)
    if m:
        return 'terminal', dict(boot=m[1], action=m[2], end=m[3], anchors_held=int(m[4]), anchors=int(m[5]),
                                fds_open=int(m[6]), fds=int(m[7]), pool=m[8], map_attempted=int(m[11]),
                                unmap_attempted=int(m[12]), regions=int(m[13]), note=m[15])
    raise RecordError('p5-record-invalid')


def p5_records(kbodies):
    """The P5 records in kernel order, each checked to be PID1's (caller T1, facility user, its level)."""
    out = []
    for body in kbodies:
        facility, level, seq, caller, message = kernel_message(body)
        parsed = parse_record(message)
        if parsed is None:
            continue
        kind, fields = parsed
        if caller != 'T1':
            raise RecordError('record-not-from-pid1')
        if facility != 1 or level != LEVEL[kind]:
            raise RecordError('record-level-invalid')
        fields.update(kind=kind, seq=seq)
        out.append(fields)
    return out


def stock_tokens(text):
    m = re.fullmatch(r'allowed=([01]) len=[0-9]+ strict=' + TOKEN + r' passthrough=' + TOKEN + r' crc32=[0-9a-f]{8}\n?', text)
    if not m:
        raise RecordError('stock-summary-invalid')
    return m[1], m[2], m[3]


def speaker(spk, d):
    """The session's own records: (verdict, played) where played means every step 1..23 rc=0 and a clean end."""
    s = d['speaker'] = {}
    if not spk or spk[0]['what'] != 'plan':
        return 'spk-plan-record-missing', False
    plan = spk[0]['groups']
    s['plan'] = dict(sha16=plan[0], bytes=int(plan[1]), pcm=int(plan[2]), level=int(plan[3]))
    rest = spk[1:]
    if [r['what'] for r in rest].count('end') != 1 or [r['what'] for r in rest].count('session') != 1:
        return 'spk-end-missing', False
    if rest[-1]['what'] != 'session' or rest[-2]['what'] != 'end':
        return 'spk-record-order', False
    steps, fail, teardown, re_rec = [], None, [], None
    phase = 'steps'
    for r in rest[:-2]:
        w = r['what']
        if w == 'step':
            n, name, rc = int(r['groups'][0]), r['groups'][1], int(r['groups'][2])
            if phase != 'steps' or not 1 <= n <= len(SPK_STEPS) or SPK_STEPS[n - 1] != name or fail is not None:
                return 'spk-record-order', False
            if rc == 0:
                if steps and n <= steps[-1]:
                    return 'spk-record-order', False
                steps.append(n)
            else:
                fail = (n, name, rc)
        elif w == 'cfg_rsp':
            if phase != 'steps' or fail is not None:
                return 'spk-record-order', False
            dst, param, valid, status, rc = r['groups']
            valid, status, rc = int(valid), int(status, 16), int(rc)
            if ((not valid and status != 0) or (valid and status != 0 and rc != -121) or
                    (valid and status == 0 and rc != 0) or (not valid and rc == 0)):
                return 'spk-cfg-response-invalid', False
            s.setdefault('cfg_responses', []).append(dict(dst=dst, param=param, valid=valid, status=status, rc=rc))
        elif w == 'cfg':
            if phase != 'steps':
                return 'spk-record-order', False
        elif w == 're':
            if phase != 'steps' or re_rec is not None:
                return 'spk-record-order', False
            re_rec = [int(x) for x in r['groups']]
        elif w == 'teardown':
            phase = 'teardown'
            teardown.append((r['groups'][0], r['groups'][1], r['body'].endswith('graph=unknown')))
        else:
            return 'spk-record-order', False
    end = [int(x) for x in rest[-2]['groups']]
    cfg_failed = [r for r in s.get('cfg_responses', []) if r['rc'] != 0]
    if cfg_failed and (len(cfg_failed) != 1 or fail is None or fail[1] not in ('vi_cfg', 'rx_cfg') or
                       fail[2] != cfg_failed[0]['rc'] or s['cfg_responses'][-1] is not cfg_failed[0]):
        return 'spk-cfg-failure-unaccounted', False
    rc, step, sent, done, nbytes, eos, amp_off, td_rc, pdr = end
    session_rc, census = int(rest[-1]['groups'][0]), int(rest[-1]['groups'][1])
    s.update(steps_ok=len(steps), fail=fail and dict(step=fail[0], name=fail[1], rc=fail[2]), teardown=[t[0] for t in teardown],
             end=dict(rc=rc, step=step, sent=sent, done=done, bytes=nbytes, eos=eos, amp_off=amp_off, teardown=td_rc, pdr=pdr),
             session=dict(rc=session_rc, census=census),
             re=re_rec and dict(ch0=dict(stage=re_rec[0], written=re_rec[1], read=re_rec[2]),
                                ch1=dict(stage=re_rec[3], written=re_rec[4], read=re_rec[5])))
    names = [t[0] for t in teardown]
    if len(set(names)) != len(names) or [n for n in TEARDOWN_ORDER if n in names] != names:
        return 'spk-teardown-order', False
    amp_touched = 'amp_off' in names
    amp_enabled = AMP_ON in steps or (fail is not None and fail[0] == AMP_ON)
    if amp_enabled and not amp_touched:
        return 'UNSAFE-amp-not-driven-off', False
    if amp_touched and (names[0] != 'amp_off' or teardown[0][1] != '0' or not amp_off):
        return 'UNSAFE-amp-off-unverified', False
    if fail is not None:
        if (rc, step) != (fail[2], fail[0]):
            return 'spk-end-mismatch', False
        where = 'amp-never-enabled' if not amp_enabled else 'amp-off-verified'
        return f'speaker-failed:{fail[1]}:{where}', False
    if steps != list(range(1, len(SPK_STEPS) + 1)):
        return 'spk-steps-incomplete', False
    if (re_rec is None or re_rec[0] != READBACK_VERIFIED or re_rec[3] != READBACK_VERIFIED or re_rec[1] != re_rec[2] or
            re_rec[4] != re_rec[5]):
        return 'spk-re-not-verified', False
    if (names != list(TEARDOWN_ORDER) or any(t[1] != '0' or t[2] for t in teardown) or rc or step or td_rc or pdr or eos or
            not amp_off or sent != done or nbytes != s['plan']['pcm']):
        return 'spk-end-not-clean', False
    if session_rc or census:
        return 'spk-session-not-clean', False
    return 'played', True


def classify(records, stock=None):
    """Returns (verdict, details). EXPECTED ('speaker-played-retaining') is the only expected outcome."""
    env = [r for r in records if r['kind'] == 'env']
    holds = [r for r in records if r['kind'] == 'hold']
    entry = [r for r in records if r['kind'] in ('entry', 'intent', 'terminal', 'spk')]
    intents = [r for r in entry if r['kind'] == 'intent']
    d = {'env_steps': [r['step'] for r in env], 'phases': [r['phase'] for r in entry if r['kind'] == 'entry'],
         'intents': len(intents), 'maps': sum(1 for r in intents if r['op'] == OP_MAP),
         'records': len(records), 'b3': 'not-compared'}
    if any(r['op'] in (OP_UNMAP, OP_CLOSE_ALL) for r in intents):
        return 'UNMAP-or-CLOSE_ALL-journaled', d
    first = next((i for i, r in enumerate(records) if r['kind'] in ('entry', 'intent', 'terminal', 'spk')), len(records))
    if any(r['kind'] == 'env' for r in records[first:]):
        return 'record-order', d
    failed = [r for r in env if r['what'] == 'failed']
    ok_steps = [r['step'] for r in env if r['what'] != 'failed']
    if ok_steps != sorted(ok_steps) or len(set(ok_steps)) != len(ok_steps) or len(failed) > 1:
        return 'record-order', d
    if holds and holds[0]['why'] == 'speaker plan refused':
        d['hold'] = holds[0]['why']
        return ('plan-refused' if not env and not entry else 'record-order'), d
    if failed:
        d['env_failed_step'], d['env_failed_rc'] = failed[0]['step'], failed[0]['rc']
        if entry or env[-1] is not failed[0] or ok_steps != [s for s in ENV_STEPS if s < failed[0]['step']]:
            return 'record-order', d
        return 'env-failed', d
    if ok_steps != list(ENV_STEPS):
        return 'env-incomplete', d
    if holds:
        d['hold'] = holds[0]['why']
        return 'pid1-held', d
    if not entry:
        return 'entry-missing', d
    if len({r['boot'] for r in entry}) != 1:
        return 'boot-epoch-mixed', d
    phases = d['phases']
    if len(set(phases)) != len(phases) or [p for p in ORDER if p in phases] != [p for p in phases if p in ORDER]:
        return 'record-order', d
    by = {r['phase']: r for r in entry if r['kind'] == 'entry'}
    if 'cmdline' in by:
        allowed, _len, strict, passthrough, _crc = by['cmdline']['groups']
        d['cmdline'] = dict(allowed=int(allowed), strict=strict, passthrough=passthrough)
        if stock is not None:
            d['b3'] = 'match' if (allowed, strict, passthrough) == stock else 'differs'
    terminals = [r for r in entry if r['kind'] == 'terminal']
    if len(terminals) != 1:
        return 'terminal-missing' if not terminals else 'record-order', d
    t = terminals[0]
    d['terminal'] = {k: t[k] for k in ('action', 'end', 'note')}
    if d['b3'] == 'differs':
        return 'b3-cmdline-differs', d
    if 'reboot_failed' in by:
        return 'reboot-failed', d
    td, seal = by.get('teardown'), by.get('seal')
    last = entry[-1]
    if t['end'] != 'pid1_exit':  # P5 never reaches the orderly end; a pre-bind failure reboots after its teardown
        if t['action'] == 'START_FAILED' and td is not None and td['named']['fsteps'] is not None and last is td:
            return ('start-failed-reboot' if td['named']['fsteps'] == TEARDOWN_STEPS else 'teardown-steps-differ'), d
        return 'unexpected-end', d
    if td is not None or seal is None:
        return 'retaining-end-unsealed', d
    if last is not seal or entry.index(t) > entry.index(seal):
        return 'record-order', d
    if seal['named']['seal'] != SEAL_STEPS:
        return 'seal-steps-differ', d
    if t['action'] == 'START_FAILED':
        return 'start-failed-pid1_exit', d
    if t['action'] != 'RESET_RETAINING_ANCHORS':
        return 'unexpected-end', d
    spk = [r for r in entry if r['kind'] == 'spk']
    if 'session' not in by:
        return 'session-missing', d
    if spk and (entry.index(spk[0]) < entry.index(by['runner']) or entry.index(spk[-1]) > entry.index(by['session'])):
        return 'record-order', d
    sv, played = speaker(spk, d)
    if not played:
        return sv, d
    expect = {'journal': ('1', '1'), 'session': ('1', '0', '2')}
    if (phases != ['journal', 'cmdline', 'pd_up', 'boot', 'runner', 'session', 'seal'] or
            by['journal']['groups'] != expect['journal'] or by['cmdline']['groups'][0] != '1' or
            by['pd_up']['groups'][0] != '0' or by['boot']['groups'][:2] != ('0', '0') or
            by['session']['groups'] != expect['session'] or d['maps'] != 2 or
            t['note'] != 'mapped_boot' or t['anchors_held'] != t['anchors'] or t['fds_open'] != t['fds'] or
            t['pool'] != 'held' or not t['map_attempted'] or t['unmap_attempted'] or t['regions'] != 2):
        return 'played-but-end-shape-invalid', d
    return EXPECTED, d


def check(data, nonce, identity, stock=None):
    streams, kbodies, report = decode(data, nonce, identity)
    verdict, details = 'transport-invalid', {}
    diagnostic = None
    try:
        if report['event_stream_complete']:
            verdict, details = classify(p5_records(kbodies), stock)
        elif kbodies:  # the records ahead of the transport error, for classification only
            diagnostic, _ = classify(p5_records(kbodies), stock)
    except RecordError as exc:
        if report['event_stream_complete']:
            verdict = str(exc)
        else:
            diagnostic = str(exc)
    report.update(p5_verdict=verdict, p5=details, p5_expected=verdict == EXPECTED,
                  p5_diagnostic=diagnostic, p5_diagnostic_strict=False,
                  audible_observation='operator (not machine-checked)')
    return streams, report


def main():
    p = argparse.ArgumentParser()
    p.add_argument('raw', type=Path)
    p.add_argument('--receipt', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--journal-nonce', required=True)
    p.add_argument('--journal-identity', required=True)
    p.add_argument('--stock-summary', type=Path, help='local cmdline_summary.py output of the stock capture (B3)')
    a = p.parse_args()
    stock = stock_tokens(a.stock_summary.read_text(encoding='ascii')) if a.stock_summary else None
    with a.raw.open('rb') as f:
        data = f.read(MAX_CAPTURE + 1)
    streams, r = check(data, a.journal_nonce, a.journal_identity, stock)
    try:
        ok = validate_receipt(r, json.loads(a.receipt.read_text(encoding='utf-8-sig')))
    except (OSError, ValueError):
        ok = False
        r.update(error='receipt-missing-or-malformed', error_category='receipt-missing-or-malformed')
    a.out.mkdir(parents=True, exist_ok=False)
    for k in streams:
        (a.out / (k + '.bin')).write_bytes(streams[k])
    (a.out / 'report.json').write_text(json.dumps(r, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in r.items() if k != 'p5'} | {'p5': r['p5']}, indent=2))
    return 0 if ok and r['p5_expected'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
