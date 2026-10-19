"""P4 (Run25 candidate) strict host-side evidence check (docs/m11-argon-p4-assembly.md, item 3).

Two layers, both fail closed, no healing or resynchronization:
  1. transport: the M11I3 stream byte-faithful to the Run23 check (START run=M11R25), the E stream a
     complete instrumentation journal bound to the on-device nonce/identity (instrumentation/evidence.py);
  2. records: every M11P4 / M11ENTRY / M11INTENT / M11TERMINAL kernel record parsed by its exact grammar
     (the formats p4_env_native.c, custodian_entry_native.c, intent_journal_native.c, terminal_native.c
     and custodian_runner_native.c write), written by PID1 (caller=T1, facility user, the level the
     writer uses), then classified. Only the never-mapped orderly shape is the expected outcome:
       env steps 1,2,4,5,6,7,8 rc=0 in order (step 3 has no record), then one entry boot with
       journal kmsg=1, cmdline allowed=1, pd_up rc=0, boot rc=0, runner, session present=0 rc=0
       intents=0, no M11INTENT, the G8 record action=ORDERLY_SHUTDOWN end=reboot note=never_mapped
       with nothing held, then teardown pd_retire=0 steps=11 as the last P4 record.
     Anything else is reported by category; nothing is inferred from a missing record.
  B3: with --stock-summary, the candidate's cmdline verdict and the two token values must equal the
  stock capture's (length and CRC may differ through boot-varying tokens and are never compared).

The report never contains the cmdline text: the record carries only the gate summary."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

MAX_CAPTURE = 64 * 1024 * 1024
RUN = b'M11R25'
HEADER = re.compile(rb'M11I3 ([SKEWF]) (0|[1-9][0-9]{0,8}) ([1-9][0-9]{0,4})\n\Z')
START = re.compile(rb'run=' + RUN + rb' nonce=([0-9a-f]{32})\n\Z')
FINAL = re.compile(rb'frames=(0|[1-9][0-9]*) bytes=(0|[1-9][0-9]*) events=(0|[1-9][0-9]*) kernel_drops=(0|[1-9][0-9]*) '
                   rb'sha256=([0-9a-f]{64}) tty_sha256=([0-9a-f]{64})\n\Z')


def _load_inspect_journal():
    path = Path(__file__).resolve().parents[2] / 'instrumentation' / 'evidence.py'
    spec = importlib.util.spec_from_file_location('m11_p4_instrumentation_evidence', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect_journal


inspect_journal = _load_inspect_journal()


# ---------------------------------------------------------------- 1. transport (Run23 rule, M11R25)
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
HOLD = re.compile(r'M11P4 v=1 pid1 hold: (environment phase failed|entry returned) step=' + INT + r' rc=' + INT)
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
    'teardown': re.compile(r'(?:pd_retire=' + INT + r' steps=' + NAT + r'|refused=1 intents=' + NAT + r' census_failed=' + INT + r')'),
    'reboot_failed': re.compile(r'rc=' + INT),
}
ORDER = ('journal', 'cmdline', 'pd_up', 'boot', 'runner', 'session', 'hold', 'teardown')
INTENT = re.compile(r'M11INTENT v=1 boot=([1-9][0-9]*) seq=' + NAT + r' op=([0-9a-f]{8}) tok=([0-9a-f]{8}) cd=' + NAT +
                    r' dst=([0-9a-f]{8})(?: (?:fd=[0-9]+ msw=[0-9]+ bytes=[0-9]+ pool=[0-9]+ regions=[0-9]+ flags=[0-9a-f]+'
                    r'|handle=[0-9a-f]{8}|pl=[0-9]+))?')
TERMINAL = re.compile(r'M11TERMINAL v=2 boot=([1-9][0-9]*) action=' + ACTION + r' end=(reboot|pid1_exit) anchors_held=' + NAT +
                      r'/' + NAT + r' anchor_fds_open=' + NAT + r'/' + NAT + r' pool=(none|held|NOT_HELD) panic=(unknown|-?[0-9]+) '
                      r'reset_path=(unknown|immediate|hang|after_[0-9]+s) map_attempted=([01]) unmap_attempted=([01]) '
                      r'regions=' + NAT + r' in_pool=' + NAT + r' note=([a-z_]+(?:=[0-9]+)?)')
START_FAILED = re.compile(r'M11TERMINAL v=2 boot=([1-9][0-9]*) action=START_FAILED end=(reboot|pid1_exit) phase=([a-z_]+) step=' +
                          INT + r' rc=' + INT + r' anchors_held=' + NAT + r'/2 boot_stage=' + INT + r' note=entry_failed')
RUNNER_FAILED = re.compile(r'M11TERMINAL v=2 boot=([1-9][0-9]*) action=START_FAILED end=pid1_exit step=' + INT +
                           r' anchor_fds_open=' + NAT + r'/4 pool=(none|held|NOT_HELD) heap_open=([01]) note=start_failed')
TAGS = ('M11P4', 'M11ENTRY', 'M11INTENT', 'M11TERMINAL')
LEVEL = {'env': 5, 'hold': 3, 'entry': 6, 'intent': 6, 'terminal': 6}


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
    """(kind, fields) for a P4 record, None for any other kernel message; RecordError if a P4 tag is malformed."""
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
        return 'entry', dict(boot=m[1], phase=phase, body=body, groups=rule.fullmatch(body).groups())
    m = INTENT.fullmatch(message)
    if m:
        return 'intent', dict(boot=m[1], seq=int(m[2]), op=m[3])
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
    raise RecordError('p4-record-invalid')


def p4_records(kbodies):
    """The P4 records in kernel order, each checked to be PID1's (caller T1, facility user, its level)."""
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


def classify(records, stock=None):
    """Returns (verdict, details). verdict 'never-mapped-orderly' is the only expected outcome."""
    env = [r for r in records if r['kind'] == 'env']
    holds = [r for r in records if r['kind'] == 'hold']
    entry = [r for r in records if r['kind'] in ('entry', 'intent', 'terminal')]
    d = {'env_steps': [r['step'] for r in env], 'phases': [r['phase'] for r in entry if r['kind'] == 'entry'],
         'intents': sum(1 for r in entry if r['kind'] == 'intent'), 'records': len(records), 'b3': 'not-compared'}
    first = next((i for i, r in enumerate(records) if r['kind'] in ('entry', 'intent', 'terminal')), len(records))
    if any(r['kind'] == 'env' for r in records[first:]):
        return 'record-order', d
    failed = [r for r in env if r['what'] == 'failed']
    ok_steps = [r['step'] for r in env if r['what'] != 'failed']
    if ok_steps != sorted(ok_steps) or len(set(ok_steps)) != len(ok_steps) or len(failed) > 1:
        return 'record-order', d
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
    if t['action'] == 'START_FAILED':
        return 'start-failed-' + t['end'], d
    if t['action'] != 'ORDERLY_SHUTDOWN' or t['end'] != 'reboot':
        return 'retaining-end', d
    expect = {'journal': ('1', '1'), 'session': ('0', '0', '0')}
    if (phases != ['journal', 'cmdline', 'pd_up', 'boot', 'runner', 'session', 'teardown'] or d['intents'] or
            by['journal']['groups'] != expect['journal'] or by['cmdline']['groups'][0] != '1' or
            by['pd_up']['groups'][0] != '0' or by['boot']['groups'][:2] != ('0', '0') or
            by['session']['groups'] != expect['session'] or
            t['note'] != 'never_mapped' or t['anchors_held'] or t['fds_open'] or t['map_attempted'] or t['unmap_attempted'] or
            t['regions'] or t['pool'] == 'NOT_HELD'):
        return 'orderly-shape-invalid', d
    td = by['teardown']['groups']
    d['teardown'] = by['teardown']['body']
    if td[0] is None:
        return 'teardown-refused', d
    if td[0] != '0':
        return 'teardown-failed', d
    if td[1] != '11':  # Run23's whole sequence: 11 steps
        return 'teardown-steps-differ', d
    if entry[-1] is not by['teardown'] or entry.index(t) != len(entry) - 2:
        return 'record-order', d
    return 'never-mapped-orderly', d


def check(data, nonce, identity, stock=None):
    streams, kbodies, report = decode(data, nonce, identity)
    verdict, details = 'transport-invalid', {}
    if report['event_stream_complete']:
        try:
            verdict, details = classify(p4_records(kbodies), stock)
        except RecordError as exc:
            verdict = str(exc)
    report.update(p4_verdict=verdict, p4=details, p4_expected=verdict == 'never-mapped-orderly')
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
    print(json.dumps({k: v for k, v in r.items() if k != 'p4'} | {'p4': r['p4']}, indent=2))
    return 0 if ok and r['p4_expected'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
