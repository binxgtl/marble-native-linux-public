#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent host verifier for an M16 journal wire. Shares no code with the device.

Exit 0: the wire is well formed, whatever its verdict says about the cycle.
Exit 2: the wire is rejected. Only `pass: true` in the report means the cycle passed.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

MAGIC = b'M16J1\0\0\0'
HEADER = 96
RECORD = 128
BODY = 96
JITTER = 5_000_000
MIN_SLEEP = 1_000_000_000
CPUS = 8
EV = {name: value for value, name in enumerate(
    ('OPEN', 'PHASE', 'COUNTERS_PRE', 'IDLE_PRE', 'ALARM', 'WAKE_COUNT', 'WRITER', 'COUNTERS_POST',
     'IDLE_POST', 'VERDICT', 'CLEANUP', 'FAIL', 'SEAL'), 1)}
NAME = {value: name for name, value in EV.items()}
LENGTH = {'OPEN': 24, 'ALARM': 12, 'WAKE_COUNT': 12, 'WRITER': 16, 'COUNTERS_PRE': 64, 'COUNTERS_POST': 64,
          'IDLE_PRE': 64, 'IDLE_POST': 64, 'VERDICT': 16, 'CLEANUP': 12, 'FAIL': 12, 'SEAL': 8}
PHASE_PREFLIGHT, PHASE_ENTER = 1, 2
VERDICTS = ('INVALID', 'PASS', 'ABORTED', 'NO_SLEEP', 'EARLY_WAKE', 'LATE_WAKE', 'WRONG_WAKE')
FAILS = ('NONE', 'CLOCK', 'JOURNAL', 'PREFLIGHT_READ', 'NO_FREEZE', 'RTC_IDENTITY', 'NO_WAKEALARM', 'USB_PRESENT',
         'ADSP_RUNNING', 'WAKE_ACTIVE', 'ALARM_STALE', 'COUNTERS', 'ALARM_ARM', 'ALARM_READBACK', 'WAKE_COUNT_READ',
         'WAKE_COUNT_WRITE', 'ENTRY_LATE', 'WRITER_START', 'WRITER_POLL', 'WRITER_TIMEOUT')
COUNTERS = ('success', 'fail', 'failed_errno', 'rtc_irq', 'alarm_enabled', 'wake_active', 'cycle_mode', 'cpu_mask')
# Allowed successors; anything else is a reordered, dropped or forged record.
GRAMMAR = {
    'OPEN': {'PHASE1', 'FAIL', 'SEAL'},
    'PHASE1': {'COUNTERS_PRE', 'FAIL'},
    'COUNTERS_PRE': {'IDLE_PRE', 'FAIL'},
    'IDLE_PRE': {'ALARM', 'FAIL'},
    'ALARM': {'WAKE_COUNT', 'FAIL'},
    'WAKE_COUNT': {'PHASE2', 'FAIL'},
    'PHASE2': {'WRITER', 'FAIL'},
    'WRITER': {'COUNTERS_POST', 'FAIL'},
    'COUNTERS_POST': {'IDLE_POST', 'FAIL'},
    'IDLE_POST': {'VERDICT', 'FAIL'},
    'VERDICT': {'CLEANUP', 'FAIL', 'SEAL'},
    'FAIL': {'CLEANUP', 'SEAL'},
    'CLEANUP': {'SEAL'},
}


class Rejected(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def gap(clock):
    return max(clock[0] - clock[1], 0)


def clock_valid(clock):
    return clock[0] > 0 and clock[1] > 0 and clock[0] + JITTER >= clock[1]


def judge(cycle, expect):
    """Second, separate reading of the rule in oracle.c, compared against it in CI."""
    interval, early, late = expect
    pre, post = cycle['clock_pre'], cycle['clock_post']
    if not interval or early >= interval or interval + late >= 1 << 64:
        return 'INVALID', 0
    if not clock_valid(pre) or not clock_valid(post) or post[0] < pre[0] or post[1] < pre[1]:
        return 'INVALID', 0
    a, b, before, after = gap(pre), gap(post), cycle['pre'], cycle['post']
    idle_a, idle_b = cycle['idle_pre'], cycle['idle_post']
    ordered = (after['success'] >= before['success'] and after['fail'] >= before['fail']
               and after['rtc_irq'] >= before['rtc_irq'] and before['cycle_mode'] == after['cycle_mode']
               and before['cpu_mask'] and before['cpu_mask'] == after['cpu_mask']
               and not before['cpu_mask'] >> CPUS and all(y >= x for x, y in zip(idle_a, idle_b)))
    if b + JITTER < a or not ordered:
        return 'INVALID', 0
    slept = max(b - a, 0)
    success, fail = after['success'] - before['success'], after['fail'] - before['fail']
    rc, error = cycle['writer_rc'], cycle['writer_errno']
    if rc:
        refused = not success and fail == 1 and slept < MIN_SLEEP and error > 0 and after['failed_errno'] == error
        return ('ABORTED' if refused else 'INVALID'), slept
    if error or success != 1 or fail or before['alarm_enabled'] or after['alarm_enabled'] > 1:
        return 'INVALID', slept
    if slept < MIN_SLEEP:
        return 'NO_SLEEP', slept
    if not all(idle_b[i] > idle_a[i] for i in range(CPUS) if after['cpu_mask'] >> i & 1):
        return 'INVALID', slept
    if slept < interval - early:
        return 'EARLY_WAKE', slept
    if slept > interval + late:
        return 'LATE_WAKE', slept
    if after['rtc_irq'] - before['rtc_irq'] != 1 or after['alarm_enabled']:
        return 'WRONG_WAKE', slept
    return 'PASS', slept


def parse_records(data, nonce, count):
    head = bytes(nonce) + bytes(16)
    head = hashlib.sha256(head + bytes(BODY)).digest()
    records = []
    for seq in range(count):
        raw = data[HEADER + seq * RECORD:HEADER + (seq + 1) * RECORD]
        got_seq, kind, length, boot, mono = struct.unpack_from('<IHHQQ', raw)
        require(got_seq == seq, f'sequence {got_seq} at {seq}')
        require(kind in NAME, f'unknown type {kind}')
        name = NAME[kind]
        expected = LENGTH.get(name)
        if name == 'PHASE':
            require(length in (4, 16), 'phase length')
        else:
            require(length == expected, f'{name} length {length}')
        payload = raw[24:88]
        require(not any(payload[length:]), 'payload padding')
        require(not any(raw[88:BODY]), 'reserved bytes')
        head = hashlib.sha256(head + raw[:BODY]).digest()
        require(raw[BODY:] == head, f'chain break at {seq}')
        records.append({'name': name, 'clock': (boot, mono), 'payload': payload})
    return records, head


def check_clocks(records):
    last = None
    for record in records:
        clock = record['clock']
        require(clock_valid(clock), 'invalid clock pair')
        if last:
            require(clock[0] >= last[0] and clock[1] >= last[1], 'clock went backwards')
            require(gap(clock) + JITTER >= gap(last), 'sleep gap shrank')
        last = clock


def walk(records):
    """Checks the event grammar and returns the fields the report is built from."""
    require(records and records[0]['name'] == 'OPEN', 'first record is not OPEN')
    require(records[-1]['name'] == 'SEAL', 'not sealed')
    state, seen = 'OPEN', {}
    for record in records[1:]:
        name = record['name']
        token = name
        if name == 'PHASE':
            phase = struct.unpack_from('<I', record['payload'])[0]
            require(phase in (PHASE_PREFLIGHT, PHASE_ENTER), f'phase {phase}')
            token = f'PHASE{phase}'
        require(token in GRAMMAR[state] or (token == 'SEAL' and state in ('CLEANUP', 'FAIL', 'VERDICT', 'OPEN')),
                f'{token} after {state}')
        require(token not in seen, f'duplicate {token}')
        seen[token] = record
        if token == 'SEAL':
            break
        state = token
    require(len(seen) == len(records) - 1, 'records after the seal')
    require('VERDICT' in seen or 'FAIL' in seen or len(records) == 2, 'ended with no verdict and no failure')
    return seen


def words(payload, n):
    return list(struct.unpack_from(f'<{n}Q', payload))


def decode(data):
    require(len(data) >= HEADER, 'short header')
    require(data[:8] == MAGIC, 'bad magic')
    size, count, capacity = struct.unpack_from('<III', data, 8)
    require(size == RECORD, 'record size')
    require(0 < count <= capacity, 'count')
    require(len(data) == HEADER + count * RECORD, 'wire length')
    nonce, stated_head = data[20:36], data[36:68]
    require(not any(data[68:HEADER]), 'header padding')
    records, head = parse_records(data, nonce, count)
    require(head == stated_head, 'head mismatch')
    check_clocks(records)
    seen = walk(records)
    seal = struct.unpack_from('<II', records[-1]['payload'])
    require(seal == (count - 1, capacity), 'seal fields')
    alarm_s, early_s, late_s = struct.unpack_from('<III', records[0]['payload'])
    mode = struct.unpack_from('<Q', records[0]['payload'], 16)[0]
    report = {'schema': 'm16-journal-report-v1', 'head': head.hex(), 'nonce': nonce.hex(), 'records': count,
              'alarm_s': alarm_s, 'cycle_mode': mode, 'verdict': None, 'slept_ns': None, 'failure': None,
              'alarm_left_enabled': None, 'pass': False}
    if 'FAIL' in seen:
        reason, error, state = struct.unpack_from('<IiI', seen['FAIL']['payload'])
        require(reason < len(FAILS) and reason, 'failure reason')
        report['failure'] = {'reason': FAILS[reason], 'error': error, 'state': state}
    if 'CLEANUP' in seen:
        read_rc, clear_rc, enabled = struct.unpack_from('<iii', seen['CLEANUP']['payload'])
        report['alarm_left_enabled'] = enabled
        report['cleanup'] = {'read_rc': read_rc, 'clear_rc': clear_rc}
    if 'VERDICT' in seen:
        code = struct.unpack_from('<I', seen['VERDICT']['payload'])[0]
        claimed_slept = struct.unpack_from('<Q', seen['VERDICT']['payload'], 8)[0]
        require(code < len(VERDICTS), 'verdict code')
        wrc, werr = struct.unpack_from('<qq', seen['WRITER']['payload'])
        pre = dict(zip(COUNTERS, words(seen['COUNTERS_PRE']['payload'], 8)))
        post = dict(zip(COUNTERS, words(seen['COUNTERS_POST']['payload'], 8)))
        cycle = {'clock_pre': seen['COUNTERS_PRE']['clock'], 'clock_post': seen['WRITER']['clock'],
                 'pre': pre, 'post': post, 'idle_pre': words(seen['IDLE_PRE']['payload'], 8),
                 'idle_post': words(seen['IDLE_POST']['payload'], 8), 'writer_rc': wrc, 'writer_errno': werr}
        verdict, slept = judge(cycle, (alarm_s * 10**9, early_s * 10**9, late_s * 10**9))
        require(verdict == VERDICTS[code], f'device said {VERDICTS[code]}, evidence says {verdict}')
        require(slept == claimed_slept, 'slept_ns disagrees')
        report.update(verdict=verdict, slept_ns=slept)
        report['pass'] = verdict == 'PASS' and 'FAIL' not in seen and report['alarm_left_enabled'] == 0
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('wire', type=Path)
    parser.add_argument('--ack', type=Path, help='write the chain head for the device')
    args = parser.parse_args()
    try:
        report = decode(args.wire.read_bytes())
    except (Rejected, struct.error) as error:
        print(json.dumps({'rejected': str(error)}))
        return 2
    if args.ack:
        args.ack.write_text(report['head'], encoding='ascii')
    print(json.dumps(report, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
