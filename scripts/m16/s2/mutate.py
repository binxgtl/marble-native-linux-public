#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Proves the tests can fail: breaks one guarantee at a time and requires a failure.

A mutant that survives means a safety property has no test behind it, and fails CI.
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SHA = Path('scripts/m11/anchor-native/p4/sha256.h')
CORE = ('journal.c', 'oracle.c', 'machine.c', 'mark.c')
# name, file, exact text, replacement, test that must then fail
MUTANTS = (
    ('post clock read before the writer returned', 'machine.c', 'int read_rc=m->ops.clock(m->ops.arg,&post);', 'post=*c;int read_rc=0;', 'machine'),
    ('suspend without alarm readback', 'machine.c', 'if(got||!readback){fail(m,M16_F_ALARM_READBACK,got);return;}', '(void)got;(void)readback;', 'machine'),
    ('suspend after a failed arm', 'machine.c', 'if(rc){fail(m,M16_F_ALARM_ARM,rc);return;}', '', 'machine'),
    ('enter after the deadline', 'machine.c', 'if(c->boot_ns>=m->enter_by){fail(m,M16_F_ENTRY_LATE,0);return;}', '', 'machine'),
    ('wake count read failure ignored', 'machine.c', 'if(got){fail(m,M16_F_WAKE_COUNT_READ,got);return;}', '', 'machine'),
    ('wake count write failure ignored', 'machine.c', 'if(put){fail(m,M16_F_WAKE_COUNT_WRITE,put);return;}', '', 'machine'),
    ('alarm not disarmed on failure', 'machine.c', ' disarm(m);\n finish_record(m,M16_S_CHANNEL);\n}\nstatic void step_init', ' finish_record(m,M16_S_CHANNEL);\n}\nstatic void step_init', 'machine'),
    ('stuck writer treated as recoverable', 'machine.c', 'if(m->writer_active){finish_record(m,M16_S_HOLD);return;}', '', 'machine'),
    ('writer timeout never fires', 'machine.c', 'if(c->boot_ns>=m->deadline)fail(m,M16_F_WRITER_TIMEOUT,0);', '', 'machine'),
    ('USB gate removed', 'machine.c', 'if(p->udc_count)return M16_F_USB_PRESENT;', '', 'machine'),
    ('ADSP gate removed', 'machine.c', 'if(!p->adsp_offline)return M16_F_ADSP_RUNNING;', '', 'machine'),
    ('wakeup source gate removed', 'machine.c', 'if(p->wake_active)return M16_F_WAKE_ACTIVE;', '', 'machine'),
    ('stale alarm accepted', 'machine.c', 'if(rc||enabled){fail(m,M16_F_ALARM_STALE,rc);return;}', '', 'machine'),
    ('verified pass despite a failure', 'machine.c', 'm->verdict==M16_V_PASS&&!m->failure?M16_O_VERIFIED_PASS', 'm->state==M16_S_RETAINED?M16_O_VERIFIED_PASS', 'machine'),
    ('wrong ACK accepted', 'machine.c', 'if(have&&!m16_journal_ack(m->journal,hex)){m->state=M16_S_RETAINED;return;}', 'if(have){(void)m16_journal_ack(m->journal,hex);m->state=M16_S_RETAINED;return;}', 'machine'),
    ('export failure drops the attempt', 'machine.c', 'if(sent<0){m->export_errors++;m16_journal_rewind(m->journal);}', 'if(sent<0)hold(m);', 'machine'),
    ('release without ACK', 'journal.c', 'if(j->state!=M16_J_ACKED)return -EBUSY;', '', 'journal'),
    ('ACK before the wire was sent', 'journal.c', 'if(j->export_offset<m16_journal_wire_size(j))return -EPERM;', '', 'journal'),
    ('sealed journal still writable', 'journal.c', ' if(j->state!=M16_J_OPEN)return -EPERM;\n if(!ordered(j,c))return -ERANGE;', ' if(!ordered(j,c))return -ERANGE;', 'journal'),
    ('sleep gap allowed to shrink', 'journal.c', 'return gap(c)+M16_JITTER_NS>=gap(&last);', 'return 1;', 'journal'),
    ('no space kept for the failure', 'journal.c', 'type==M16_EV_CLEANUP?1u:M16_RESERVED', '1u', 'journal'),
    ('chain not bound to the nonce', 'journal.c', 'memcpy(seed,nonce,16);', '', 'journal'),
    ('short write counted as whole', 'journal.c', 'j->export_offset=off+(uint64_t)n;', 'j->export_offset=off+(have-at);', 'journal'),
    ('RTC interrupt not required', 'oracle.c', 'if(c->post.rtc_irq-c->pre.rtc_irq!=1||c->post.alarm_enabled)return M16_V_WRONG_WAKE;', '', 'oracle'),
    ('CPUs not required to idle', 'oracle.c', 'if(!all_idled(c))return M16_V_INVALID;', '', 'oracle'),
    ('more than one cycle accepted', 'oracle.c', 'if(c->writer_errno||success!=1||fail', 'if(c->writer_errno||!success||fail', 'oracle'),
    ('late wake passes', 'oracle.c', 'if(slept>e->interval_ns+e->late_ns)return M16_V_LATE_WAKE;', '', 'oracle'),
    ('early wake passes', 'oracle.c', 'if(slept<e->interval_ns-e->early_ns)return M16_V_EARLY_WAKE;', '', 'oracle'),
    ('refusal accepted without its count', 'oracle.c', 'if(!success&&fail==1&&slept<M16_MIN_SLEEP_NS&&', 'if(', 'oracle'),
    ('two matching IRQ lines accepted', 'linux.c', 'if(found++)return -EEXIST;', 'found++;', 'linux'),
    ('name suffix matches a longer IRQ', 'linux.c', "&&line[n-name_n-1]==' '", '', 'linux'),
    ('CPU outside the known set accepted', 'linux.c', 'if(a>b||b>=M16_CPUS)return -EINVAL;', 'if(a>b)return -EINVAL;', 'linux'),
    ('every UDC treated as the emulator', 'linux.c', "if(e->d_name[0]!='.'&&!m16_udc_is_emulated(e->d_name))++*out;", '', 'integration'),
    ('the emulator counted as real USB', 'linux.c', "if(e->d_name[0]!='.'&&!m16_udc_is_emulated(e->d_name))++*out;", "if(e->d_name[0]!='.')++*out;", 'integration'),
    ('any name after the emulator prefix', 'linux.c', 'if(!isdigit((unsigned char)*p))return 0;', '', 'linux'),
    ('mark drops the run tag', 'mark.c', '*alarm=base|(uint64_t)tag<<4|(uint64_t)code;', '*alarm=base|(uint64_t)code;', 'mark'),
    ('mark accepts tag zero', 'mark.c', 'if(!alarm||!tag||code', 'if(!alarm||code', 'mark'),
    ('mark may overflow the register', 'mark.c', 'if(rtc_now>M16_MARK_MAX_RTC-M16_MARK_HORIZON_S)return -ERANGE;', '', 'mark'),
    ('a failure can read as a pass', 'mark.c', 'if(failed)return reached_suspend?M16_M_FAILED_AFTER_RESUME:M16_M_FAILED_BEFORE_SUSPEND;', '(void)failed;(void)reached_suspend;', 'mark'),
    ('unknown verdict reads as a pass', 'mark.c', 'default: return M16_M_INVALID;', 'default: return M16_M_PASS;', 'mark'),
)
FLAGS = ('-std=c11', '-O1', '-Wall', '-Wextra')


def build(source, names, target):
    subprocess.run(['gcc', *FLAGS, *(str(source / n) for n in names), '-o', str(target)], check=True, capture_output=True)


def fails(test, source, work):
    if test == 'journal':
        build(source, CORE + ('test-journal.c',), work / 't')
        return subprocess.run([str(work / 't')], capture_output=True).returncode != 0
    if test == 'machine':
        build(source, CORE + ('test-machine.c',), work / 't')
        return subprocess.run([str(work / 't'), str(work)], capture_output=True).returncode != 0
    if test == 'linux':
        build(source, ('linux.c', 'test-linux.c'), work / 't')
        return subprocess.run([str(work / 't')], capture_output=True).returncode != 0
    if test == 'mark':
        build(source, ('mark.c', 'test-mark.c'), work / 't')
        return subprocess.run([str(work / 't')], capture_output=True).returncode != 0
    build(source, CORE + ('linux.c', 'driver.c'), work / 'driver')
    group = 'Integration' if test == 'integration' else 'Oracle'
    return subprocess.run([sys.executable, str(HERE / 'test.py'), '--driver', str(work / 'driver'), '--out', str(work), '-f', group],
                          capture_output=True).returncode != 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    survivors, results = [], []
    for name, file, old, new, test in MUTANTS:
        with tempfile.TemporaryDirectory(prefix='m16-mutant-') as tmp:
            work = Path(tmp)
            source = work / 'scripts/m16/s2'
            source.mkdir(parents=True)
            for item in HERE.iterdir():
                if item.suffix in ('.c', '.h'):
                    shutil.copy(item, source)
            (work / SHA).parent.mkdir(parents=True)
            shutil.copy(ROOT / SHA, work / SHA)
            path = source / file
            text = path.read_text(encoding='utf-8')
            if text.count(old) != 1:
                sys.exit(f'mutant no longer applies: {name}')
            path.write_text(text.replace(old, new), encoding='utf-8')
            killed = fails(test, source, work)
            results.append({'mutant': name, 'test': test, 'killed': killed})
            print(('killed  ' if killed else 'SURVIVED'), name, flush=True)
            if not killed:
                survivors.append(name)
    args.out.write_text(json.dumps({'mutants': len(results), 'survivors': survivors, 'results': results}, indent=1), encoding='utf-8')
    return 1 if survivors else 0


if __name__ == '__main__':
    sys.exit(main())
