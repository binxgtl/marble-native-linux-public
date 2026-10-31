#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Proves the Run1 tests can fail: breaks one guarantee at a time and requires a failure."""
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
CORE = ('journal.c', 'oracle.c', 'machine.c', 'mark.c', 'linux.c')
# name, exact text in run.c, replacement
MUTANTS = (
    ('no mark after the cycles', ' write_mark(r);\n', ''),
    ('a failed colour still suspends', 'return rc?rc:r->display_failed?-ENODEV:0;', 'return rc;'),
    ('colour while the writer is stuck', 'if(!r->cycles||!machines[r->cycles-1].writer_active)(void)paint(r,RED,r->final_ms);', '(void)paint(r,RED,r->final_ms);'),
    ('settling skipped', ' settle(r);\n log_value(', ' log_value('),
    ('UDC names not logged', ' log_dir(r,"/sys/class/udc");\n', ''),
    ('no quiet period after the panel disable', 'if(now>=end||(now>=quiet&&(rc||!p.wake_active))){', 'if(now>=end||rc||!p.wake_active){'),
    ('SPI state not logged', ' log_value(r,"/sys/bus/platform/devices/990000.spi/power/runtime_status");\n', ''),
    ('export without the host hello', 'r->link=M16_LINK_HOST;\n  return 0;', 'r->link=M16_LINK_READY;\n  return 1;'),
    ('failed run shown as GREEN', 'r->all_ok?GREEN:YELLOW', 'GREEN'),
    ('log hash does not cover the log', 'sha_update(&s,(const char *)log_bytes,(ulong)size);', 'sha_update(&s,(const char *)log_bytes,(ulong)size-1);'),
    ('resend keeps the old offset', ' m16_journal_rewind(j);\n', ''),
    ('bootstrap failure ignored', ' if(rc||status)return M16_END_BOOTSTRAP;\n', ''),
    ('a failed cycle marked as its verdict', 'm16_mark_code(m->verdict,m->failure!=M16_F_NONE,', 'm16_mark_code(M16_V_PASS,0,'),
    ('USB started before the mark', ' write_mark(r);\n if(bring_up_link(r)||export_cycles(r))return hold(r);\n',
     ' if(bring_up_link(r)){write_mark(r);return hold(r);}\n write_mark(r);\n if(export_cycles(r))return hold(r);\n'),
    ('connector failure ignored', 'if(strcmp(r->line,"CONNECTOR_READY"))return -1;\n', 'if(strcmp(r->line,"CONNECTOR_READY"))return 0;\n'),
    ('a failed cycle keeps looping', 'if(!cycle_passed(&machines[i])){good=0;r->all_ok=0;return 0;}', 'if(!cycle_passed(&machines[i]))good=0;'),
    ('changed storage ignored', 'if(!rc&&strcmp(hash,r->baseline))rc=-EBADMSG;\n', ''),
    ('a failed flash ignored', 'if((r->storage_ready&&check_storage(r))||check_display(r)){r->all_ok=0;return 0;}', 'if(r->storage_ready)(void)check_storage(r);'),
    ('touch not required', 'if(r->touch_events<TOUCH_MIN_EVENTS)good=0;', ''),
    ('events of any type count as touch', 'if(e[i].type==EV_ABS_TYPE)r->touch_events++;', 'r->touch_events++;'),
    ('an RTC wake counts as the key', 'r->key_ok=m->verdict==M16_V_EARLY_WAKE&&!m->failure&&m->cycle.post.rtc_irq==m->cycle.pre.rtc_irq;', 'r->key_ok=!m->failure;'),
    ('the same nonce for every cycle', 'nonce[15]^=(unsigned char)(i+1);', ''),
    ('only the last cycle exported', 'for(unsigned i=0;i<r->cycles;i++){\n  struct m16_machine *m=&machines[i];\n  r->current=i;', 'for(unsigned i=r->cycles-1;i<r->cycles;i++){\n  struct m16_machine *m=&machines[i];\n  r->current=i;'),
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    survivors, results = [], []
    for name, old, new in MUTANTS:
        with tempfile.TemporaryDirectory(prefix='m16-run1-mutant-') as tmp:
            work = Path(tmp)
            s2, run1 = work / 'scripts/m16/s2', work / 'scripts/m16/run1'
            shutil.copytree(HERE.parent / 's2', s2, ignore=shutil.ignore_patterns('__pycache__'))
            shutil.copytree(HERE, run1, ignore=shutil.ignore_patterns('__pycache__'))
            (work / SHA).parent.mkdir(parents=True)
            shutil.copy(ROOT / SHA, work / SHA)
            path = run1 / 'run.c'
            text = path.read_text(encoding='utf-8')
            if text.count(old) != 1:
                sys.exit(f'mutant no longer applies: {name}')
            path.write_text(text.replace(old, new), encoding='utf-8')
            driver = work / 'driver'
            subprocess.run(['gcc', '-std=c11', '-O1', *(str(s2 / n) for n in CORE), str(run1 / 'run.c'), str(run1 / 'test-run.c'), '-o', str(driver)],
                           check=True, capture_output=True)
            killed = subprocess.run([sys.executable, str(HERE / 'test.py'), '--driver', str(driver), '-f', 'Run'],
                                    capture_output=True).returncode != 0
            results.append({'mutant': name, 'killed': killed})
            print(('killed  ' if killed else 'SURVIVED'), name, flush=True)
            if not killed:
                survivors.append(name)
    args.out.write_text(json.dumps({'mutants': len(results), 'survivors': survivors, 'results': results}, indent=1), encoding='utf-8')
    return 1 if survivors else 0


if __name__ == '__main__':
    sys.exit(main())
