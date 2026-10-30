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
    ('no mark after the cycle', ' write_mark(r);\n', ''),
    ('a failed colour still suspends', 'return rc?rc:r->display_failed?-ENODEV:0;', 'return rc;'),
    ('colour while the writer is stuck', 'if(!machine.writer_active)(void)paint(r,RED,r->final_ms);', '(void)paint(r,RED,r->final_ms);'),
    ('settling skipped', ' settle(r);\n', ''),
    ('export without the host hello', 'r->link=M16_LINK_HOST;\n  return 0;', 'r->link=M16_LINK_READY;\n  return 1;'),
    ('failed run shown as GREEN', 'outcome==M16_O_VERIFIED_PASS?GREEN:YELLOW', 'GREEN'),
    ('log hash does not cover the log', 'sha_update(&s,(const char *)log_bytes,(ulong)size);', 'sha_update(&s,(const char *)log_bytes,(ulong)size-1);'),
    ('resend keeps the old offset', ' m16_journal_rewind(&journal);\n', ''),
    ('bootstrap failure ignored', ' if(rc||status)return M16_END_BOOTSTRAP;\n', ''),
    ('a failed run marked as its verdict', 'm->failure!=M16_F_NONE', '0'),
    ('USB started before the mark', ' write_mark(r);\n char *argv[]={(char *)r->adsp,NULL};\n pid_t p=spawn_logged(argv);\n if(p<0)return -1;\n',
     ' char *argv[]={(char *)r->adsp,NULL};\n pid_t p=spawn_logged(argv);\n if(p<0)return -1;\n (void)poll(NULL,0,500);\n write_mark(r);\n'),
    ('connector failure ignored', 'if(strcmp(r->line,"CONNECTOR_READY"))return -1;\n', 'if(strcmp(r->line,"CONNECTOR_READY"))return 0;\n'),
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
