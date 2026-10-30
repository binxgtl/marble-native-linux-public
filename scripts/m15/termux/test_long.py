#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Linux offline root harness for long.sh; synthetic files only, never a phone or host /sys."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
import verify_long

p=argparse.ArgumentParser();p.add_argument('--binary',required=True,type=Path)
args,extra=p.parse_known_args();BINARY=args.binary.resolve()
HERE=Path(__file__).resolve().parent
base=verify_long.base
ARGS='--sysfs --samples 10 --interval-ms 10000 --deadline-ms 120000'

class Long(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.getuid(),0,'CI must run this RAM-only Linux harness via sudo')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.host=Path(self.tmp.name)
        self.session=self.host/('m15-o3-test-'+uuid.uuid4().hex)
        self.session.mkdir(mode=0o700);self.addCleanup(lambda:shutil.rmtree(self.session,ignore_errors=True))
        self.bin=self.host/'bin';self.bin.mkdir();self.tree=self.host/'fixture'
        self.env=os.environ.copy()
        # As in test.py: production keeps its /dev tmpfs rule, the test copy swaps only the prefix.
        original=(HERE/'long.sh').read_text()
        self.assertEqual(original.count('PATH=/system/bin:/system/xbin'),1)
        self.assertEqual(original.count('/dev/'),2)
        (self.session/'long.sh').write_text(original.replace('PATH=/system/bin:/system/xbin',f'PATH={self.bin}:/usr/bin:/bin').replace('/dev/',str(self.host)+'/'))
        self.put_tool('stat','if [ "$1" = -f ]; then printf "%s\\n" "${M15_MOCK_FS:-tmpfs}"; else exec /usr/bin/stat "$@"; fi')
        self.put_tool('id','if [ -n "${M15_MOCK_UID:-}" ]; then printf "%s\\n" "$M15_MOCK_UID"; else exec /usr/bin/id "$@"; fi')
        fixture=HERE.parent/'o3_integration/fixtures/android.synthetic.jsonl'
        for row in base.contract.o3.legacy.load(fixture.read_bytes()):
            if row.get('kind')=='read_end' and row['rc']==0:
                path=self.tree/'class'/row['group']/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(row['value']+'\n')
        manifest=json.loads((HERE.parent/'o3_integration/fixtures/topology.synthetic.json').read_bytes())
        manifest.update(power_source='wall-charger',evidence_path='ram-offline')
        (self.session/'topology.json').write_text(json.dumps(manifest)+'\n')
        self.topology=base.sha((self.session/'topology.json').read_bytes())
        self.trace=self.host/'trace'
        # Records the production arguments, then runs the real C observer quickly on the fixture.
        (self.session/'observer').write_text(f'''#!/bin/sh
printf '%s\\n' "$*" >> '{self.trace}'
if [ "${{M15_CASE:-}}" = failed-child ]; then printf 'partial\\n'; printf 'fixture failure\\n' >&2; exit 9; fi
exec '{BINARY}' --fixture-root '{self.tree}' --samples "${{M15_SAMPLES:-10}}" --interval-ms 5 --deadline-ms 120000
''');(self.session/'observer').chmod(0o700)
        self.observer_sha=base.sha((self.session/'observer').read_bytes())
        self.runner_sha=base.sha((self.session/'long.sh').read_bytes())
    def put_tool(self,name,body):
        target=self.bin/name;target.write_text('#!/bin/sh\n'+body+'\n');target.chmod(0o700)
    def run_it(self,binary=None,**env):
        return subprocess.run(['/bin/sh',str(self.session/'long.sh'),str(self.session),binary or self.observer_sha,self.topology],
                              capture_output=True,env={**self.env,**env},timeout=30)
    def check(self):
        return verify_long.verify(self.session,self.topology,observer_sha=self.observer_sha,runner_sha=self.runner_sha)
    def index(self):
        folder=self.session/'long'
        (folder/'SHA256SUMS').write_bytes(b''.join((base.sha((folder/name).read_bytes())+'  '+name+'\n').encode() for name in sorted(base.FILES)))
    def test_real_wrapper_and_exact_arguments(self):
        result=self.run_it();self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.trace.read_text().strip(),ARGS)
        report=self.check();self.assertEqual(report['samples'],10);self.assertEqual(report['telemetry'],'READABLE')
        self.assertFalse(report['sealed_baseline']);self.assertFalse(report['control_permitted'])
        for key in ('freshness','negotiated_contract','protection_active'):self.assertEqual(report[key],'UNKNOWN')
    def test_refusals_run_no_observer(self):
        cases=[({'binary':'0'*64},{}),({},{'M15_MOCK_UID':'1000'}),({},{'M15_MOCK_FS':'ext4'})]
        for kw,env in cases:
            self.assertEqual(self.run_it(**kw,**env).returncode,70);self.assertFalse(self.trace.exists())
            self.assertFalse((self.session/'long').exists())
    def test_output_is_never_overwritten(self):
        self.assertEqual(self.run_it().returncode,0)
        self.assertEqual(self.run_it().returncode,70);self.assertEqual(len(self.trace.read_text().splitlines()),1)
    def test_session_path_is_restricted(self):
        result=subprocess.run(['/bin/sh',str(self.session/'long.sh'),'/tmp/elsewhere',self.observer_sha,self.topology],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,70);self.assertFalse(self.trace.exists())
    def test_failed_child_is_preserved_and_refused(self):
        result=self.run_it(M15_CASE='failed-child');self.assertEqual(result.returncode,9)
        self.assertEqual((self.session/'long/capture.exit').read_bytes(),b'9\n')
        with self.assertRaises(ValueError):self.check()
    def test_tampering_is_refused(self):
        self.assertEqual(self.run_it().returncode,0)
        target=self.session/'long/capture.raw';original=target.read_bytes()
        target.write_bytes(original+b'x')
        with self.assertRaises(ValueError):self.check()
        self.index()
        with self.assertRaises(ValueError):self.check() # rehashed, but no longer a complete transcript
        target.write_bytes(original);self.index();self.check()
        (self.session/'long.sh').write_text('changed')
        with self.assertRaises(ValueError):self.check()
    def test_three_samples_are_not_the_long_window(self):
        self.assertEqual(self.run_it(M15_SAMPLES='3').returncode,0)
        with self.assertRaises(ValueError):self.check()
    def test_record_cannot_grant_anything(self):
        self.assertEqual(self.run_it().returncode,0)
        path=self.session/'long/record.json';record=json.loads(path.read_bytes());record['control_permitted']=True
        path.write_text(json.dumps(record));self.index()
        with self.assertRaises(ValueError):self.check()
    def test_wrapper_stays_read_only(self):
        code='\n'.join(l for l in (HERE/'long.sh').read_text().splitlines() if not l.startswith('#'))
        self.assertNotRegex(code,r'\b(su|adb|mount|setenforce|reboot)\b|/sys/|/data/|/sdcard')
        self.assertEqual(code.count('./observer'),1);self.assertIn('./observer '+ARGS+' >',code)

if __name__=='__main__':
    unittest.main(argv=[sys.argv[0],*extra])
