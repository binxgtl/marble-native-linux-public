#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Linux offline root harness; synthetic files only, never a phone or host /sys."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
import verify

p=argparse.ArgumentParser();p.add_argument('--binary',required=True,type=Path)
args,extra=p.parse_known_args();BINARY=args.binary.resolve()
HERE=Path(__file__).resolve().parent

class Workflow(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.getuid(),0,'CI must run this RAM-only Linux harness via sudo')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.host=Path(self.tmp.name)
        self.session=Path('/dev')/('m15-o3-test-'+uuid.uuid4().hex)
        self.session.mkdir(mode=0o700);self.addCleanup(lambda:shutil.rmtree(self.session))
        self.bin=self.host/'bin';self.bin.mkdir();self.tree=self.host/'fixture'
        self.env=os.environ.copy()
        # Only production PATH is replaced. Mock filesystem type/uid tools expose
        # guard faults; all other wrapper logic and shell process control is real.
        original=(HERE/'capture.sh').read_text()
        self.assertEqual(original.count('PATH=/system/bin:/system/xbin'),1)
        self.runner=original.replace('PATH=/system/bin:/system/xbin',f'PATH={self.bin}:/usr/bin:/bin')
        (self.session/'capture.sh').write_text(self.runner)
        self.put_tool('stat','if [ "$1" = -f ]; then printf "%s\\n" "${M15_MOCK_FS:-tmpfs}"; else exec /usr/bin/stat "$@"; fi')
        self.put_tool('id','if [ -n "${M15_MOCK_UID:-}" ]; then printf "%s\\n" "$M15_MOCK_UID"; else exec /usr/bin/id "$@"; fi')
        fixture=HERE.parent/'o3_integration/fixtures/android.synthetic.jsonl'
        for row in verify.contract.o3.legacy.load(fixture.read_bytes()):
            if row.get('kind')=='read_end' and row['rc']==0:
                path=self.tree/'class'/row['group']/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(row['value']+'\n')
        manifest=json.loads((HERE.parent/'o3_integration/fixtures/topology.synthetic.json').read_bytes())
        manifest.update(power_source='wall-charger',evidence_path='ram-offline')
        (self.session/'topology.json').write_text(json.dumps(manifest)+'\n')
        self.topology=verify.sha((self.session/'topology.json').read_bytes())
        self.trace=self.host/'trace'
        self.observer=f'''#!/bin/sh
printf '%s\\n' "$*" >> '{self.trace}'
if [ "$#" -eq 0 ]; then
 [ "${{M15_CASE:-}}" != bad-noargs ] || exit 1
 exec '{BINARY}'
fi
if [ "${{M15_CASE:-}}" = failed-child ]; then printf 'partial\\n'; printf 'fixture failure\\n' >&2; exit 9; fi
if [ "${{M15_CASE:-}}" = timeout ]; then printf 'partial\\n'; printf '{{"supervisor":"FAIL","errno":110,"reaped":true}}\\n' >&2; exit 1; fi
if [ "$1" = --sysfs ]; then shift; exec '{BINARY}' --fixture-root '{self.tree}' "$@"; fi
exec '{BINARY}' "$@"
'''
        (self.session/'observer').write_text(self.observer);(self.session/'observer').chmod(0o700)
        self.observer_sha=verify.sha((self.session/'observer').read_bytes())
        self.runner_sha=verify.sha((self.session/'capture.sh').read_bytes())
    def put_tool(self,name,body):
        target=self.bin/name;target.write_text('#!/bin/sh\n'+body+'\n');target.chmod(0o700)
    def run_phase(self,phase='qualify',**env):
        return subprocess.run(['/bin/sh',str(self.session/'capture.sh'),phase,str(self.session),self.observer_sha,self.topology],
                              capture_output=True,env={**self.env,**env},timeout=15)
    def verify(self,phase='qualify'):
        return verify.verify(self.session,phase,self.topology,observer_sha=self.observer_sha,runner_sha=self.runner_sha)
    def qualify(self):
        result=self.run_phase();self.assertEqual(result.returncode,0,result.stderr)
        report=self.verify();self.assertEqual(report['telemetry'],'BLOCKED')
        (self.session/'qualification.ok').write_text(report['hash_index_sha256']+'\n')
        return report
    def index(self,phase='qualify'):
        folder=self.session/phase;names=verify.FILES|(verify.NOARGS if phase=='qualify' else set())
        (folder/'SHA256SUMS').write_bytes(b''.join((verify.sha((folder/name).read_bytes())+'  '+name+'\n').encode() for name in sorted(names)))
    def mutate_raw(self,mutator):
        target=self.session/'qualify/capture.raw';rows=verify.contract.o3.legacy.load(target.read_bytes())
        mutator(rows);target.write_bytes(b''.join((json.dumps(r)+'\n').encode() for r in rows));self.index()
    def test_real_wrapper_real_c_qualification_and_capture(self):
        self.qualify();trace=self.trace.read_text();self.assertNotIn('--sysfs',trace)
        result=self.run_phase('acquire');self.assertEqual(result.returncode,0,result.stderr)
        report=self.verify('acquire');self.assertEqual(report['telemetry'],'READABLE')
        self.assertEqual(report['android_termux_launch'],'UNKNOWN');self.assertFalse(report['sealed_baseline'])
        rows=verify.contract.o3.legacy.load((self.session/'acquire/capture.raw').read_bytes())
        self.assertEqual(rows[0]['samples'],3)
        self.assertIn('--sysfs --samples 3 --interval-ms 1000 --deadline-ms 90000',self.trace.read_text())
    def test_acquire_without_admission_never_executes(self):
        self.assertNotEqual(self.run_phase('acquire').returncode,0);self.assertFalse(self.trace.exists())
        self.assertFalse((self.session/'acquire').exists())
    def test_no_overwrite_or_automatic_retry(self):
        self.qualify();before=(self.session/'qualify/capture.raw').read_bytes();trace=self.trace.read_bytes()
        self.assertNotEqual(self.run_phase().returncode,0)
        self.assertEqual(before,(self.session/'qualify/capture.raw').read_bytes());self.assertEqual(trace,self.trace.read_bytes())
    def test_uid_and_filesystem_guard(self):
        for fault in ({'M15_MOCK_UID':'2000'},{'M15_MOCK_FS':'f2fs'}):
            self.assertNotEqual(self.run_phase(**fault).returncode,0)
        self.assertFalse(self.trace.exists())
    def test_hash_mismatch_and_symlink_payload(self):
        target=self.session/'observer';target.write_text(self.observer+'\n')
        self.assertNotEqual(self.run_phase().returncode,0);target.unlink();target.symlink_to(BINARY)
        self.assertNotEqual(self.run_phase().returncode,0);self.assertFalse(self.trace.exists())
    def test_noargs_failure_blocks_collection(self):
        self.assertNotEqual(self.run_phase(M15_CASE='bad-noargs').returncode,0)
        self.assertFalse((self.session/'qualify/capture.raw').exists())
    def test_child_exit_and_stderr_preserved(self):
        result=self.run_phase(M15_CASE='failed-child');self.assertEqual(result.returncode,9)
        self.assertEqual((self.session/'qualify/capture.exit').read_bytes(),b'9\n')
        self.assertEqual((self.session/'qualify/capture.stderr').read_bytes(),b'fixture failure\n')
        with self.assertRaises(ValueError):self.verify()
    def test_timeout_and_incomplete_receipt_rejected(self):
        self.assertEqual(self.run_phase(M15_CASE='timeout').returncode,1)
        with self.assertRaises(ValueError):self.verify()
        self.assertFalse((self.session/'qualification.ok').exists())
    def test_missing_terminal_frame_with_repaired_hash_is_rejected(self):
        self.qualify();target=self.session/'qualify/capture.raw';target.write_bytes(b'\n'.join(target.read_bytes().splitlines()[:-1])+b'\n');self.index()
        with self.assertRaises(ValueError):self.verify()
    def test_mixed_schema_and_wrong_contract_with_repaired_hash(self):
        self.qualify();original=(self.session/'qualify/capture.raw').read_bytes()
        for mutate in (lambda r:r[1].update(schema='M15O2'),lambda r:r[0].update(power_supply_contract='unknown')):
            (self.session/'qualify/capture.raw').write_bytes(original);self.mutate_raw(mutate)
            with self.assertRaises(ValueError):self.verify()
    def test_original_bytes_not_reserialized_digest(self):
        self.qualify();target=self.session/'qualify/capture.raw'
        rows=verify.contract.o3.legacy.load(target.read_bytes());target.write_bytes(b''.join((json.dumps(r)+'\n').encode() for r in rows))
        with self.assertRaises(ValueError):self.verify()
    def test_unexpected_stderr_cannot_be_admitted(self):
        self.qualify();(self.session/'qualify/capture.stderr').write_bytes(b'error\n');self.index()
        with self.assertRaises(ValueError):self.verify()
    def test_wrong_topology_and_extra_metadata(self):
        self.qualify();target=self.session/'topology.json';target.write_bytes(target.read_bytes()+b' ')
        with self.assertRaises(ValueError):self.verify()
    def test_qualifier_cannot_use_readable_fixture_as_empty_tree(self):
        self.qualify();self.mutate_raw(lambda rows:rows[2].update(rc=0,errno=0,value='Battery'))
        with self.assertRaises(ValueError):self.verify()
    def test_mutated_inputs_and_changed_qualification_block_acquisition(self):
        self.qualify();(self.session/'qualify/capture.raw').write_bytes(b'changed')
        self.assertNotEqual(self.run_phase('acquire').returncode,0);self.assertFalse((self.session/'acquire').exists())
    def test_bad_admission_marker_blocks_before_exec(self):
        self.qualify();before=self.trace.read_bytes();(self.session/'qualification.ok').write_text('0'*64+'\n')
        self.assertNotEqual(self.run_phase('acquire').returncode,0);self.assertEqual(before,self.trace.read_bytes())
    def test_hash_index_missing_duplicate_traversal_and_corruption(self):
        self.qualify();target=self.session/'qualify/SHA256SUMS';good=target.read_bytes()
        for bad in (good[:-1],good+good.splitlines()[0]+b'\n',good.replace(b'capture.raw',b'../capture.raw'),good.replace(b'  ',b' ',1)):
            target.write_bytes(bad)
            with self.assertRaises(ValueError):self.verify()
    def test_linked_evidence_and_metadata_bool_coercion_rejected(self):
        self.qualify();target=self.session/'qualify/record.json';original=target.read_bytes()
        for field,value in [('process_rc',False),('sealed_baseline',0),('control_permitted',0)]:
            record=json.loads(original);record[field]=value;target.write_text(json.dumps(record));self.index()
            with self.assertRaises(ValueError):self.verify()
        target.unlink();other=self.host/'other.json';other.write_bytes(original);target.symlink_to(other);self.index()
        with self.assertRaises(ValueError):self.verify()
    def test_cli_rejects_private_input_without_echo(self):
        result=subprocess.run([sys.executable,str(HERE/'verify.py'),'--session',str(self.session),
                               '--phase','qualify','--topology-file-sha256','PRIVATE-FIXTURE-DO-NOT-ECHO'],capture_output=True)
        self.assertEqual(result.returncode,1);self.assertNotIn(b'PRIVATE-FIXTURE-DO-NOT-ECHO',result.stdout+result.stderr)
        report=json.loads(result.stdout);self.assertFalse(report['control_permitted']);self.assertFalse(report['sealed_baseline'])

if __name__=='__main__':unittest.main(argv=[sys.argv[0],*extra])
