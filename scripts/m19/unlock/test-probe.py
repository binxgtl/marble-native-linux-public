#!/usr/bin/env python3
"""Run real binding/supervisor logic on typed fakes and read-only tmpfs fixtures.
No Android device, real Binder, key data or TEE. Root needed for private mounts.
"""
import argparse,hashlib,os,signal,subprocess,tempfile,time,unittest
from pathlib import Path

BINDING=PROBE=SUPERVISOR=None
FAULTS=('success','missing-library','missing-marker','missing-lookup','missing-service','null-level','level-error',
        'create-error','create-error-upgrade','empty-upgrade','null-operation','upgrade','update-error','update-throw',
        'update-oversize','finish-error','finish-throw','upgrade-then-fail','empty','convert-error','convert-error-upgrade',
        'convert-empty','convert-oversize','convert-throw','convert-upgrade')
GOOD={'success','upgrade'}
MOUNT='mount --bind "$1" "$1" && mount -o remount,bind,ro "$1" && exec "$2" --probe "$1"'

def command(binary,directory):
    return ['unshare','--mount','--propagation','private','sh','-c',MOUNT,'fixture',str(directory),binary]

class Binding(unittest.TestCase):
    def test_actual_binding_all_returned_paths(self):
        for fault in FAULTS:
            with self.subTest(fault=fault):
                p=subprocess.run([BINDING],env=dict(os.environ,M19_TEST_FAULT=fault),capture_output=True,text=True,timeout=10)
                self.assertEqual(p.returncode,0,p.stderr)
                self.assertIn('PASS actual binding paths',p.stdout)

class Probe(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'key';self.root.mkdir()
        for name,data in [('version',b'1'),('encrypted_key',b'X'*282),('keymaster_key_blob',b'B'*214),('secdiscardable',b'S'*16384)]:
            (self.root/name).write_bytes(data)
    def run_probe(self,fault='success',ro=True):
        env=dict(os.environ,M19_TEST_FAULT=fault)
        return subprocess.run(command(PROBE,self.root) if ro else [PROBE,'--probe',str(self.root)],
                              env=env,capture_output=True,text=True,timeout=10)
    def test_complete_and_all_binding_failures(self):
        before={p.name:(hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in self.root.iterdir()}
        for fault in FAULTS:
            with self.subTest(fault=fault):
                p=self.run_probe(fault)
                self.assertEqual(p.returncode,0 if fault in GOOD else 1,p.stdout+p.stderr)
                self.assertIn('reaped=1',p.stdout);self.assertIn('retry=0 r1=0',p.stdout)
                self.assertIn('final=OK' if fault in GOOD else 'final=ERROR',p.stdout)
                if fault in ('upgrade-then-fail','create-error-upgrade','convert-error-upgrade','convert-upgrade'):
                    self.assertIn('upgrade=UNKNOWN upgrade_observed=1',p.stdout)
                if fault=='success':self.assertIn('upgrade=NONE_OBSERVED upgrade_observed=0',p.stdout)
                if fault=='upgrade':self.assertIn('upgrade=OBSERVED upgrade_observed=1',p.stdout)
                self.assertNotIn('a5a5a5a5',p.stdout)
        after={p.name:(hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in self.root.iterdir()}
        self.assertEqual(before,after)
    def test_writable_mount_refused_before_lookup(self):
        p=self.run_probe(ro=False)
        self.assertEqual(p.returncode,1);self.assertIn('status=12',p.stdout)
        self.assertNotIn('stage=lookup',p.stdout);self.assertIn('upgrade=NOT_ATTEMPTED',p.stdout)
    def test_every_blocking_service_stage_is_bounded_and_unknown(self):
        for fault in ('lookup-block','level-block','create-block','update-block','finish-block','convert-block'):
            with self.subTest(fault=fault):
                start=time.monotonic();p=self.run_probe(fault)
                self.assertEqual(p.returncode,1);self.assertLess(time.monotonic()-start,6)
                self.assertIn('final=TIMEOUT',p.stdout);self.assertIn('remote=UNKNOWN',p.stdout)
                self.assertIn('upgrade=UNKNOWN',p.stdout);self.assertIn('reaped=1',p.stdout)
    def test_nonregular_symlink_and_pending_inputs_refused(self):
        p=self.root/'encrypted_key';p.unlink();os.mkfifo(p)
        r=self.run_probe();self.assertEqual(r.returncode,1);self.assertNotIn('stage=lookup',r.stdout)
        p.unlink();p.symlink_to('/dev/zero')
        r=self.run_probe();self.assertEqual(r.returncode,1);self.assertNotIn('stage=lookup',r.stdout)
        p.unlink();p.write_bytes(b'X'*282)
        (self.root/'keymaster_key_blob_upgraded').write_bytes(b'U')
        r=self.run_probe();self.assertEqual(r.returncode,1);self.assertNotIn('stage=lookup',r.stdout)
    def test_probe_has_no_normal_unlock_cli(self):
        for args in ([],['--probe'],['x','y','z','8'],['--probe','x','y','8']):
            p=subprocess.run([PROBE,*args],capture_output=True,timeout=5)
            self.assertEqual(p.returncode,64)
    def test_sigterm_is_failure_and_no_retry(self):
        p=subprocess.Popen(command(PROBE,self.root),env=dict(os.environ,M19_TEST_FAULT='create-block'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        lines=[]
        for _ in range(5):
            line=p.stdout.readline();lines.append(line)
            if 'stage=create' in line:break
        p.send_signal(signal.SIGTERM)
        out,err=p.communicate(timeout=6)
        self.assertEqual(p.returncode,1,err);self.assertIn('final=INTERRUPTED',out);self.assertIn('remote=UNKNOWN',out)

class Supervisor(unittest.TestCase):
    def test_crash_partial_protocol_duplicate_and_timeout(self):
        for mode in ('crash','partial','wrong-stage','duplicate','block'):
            with self.subTest(mode=mode):
                p=subprocess.run([SUPERVISOR,mode],capture_output=True,text=True,timeout=6)
                self.assertEqual(p.returncode,1);self.assertIn('remote=UNKNOWN',p.stdout)
                self.assertIn('reaped=1',p.stdout);self.assertNotIn('final=OK',p.stdout)
    def test_regular_output_refused(self):
        with tempfile.TemporaryFile() as f:
            p=subprocess.run([SUPERVISOR,'crash'],stdout=f,stderr=subprocess.PIPE,timeout=5)
            self.assertEqual(p.returncode,64)
    def test_closed_and_backpressured_output_fail(self):
        for fill in (False,True):
            r,w=os.pipe();os.set_blocking(w,False)
            if fill:
                try:
                    while True:os.write(w,b'X'*4096)
                except BlockingIOError:pass
            else:os.close(r)
            p=subprocess.Popen([SUPERVISOR,'block'],stdout=w,stderr=subprocess.PIPE)
            os.close(w)
            try:
                p.communicate(timeout=7);self.assertNotEqual(p.returncode,0)
            finally:
                if fill:os.close(r)

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--binding',required=True);a.add_argument('--probe',required=True);a.add_argument('--supervisor',required=True);x=a.parse_args()
    BINDING,PROBE,SUPERVISOR=map(os.path.abspath,(x.binding,x.probe,x.supervisor))
    if os.geteuid()!=0:raise SystemExit('Root required for synthetic read-only private mount; no tests skipped')
    unittest.main(argv=['probe-tests'],verbosity=2)
