#!/usr/bin/env python3
"""Real C endpoint/supervisor with synthetic DSO only. No phone, keys or Binder."""
import argparse,ctypes,os,select,signal,subprocess,tempfile,time,unittest
from pathlib import Path

OUT=None;VARIANT=None
FAULTS={'':0,'missingendpoint':3,'classnull':4,'associatefalse':5,'wrongremote':5,'wrongdesc':6,
        'getClassnull':4,'getDescnull':6,'longdesc':6}
SYMBOLS=('AParcel_markSensitive','AServiceManager_checkService','AIBinder_Class_define',
         'AIBinder_associateClass','AIBinder_getClass','AIBinder_Class_getDescriptor','AIBinder_decStrong')
def exe(name):return str(OUT/(name+'-'+VARIANT))
def environment(fault='',hostile='success'):
    return dict(os.environ,M19_ENDPOINT_TEST_FAULT=fault,M19_ENDPOINT_HOSTILE=hostile,ASAN_OPTIONS='detect_leaks=0')
def invoke(name='endpoint',fault='',hostile='success'):
    return subprocess.run([exe(name),'--check'],env=environment(fault,hostile),capture_output=True,text=True,timeout=7)
def receipt(p):
    lines=p.stdout.splitlines();final=[s for s in lines if s.startswith('M19_ENDPOINT1 final=')]
    if len(final)!=1 or not lines or lines[-1]!=final[0] or not p.stdout.endswith('\n'):
        raise ValueError('missing/partial/duplicate terminal receipt')
    values=dict(item.split('=',1) for item in final[0].split()[1:])
    if values.get('final')=='OK':
        expected={'status':'0','errno':'0','flags':'31','reaped':'1','raw_wait':'0',
                  'descriptor':'android.system.keystore2.IKeystoreService','key_calls':'0','retry':'0','r1':'0'}
        if p.returncode!=0 or any(values.get(k)!=v for k,v in expected.items()):raise ValueError('inconsistent success')
        stages=[s.split('stage=')[1].split()[0] for s in lines[:-1] if 'event=begin' in s]
        if stages!=['load','symbols','lookup','descriptor','release']:raise ValueError('stage sequence')
    return values

class Endpoint(unittest.TestCase):
    def test_actual_core_and_supervised_returned_paths(self):
        for fault,status in FAULTS.items():
            with self.subTest(fault=fault):
                p=subprocess.run([exe('core'),str(status)],env=environment(fault),capture_output=True,text=True,timeout=7)
                self.assertEqual(p.returncode,0,p.stdout+p.stderr)
                p=invoke(fault=fault);r=receipt(p)
                self.assertEqual(p.returncode,0 if not status else 1,p.stdout+p.stderr)
                self.assertEqual(r['final'],'OK' if not status else 'ERROR',p.stdout)
                self.assertEqual(int(r['status']),status);self.assertEqual(r['reaped'],'1')
                if status:self.assertEqual(r['descriptor'],'UNVERIFIED')
    def test_every_required_symbol_missing_stops_before_lookup(self):
        for symbol in SYMBOLS:
            with self.subTest(symbol=symbol):
                p=subprocess.run([exe('core-omit-'+symbol),'2'],env=environment(),capture_output=True,text=True,timeout=7)
                self.assertEqual(p.returncode,0,p.stdout+p.stderr)
                p=invoke('endpoint-omit-'+symbol);r=receipt(p)
                self.assertEqual(p.returncode,1,p.stdout);self.assertEqual(r['status'],'2')
                self.assertNotIn('stage=lookup',p.stdout)
    def test_missing_library_has_no_lookup(self):
        p=invoke('endpoint-missing');r=receipt(p)
        self.assertEqual(p.returncode,1);self.assertEqual(r['status'],'1')
        self.assertNotIn('stage=symbols',p.stdout)
    def test_blocked_library_lookup_descriptor_release_are_bounded(self):
        for fault in ('block-loadctor','blocklookup','blockassoc','blockrelease'):
            with self.subTest(fault=fault):
                start=time.monotonic();p=invoke(fault=fault);r=receipt(p)
                self.assertLess(time.monotonic()-start,5);self.assertEqual(p.returncode,1)
                self.assertEqual(r['final'],'TIMEOUT');self.assertEqual(r['reaped'],'1')
                self.assertEqual(r['descriptor'],'UNVERIFIED')
    def test_unexpected_local_callback_fails_closed(self):
        p=invoke(fault='unexpectedcallback');r=receipt(p)
        self.assertEqual(p.returncode,1);self.assertNotEqual(r['final'],'OK');self.assertEqual(r['reaped'],'1')
    def test_no_arbitrary_endpoint_or_probe_or_key_cli(self):
        for args in ([],['--probe'],['--check','extra'],['--check','--check'],['other']):
            with self.subTest(args=args):
                p=subprocess.run([exe('endpoint'),*args],capture_output=True,text=True,timeout=5)
                self.assertEqual(p.returncode,64);self.assertEqual(p.stdout,'')
    def test_signal_stops_worker_without_retry(self):
        p=subprocess.Popen([exe('endpoint'),'--check'],env=environment('blocklookup'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        try:
            for _ in range(3):
                self.assertTrue(select.select([p.stdout],[],[],3)[0]);line=p.stdout.readline()
                if b'stage=lookup' in line:break
            p.send_signal(signal.SIGTERM);out,err=p.communicate(timeout=5)
            self.assertEqual(p.returncode,1,err);self.assertIn(b'final=INTERRUPTED',out);self.assertIn(b'reaped=1',out)
        finally:
            if p.poll() is None:p.kill();p.communicate(timeout=3)

class Supervisor(unittest.TestCase):
    def test_complete_worker(self):
        p=invoke('hostile');self.assertEqual(p.returncode,0,p.stdout+p.stderr);self.assertEqual(receipt(p)['final'],'OK')
    def test_hostile_frames_and_worker_exit_never_pass(self):
        for mode in ('crash','incomplete','partial','skip','duplicate','false-success','missing-release',
                     'flags-regress','descriptor-absent','success-errno','wrong-status','wrong-exit','trailing-byte'):
            with self.subTest(mode=mode):
                p=invoke('hostile',hostile=mode)
                self.assertEqual(p.returncode,1,p.stdout);r=receipt(p)
                self.assertNotEqual(r['final'],'OK');self.assertEqual(r['reaped'],'1')
    def test_regular_file_and_closed_standard_input_refused(self):
        with tempfile.TemporaryFile() as target:
            p=subprocess.run([exe('hostile'),'--check'],stdout=target,stderr=subprocess.PIPE,timeout=5)
            self.assertEqual(p.returncode,64)
        p=subprocess.run([exe('hostile'),'--check'],preexec_fn=lambda:os.close(0),capture_output=True,timeout=5)
        self.assertEqual(p.returncode,64)
    def test_closed_and_backpressured_output_fail(self):
        for fill in (False,True):
            r,w=os.pipe();os.set_blocking(w,False)
            if fill:
                try:
                    while True:os.write(w,b'x'*4096)
                except BlockingIOError:pass
            else:os.close(r)
            p=subprocess.Popen([exe('hostile'),'--check'],env=environment(hostile='block'),stdout=w,stderr=subprocess.PIPE)
            os.close(w)
            try:p.communicate(timeout=6);self.assertEqual(p.returncode,1)
            finally:
                if p.poll() is None:p.kill();p.communicate(timeout=3)
                if fill:os.close(r)
    def test_parent_death_stops_worker(self):
        libc=ctypes.CDLL(None,use_errno=True);old=ctypes.c_int()
        self.assertEqual(libc.prctl(37,ctypes.byref(old),0,0,0),0)
        self.assertEqual(libc.prctl(36,1,0,0,0),0)
        p=None;child=None;reaped=False
        try:
            p=subprocess.Popen([exe('hostile'),'--check'],env=environment(hostile='block'),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.assertTrue(select.select([p.stdout],[],[],3)[0]);self.assertIn(b'stage=load',p.stdout.readline())
            children=Path(f'/proc/{p.pid}/task/{p.pid}/children').read_text().split()
            self.assertEqual(len(children),1);child=int(children[0]);p.kill();p.communicate(timeout=3)
            deadline=time.monotonic()+1
            while time.monotonic()<deadline:
                got,status=os.waitpid(child,os.WNOHANG)
                if got==child:
                    reaped=True;self.assertTrue(os.WIFSIGNALED(status));self.assertEqual(os.WTERMSIG(status),signal.SIGKILL);break
                time.sleep(.01)
            self.assertTrue(reaped,'worker survived supervisor death')
        finally:
            if p and p.poll() is None:p.kill();p.communicate(timeout=3)
            if child and not reaped:
                try:os.kill(child,signal.SIGKILL);os.waitpid(child,0)
                except ProcessLookupError:pass
            self.assertEqual(libc.prctl(36,old.value,0,0,0),0)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--variant',choices=('normal','sanitize'),required=True)
    parser.add_argument('--case',choices=('parent-death','protocol'));a=parser.parse_args()
    OUT=a.out.resolve();VARIANT=a.variant
    cases={'parent-death':'Supervisor.test_parent_death_stops_worker','protocol':'Supervisor.test_hostile_frames_and_worker_exit_never_pass'}
    unittest.main(argv=['endpoint-tests']+([cases[a.case]] if a.case else []),verbosity=2)
