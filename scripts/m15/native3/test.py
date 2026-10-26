#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import argparse
import errno
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time
import unittest
from receiver import Receiver,host
from boundary import Boundary,KernelSpool,provenance

p=argparse.ArgumentParser();p.add_argument('--custodian',type=Path,required=True)
p.add_argument('--observer',type=Path,required=True);p.add_argument('--wire',type=Path,required=True)
ARGS,REST=p.parse_known_args()

class Link:
    def __init__(self,root,observer=None):
        self.p=subprocess.Popen([str(ARGS.custodian.resolve()),'--offline-fixture',
            str((observer or ARGS.observer).resolve()),str(root/'fixture'),'collect'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        self.selector=selectors.DefaultSelector();self.lines=[];self.pending=b'';self.raw=bytearray()
        for f in (self.p.stdout,self.p.stderr):
            os.set_blocking(f.fileno(),False);self.selector.register(f,selectors.EVENT_READ)
    def until(self,prefix,timeout=15):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            for i,line in enumerate(self.lines):
                if line.startswith(prefix):return self.lines.pop(i)
            for key,_ in self.selector.select(.05):
                raw=os.read(key.fileobj.fileno(),4096)
                if not raw:self.selector.unregister(key.fileobj);continue
                if key.fileobj is self.p.stdout:self.raw.extend(raw)
                else:
                    self.pending+=raw
                    while b'\n' in self.pending:
                        line,self.pending=self.pending.split(b'\n',1);self.lines.append(line)
            if self.p.poll() is not None and not self.selector.get_map():raise RuntimeError('custodian-lost: ownership/safety UNKNOWN')
        raise TimeoutError(prefix)
    def command(self,seq,payload,nonce=b'0102030405060708090a0b0c0d0e0f10'):
        self.p.stdin.write(b'M15IPC1 '+nonce+b' '+str(seq).encode()+b' '+payload);self.p.stdin.flush()
    def start(self):
        ready=self.until(b'READY ').split()
        self.command(0,b'M15PC1 '+ready[1]+b' '+ready[2]+b'\n');self.until(b'ISOLATE_BEGIN')
        self.command(1,b'ISOLATED 1 1\n');self.until(b'WALL_WAIT')
    def freeze(self):
        self.start();self.command(2,b'WALL 1 1\n');self.until(b'FROZEN')
    def export(self):
        self.command(3,b'PC 1\n');line=self.until(b'WAIT_ACK ')
        count=int(line.split()[1]);end=time.monotonic()+2
        while len(self.raw)<count and time.monotonic()<end:
            for key,_ in self.selector.select(.02):
                raw=os.read(key.fileobj.fileno(),4096)
                if key.fileobj is self.p.stdout:self.raw.extend(raw)
                elif raw:raise AssertionError('unexpected control')
        if len(self.raw)!=count:raise AssertionError('incomplete wire')
        return bytes(self.raw)
    def close(self):
        # TEST teardown only. Never a runtime recovery policy or safety proof.
        if self.p.poll() is None:os.killpg(self.p.pid,signal.SIGKILL)
        self.p.wait(timeout=5)
        self.selector.close()
        for f in (self.p.stdin,self.p.stdout,self.p.stderr):f.close()

class Integration(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.wire=ARGS.wire.read_bytes()
        files,_,_=host.decode(self.wire)
        for row in host.contract.o3.legacy.load(files['capture.raw']):
            if row.get('kind')=='read_end' and row['rc']==0:
                path=self.root/'fixture'/'class'/row['group']/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(row['value']+'\n')
    def link(self,observer=None):
        link=Link(self.root,observer);self.addCleanup(link.close);return link
    def receiver(self,**kw):
        r=Receiver(self.root/'capture',**kw);self.addCleanup(lambda:r.abort() if r.fd is not None else None);return r
    def test_full_custodian_o3_saved_replay_ack_with_unrelated_child(self):
        logger=subprocess.Popen(['sleep','30']);self.addCleanup(lambda:(logger.kill(),logger.wait()) if logger.poll() is None else None)
        l=self.link();l.freeze();raw=l.export();r=self.receiver()
        for at in range(0,len(raw),7):r.feed(raw[at:at+7])
        ack=r.finish(len(raw));l.command(4,ack);l.until(b'RECOVERED evidence_only')
        self.assertEqual(l.p.wait(timeout=5),0);self.assertIsNone(logger.poll())
        self.assertEqual((self.root/'capture').read_bytes(),raw)
    def test_missing_ack_retains_live_custodian(self):
        l=self.link();l.freeze();l.export();l.until(b'HOLD',5);self.assertIsNone(l.p.poll())
    def test_wrong_ack_retains_live_custodian(self):
        l=self.link();l.freeze();l.export();l.command(4,b'wrong\n');l.until(b'HOLD');self.assertIsNone(l.p.poll())
    def test_broken_reconnect(self):
        l=self.link();l.freeze();l.command(3,b'PC 0\n');l.until(b'HOLD');self.assertFalse(l.raw)
    def test_wrong_sequence(self):
        l=self.link();l.until(b'READY');l.command(1,b'wrong\n');l.until(b'HOLD')
    def test_wrong_nonce(self):
        l=self.link();l.until(b'READY');l.command(0,b'wrong\n',b'0'*32);l.until(b'HOLD')
    def test_parent_ipc_disconnect(self):
        l=self.link();l.start();l.p.stdin.close();l.until(b'HOLD');self.assertIsNone(l.p.poll())
    def test_partial_ipc(self):
        l=self.link();l.until(b'READY');l.p.stdin.write(b'M15IPC1 partial');l.p.stdin.flush();l.until(b'HOLD',5)
    def test_embedded_nul_cannot_hide_ipc_suffix(self):
        l=self.link();l.start();l.command(2,b'WALL 1 1\x00ignored\n');l.until(b'HOLD');self.assertFalse(l.raw)
    def test_unbind_failure_stops_before_collection(self):
        l=self.link();ready=l.until(b'READY').split();l.command(0,b'M15PC1 '+ready[1]+b' '+ready[2]+b'\n')
        l.until(b'ISOLATE');l.command(1,b'ISOLATED 1 0\n');l.until(b'HOLD');self.assertFalse(l.raw)
    def test_collector_exec_failure_retains_evidence(self):
        l=self.link(self.root/'absent');l.start();l.command(2,b'WALL 1 1\n');l.until(b'HOLD');self.assertFalse(l.raw)
    def test_custodian_death_before_collection_is_not_success(self):
        l=self.link();l.start();l.p.kill()
        with self.assertRaises(RuntimeError):l.until(b'RECOVERED')
    def test_custodian_death_after_freeze_loses_escrow(self):
        l=self.link();l.freeze();l.p.kill()
        with self.assertRaises(RuntimeError):l.until(b'RECOVERED')
    def test_receiver_short_writes_exact(self):
        r=self.receiver(write=lambda fd,b:os.write(fd,b[:3]));r.feed(self.wire)
        self.assertTrue(r.finish(len(self.wire)).startswith(b'M15ACK1 '))
    def test_receiver_zero_write(self):
        r=self.receiver(write=lambda fd,b:0)
        with self.assertRaises(OSError):r.feed(self.wire)
        with self.assertRaises(ValueError):r.finish(len(self.wire))
    def test_receiver_disk_full(self):
        def full(fd,b):raise OSError(errno.ENOSPC,'fixture')
        r=self.receiver(write=full)
        with self.assertRaises(OSError):r.feed(self.wire)
        self.assertTrue(r.failed)
    def test_receiver_flush_failure_no_ack(self):
        def fail(fd):raise OSError(errno.EIO,'fixture')
        r=self.receiver(sync=fail);r.feed(self.wire)
        with self.assertRaises(OSError):r.finish(len(self.wire))
        self.assertTrue(r.failed)
    def test_receiver_partial_capture_no_ack(self):
        r=self.receiver();r.feed(self.wire[:-1])
        with self.assertRaises(ValueError):r.finish(len(self.wire))
    def test_receiver_corrupt_capture_no_ack(self):
        r=self.receiver();r.feed(self.wire.replace(b'M15E1',b'M15E9',1))
        with self.assertRaises(ValueError):r.finish(len(self.wire))
    def test_receiver_reopen_corruption_no_ack(self):
        def corrupt(fd):
            os.fsync(fd)
            with (self.root/'capture').open('r+b') as f:f.write(b'X')
        r=self.receiver(sync=corrupt);r.feed(self.wire)
        with self.assertRaises(ValueError):r.finish(len(self.wire))
    def test_receiver_no_overwrite(self):
        r=self.receiver();r.feed(b'original')
        with self.assertRaises(FileExistsError):Receiver(self.root/'capture')
    def test_receiver_abort_no_ack(self):
        r=self.receiver();r.feed(self.wire);r.abort()
        with self.assertRaises(ValueError):r.finish(len(self.wire))
    def test_receiver_receipt_collision_no_ack(self):
        r=self.receiver();r.feed(self.wire);(self.root/'capture.receipt.json').write_text('original')
        with self.assertRaises(FileExistsError):r.finish(len(self.wire))
    def test_receiver_chunk_boundaries_identical(self):
        r=self.receiver()
        for at in range(0,len(self.wire),511):r.feed(self.wire[at:at+511])
        ack=r.finish(len(self.wire));self.assertEqual(ack,host.decode(self.wire)[2])
    def test_receiver_budget(self):
        r=self.receiver()
        with self.assertRaises(ValueError):r.feed(b'x'*(16*1024*1024+1))
    def test_boundary_full_synthetic_connector_lifecycle(self):
        b=Boundary('1'*32)
        rows=[('admission','admitted',{'host_receipt':True}),
              ('unbind','isolated',{'transmitter_reaped':True,'unbind_readback_empty':True}),
              ('attachment','attached',{'operator_declared_wall':True,'pc_absent':True}),
              (None,'frozen',{'collector_receipt':True,'census_closed':True}),
              ('rebind','connected',{'pc_configured':True}),
              (None,'ack',{'saved_file_verified':True,'ack_bound':True})]
        for seq,(call,event,facts) in enumerate(rows):
            if call:b.call_begin(call);b.call_end(call,0,0)
            if event=='frozen':b.own(123,456,collector=True);b.reaped(123,456,0)
            b.event(seq,'1'*32,event,facts)
        self.assertTrue(b.release_permitted)
    def test_boundary_real_errno_and_missing_return(self):
        b=Boundary('1'*32);b.call_begin('admission')
        with self.assertRaises(ValueError):b.call_end('admission',-1,5)
        self.assertEqual(b.journal[-1],('end','admission',-1,5));self.assertFalse(b.release_permitted)
        b=Boundary('1'*32);b.call_begin('admission');b.timeout()
        self.assertEqual(b.journal,[('begin','admission')]);self.assertFalse(b.release_permitted)
    def test_boundary_forged_events(self):
        for seq,run,facts in [(1,'1'*32,{'host_receipt':True}),
                              (0,'2'*32,{'host_receipt':True}),
                              (0,'1'*32,{'host_receipt':1}),
                              (0,'1'*32,{'host_receipt':True,'extra':True})]:
            b=Boundary('1'*32);b.call_begin('admission');b.call_end('admission',0,0)
            with self.assertRaises(ValueError):b.event(seq,run,'admitted',facts)
            self.assertFalse(b.release_permitted)
    def test_boundary_custodian_loss_every_phase(self):
        for phase in ('pc','isolate','wall','collect','reconnect','export','recovered'):
            b=Boundary('1'*32);b.own(123,456);b.phase=phase;b.reaped(123,456,9,custodian=True)
            self.assertTrue(b.escrow_lost);self.assertFalse(b.release_permitted)
    def test_boundary_empty_owners_reject_freeze_ack_and_release(self):
        for phase,event,facts in [('collect','frozen',{'collector_receipt':True,'census_closed':True}),
                                  ('export','ack',{'saved_file_verified':True,'ack_bound':True})]:
            b=Boundary('1'*32);b.phase=phase
            with self.assertRaises(ValueError):b.event(0,'1'*32,event,facts)
            self.assertTrue(b.failed);self.assertFalse(b.release_permitted)
        b=Boundary('1'*32);b.phase='recovered';self.assertFalse(b.release_permitted)
    def test_boundary_worker_cannot_substitute_for_collector(self):
        b=Boundary('1'*32);b.phase='collect';b.own(123,456);b.reaped(123,456,0)
        with self.assertRaises(ValueError):b.event(0,'1'*32,'frozen',{'collector_receipt':True,'census_closed':True})
        self.assertFalse(b.release_permitted)
    def test_boundary_terminal_wait_validation(self):
        for status in (None,False,True,-1,65536,0x137f,0xffff,0x10009,0x80,0x7f,0x41,'0'):
            b=Boundary('1'*32);b.phase='collect';b.own(123,456,collector=True)
            with self.assertRaises(ValueError):b.reaped(123,456,status)
            self.assertIsNone(b.owners[(123,456)]);self.assertFalse(b.release_permitted)
    def test_boundary_failed_terminal_wait_is_recorded_but_never_releases(self):
        for status in (256,9,0x89,0xff00):
            b=Boundary('1'*32);b.phase='collect';b.own(123,456,collector=True);b.reaped(123,456,status)
            self.assertEqual(b.owners[(123,456)],status);self.assertTrue(b.failed)
            with self.assertRaises(ValueError):b.event(0,'1'*32,'frozen',{'collector_receipt':True,'census_closed':True})
            self.assertFalse(b.release_permitted)
    def test_boundary_unreaped_worker_blocks_completed_collector(self):
        b=Boundary('1'*32);b.phase='collect';b.own(123,456,collector=True);b.own(124,457);b.reaped(123,456,0)
        with self.assertRaises(ValueError):b.event(0,'1'*32,'frozen',{'collector_receipt':True,'census_closed':True})
        self.assertFalse(b.release_permitted)
    def test_boundary_duplicate_collector_and_postfreeze_owner_rejected(self):
        b=Boundary('1'*32);b.phase='collect';b.own(123,456,collector=True)
        with self.assertRaises(ValueError):b.own(124,457,collector=True)
        b=Boundary('1'*32);b.phase='collect';b.own(123,456,collector=True);b.reaped(123,456,0)
        b.event(0,'1'*32,'frozen',{'collector_receipt':True,'census_closed':True})
        with self.assertRaises(ValueError):b.own(124,457)
    def test_boundary_unknown_or_duplicate_reap(self):
        b=Boundary('1'*32);b.own(123,456)
        with self.assertRaises(ValueError):b.reaped(123,457,0)
        self.assertFalse(b.release_permitted)
    def test_kernel_spool_exact_bytes_and_freeze(self):
        s=KernelSpool(128);raw=b'6,101,999,-;fixture\n';s.append(raw)
        self.assertEqual(s.freeze()[0],raw)
        with self.assertRaises(ValueError):s.append(raw)
    def test_kernel_spool_loss_duplicate_and_overflow(self):
        for second in (b'6,101,1000,-;duplicate\n',b'6,103,1000,-;gap\n',b'broken\n',b'x'*200):
            s=KernelSpool(128);s.append(b'6,101,999,-;fixture\n')
            with self.assertRaises(ValueError):s.append(second)
            with self.assertRaises(ValueError):s.freeze()
    def test_provenance_never_promotes_native_or_android(self):
        v={k:'a'*64 for k in ('source','observer','launcher','kernel','closure','firmware','topology','evidence_path')}
        v.update(schema='M15-native-integration-fixture-v1',synthetic_only=True,
                 launcher_kind='dedicated-custodian',control_permitted=False,sealed_baseline=False)
        self.assertFalse(provenance(v)['comparison_eligible'])
        for key,value in [('synthetic_only',False),('launcher_kind','android-termux'),('control_permitted',True),('observer','bad')]:
            with self.assertRaises(ValueError):provenance(dict(v,**{key:value}))

if __name__=='__main__':unittest.main(argv=['test.py']+REST)
