#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent host versus real C escrow/supervision, synthetic offline only."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import host

p=argparse.ArgumentParser();p.add_argument('--driver',required=True,type=Path)
p.add_argument('--observer',required=True,type=Path);p.add_argument('--out',required=True,type=Path)
args,remaining=p.parse_known_args();DRIVER=args.driver.resolve();OBSERVER=args.observer.resolve();OUT=args.out
HERE=Path(__file__).resolve().parent

def encode(rows):return b''.join((json.dumps(row,separators=(',',':'))+'\n').encode() for row in rows)
def capture():
    rows=host.contract.o3.legacy.load((HERE.parent/'o3_integration/fixtures/native.synthetic.jsonl').read_bytes())
    body=[copy.deepcopy(rows[0])];body[0]['samples']=3
    for i in range(3):
        for row in copy.deepcopy(rows[1:-2]):row['sample']=i;row['mono_ms']+=1000*i;body.append(row)
    end=copy.deepcopy(rows[-2]);end.update(sample=2,mono_ms=end['mono_ms']+2000);body.append(end)
    for i,row in enumerate(body):row['seq']=i
    body[-1]['records']=len(body)
    result=encode(body+[rows[-1]]);assert host.contract.analyze_o3(result)['telemetry']=='READABLE'
    return result

def reference_wire(files):
    # A second encoder, stdlib/hashlib only: not the production C serializer.
    nonce=b'0102030405060708090a0b0c0d0e0f10'
    digest=lambda b:hashlib.sha256(b).hexdigest().encode()
    manifest=b'M15E1 '+nonce+b' '+digest(files[3])+b' 6\n'
    manifest+=b''.join(b'I %d %d '%(i,len(raw))+digest(raw)+b'\n' for i,raw in enumerate(files))+b'END\n'
    wire=manifest;seq=0
    for i,raw in enumerate(files):
        for offset in range(0,len(raw),1024):
            data=raw[offset:offset+1024];wire+=b'D %d %d %d %d\n'%(seq,i,offset,len(data))+data;seq+=1
    suffix=b'M15E1 FINAL\nframes=%d bytes=%d manifest='%(seq,len(wire))+digest(manifest)+b'\n'
    return wire+b'F %d %d '%(seq,len(wire))+digest(manifest)+b' '+digest(wire+suffix)+b'\n'

META={'schema':'M15-native-phase1-metadata-v1','synthetic_only':True,'launcher':'offline-subreaper',
      'evidence_path':'ram-escrow-deferred-export','observation_schema':'M15O3','power_supply_contract':'usb-or-usb-pd-v1',
      'freshness':'UNKNOWN','negotiated_contract':'UNKNOWN','protection_active':'UNKNOWN',
      'sealed_baseline':False,'control_permitted':False}

class NativePhase1(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.raw=capture();self.rawfile=self.root/'raw';self.rawfile.write_bytes(self.raw)
        self.meta=self.root/'metadata';self.meta.write_bytes((json.dumps(META,sort_keys=True)+'\n').encode())
        self.counter=0;self.fixture=self.root/'fixture'
        for row in host.contract.o3.legacy.load(self.raw):
            if row.get('kind')=='read_end' and row['rc']==0:
                path=self.fixture/'class'/row['group']/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(row['value']+'\n')
    def driver(self,mode='happy',ack=None):
        self.counter+=1;base=self.root/str(self.counter)
        wire=base.with_suffix('.wire');report=base.with_suffix('.json');ackfile=self.root/'ack'
        if ack is not None:ackfile.write_bytes(ack)
        cmd=[str(DRIVER),mode,str(self.rawfile),str(self.meta),str(wire),str(ackfile) if ack is not None else '-',str(report)]
        if mode in ('process','closed-stdio','worker-crash','getter-block','orphan-process','orphan-fast'):cmd.extend([str(OBSERVER),str(self.fixture)])
        result=subprocess.run(cmd,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        self.assertEqual(result.stderr,b'')
        r=json.loads(report.read_bytes());self.assertFalse(r['control_permitted']);self.assertFalse(r['sealed_baseline'])
        self.assertEqual(r['device_safety'],'UNKNOWN');self.assertTrue(r['ownership_clear'])
        raw=report.with_suffix('.json.raw').read_bytes()
        return (wire.read_bytes() if wire.exists() else b''),r,raw
    def happy(self):
        wire,r,raw=self.driver();self.assertEqual(r['state'],6);self.assertEqual(raw,self.raw)
        data,report,ack=host.decode(wire)
        self.assertEqual(data['capture.raw'],self.raw);self.assertFalse(report['sealed_baseline'])
        return wire,r,report,ack
    def reject(self,raw):
        with self.assertRaises((ValueError,KeyError,TypeError)):host.decode(raw)
    def test_actual_c_sender_independent_host_and_ack(self):
        wire,_,report,ack=self.happy();again,state,raw=self.driver(ack=ack)
        self.assertEqual(wire,again);self.assertEqual(state['state'],7);self.assertEqual(raw,self.raw)
        self.assertEqual(report['files']['capture.raw']['sha256'],hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(report['files']['capture.raw']['bytes'],len(self.raw))
    def test_deterministic_frozen_manifest_wire_across_runs(self):
        wire,_,report,_=self.happy();other,_,_=self.driver()
        self.assertEqual(wire,other);OUT.mkdir(parents=True,exist_ok=True)
        (OUT/'native1-synthetic.wire').write_bytes(wire)
        (OUT/'native1-synthetic-host.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    def test_deferred_export_requires_receipts_and_connector_order(self):
        for mode in ('missing-pc','bad-pc','pc-replay','bad-unbind','pc-present','reconnect-failed','reconnect-timeout'):
            with self.subTest(mode=mode):
                wire,r,_=self.driver(mode);self.assertEqual(r['state'],8);self.assertNotEqual(r['error'],'');self.assertEqual(wire,b'')
    def test_missing_ack_never_becomes_recovered(self):
        _,r,_,_=self.happy();self.assertEqual(r['state'],6)
        _,timeout,_=self.driver('ack-timeout');self.assertEqual(timeout['state'],8)
    def test_wrong_nonce_manifest_digest_partial_ack_rejected(self):
        _,_,_,ack=self.happy()
        for bad in (ack[:-1],ack+b'junk',ack.replace(b'010203',b'ff0203',1),ack[:-2]+b'0\n',b''):
            with self.subTest(bad=bad[:12]):
                _,r,_=self.driver(ack=bad);self.assertEqual(r['state'],8)
    def test_short_writes_eintr_eagain_advance_exact_bytes(self):
        expected,_,_,ack=self.happy()
        for mode in ('short','eintr','eagain'):
            wire,r,_=self.driver(mode,ack=ack);self.assertEqual(wire,expected);self.assertEqual(r['state'],7)
    def test_disconnect_zero_write_short_failure_and_stall_fail_closed(self):
        for mode in ('disconnect','short-fail','zero-write','overreported-write','stall','null-sink'):
            wire,r,raw=self.driver(mode);self.assertEqual(r['state'],8);self.assertEqual(raw,self.raw);self.reject(wire)
    def test_ram_exhaustion_preserves_original_prefix(self):
        wire,r,raw=self.driver('ram-exhausted');self.assertEqual(r['state'],8);self.assertEqual(raw,self.raw[:512]);self.assertEqual(wire,b'')
    def test_kernel_and_journal_exhaustion_never_seal(self):
        for mode in ('kernel-overflow','tiny-journal'):
            wire,r,_=self.driver(mode);self.assertEqual(r['state'],8);self.assertEqual(wire,b'')
    def test_owner_orphan_block_and_reap_errors_fail_closed(self):
        for mode in ('orphan-owner','blocked-owner','double-reap','nonterminal-wait','exit-error','stderr'):
            wire,r,_=self.driver(mode);self.assertEqual(r['state'],8);self.assertEqual(wire,b'')
    def test_frozen_raw_cannot_be_appended(self):
        expected,_,_,_=self.happy();wire,r,raw=self.driver('frozen-append')
        self.assertEqual(raw,self.raw);self.assertEqual(wire,expected);self.assertEqual(r['state'],6)
    def test_missing_collector_receipt_blocks_core_freeze(self):
        self.rawfile.write_bytes(self.raw.rsplit(b'\n',2)[0]+b'\n')
        wire,r,_=self.driver();self.assertEqual(r['state'],8);self.assertEqual(r['error'],'incomplete-supervisor-receipt');self.assertEqual(wire,b'')
    def test_tail_check_is_not_full_o3_validation_host_rejects(self):
        altered=self.raw.replace(b'"seq":1,',b'"seq":0,',1);self.assertNotEqual(self.raw,altered)
        self.rawfile.write_bytes(altered);wire,r,_=self.driver();self.assertEqual(r['state'],6);self.reject(wire)
    def test_real_process_collector_reaped_before_freeze(self):
        wire,r,raw=self.driver('process');self.assertEqual(r['state'],6)
        data,report,_=host.decode(wire);self.assertEqual(data['capture.raw'],raw);self.assertEqual(report['telemetry'],'READABLE')
        self.assertIn(b'tracked=1\nreaped=1\ncensus_closed=1\n',data['status.txt'])
        self.assertEqual(host.contract.o3.legacy.load(raw)[0]['samples'],3)
    def test_closed_inherited_stdio_does_not_close_pipe_duplicates(self):
        wire,r,_=self.driver('closed-stdio');self.assertEqual(r['state'],6)
        self.assertEqual(host.decode(wire)[1]['telemetry'],'READABLE')
    def test_ambient_child_scope_rejected_without_spawning_collector(self):
        wire,r,raw=self.driver('ambient-child');self.assertEqual(r['state'],8)
        self.assertEqual(r['error'],'nonexclusive-process-scope');self.assertEqual(raw,b'');self.assertEqual(wire,b'')
    def test_actual_orphan_setsid_worker_crash_and_blocked_worker(self):
        for mode in ('orphan-process','orphan-fast','worker-crash','getter-block'):
            wire,r,_=self.driver(mode);self.assertEqual(r['state'],8);self.assertEqual(wire,b'')
    def test_delete_1536_arbitrary_bytes_never_resynchronizes(self):
        wire,_,_,_=self.happy()
        for n in (1,17,512,1536,2000):self.reject(wire[:512]+wire[512+n:])
    def test_duplicate_skip_frame_and_wrong_offset(self):
        wire,_,_,_=self.happy();at=wire.index(b'END\n')+4;end=wire.index(b'\n',at)+1
        header=wire[at:end];payload=int(header.split()[-1]);frame=wire[at:end+payload]
        self.reject(wire[:at]+frame+wire[at:]);self.reject(wire[:at]+wire[end+payload:])
        self.reject(wire.replace(b'D 0 0 0 ',b'D 0 0 1 ',1))
    def test_arbitrary_read_chunk_boundaries_leave_original_bytes(self):
        wire,_,_,_=self.happy()
        for n in (1,3,511,512,513,1536,4096):
            rebuilt=b''.join(wire[i:i+n] for i in range(0,len(wire),n));self.assertEqual(host.decode(rebuilt)[1],host.decode(wire)[1])
    def test_truncated_final_digest_header_and_trailing_data(self):
        wire,_,_,_=self.happy()
        for bad in (wire[:-1],wire[:-100],wire+b'junk',wire.replace(b'M15E1',b'M15E2',1),wire[:-2]+b'0\n'):
            self.reject(bad)
    def test_hash_mismatch_and_raw_bit_corruption(self):
        wire,_,_,_=self.happy();at=wire.index(b'END\n')+50
        self.reject(wire[:at]+bytes([wire[at]^1])+wire[at+1:])
    def test_frozen_memory_corruption_poisoned_by_sender_and_host(self):
        wire,r,_=self.driver('frozen-corrupt');self.assertEqual(r['state'],8)
        self.assertEqual(r['error'],'accepted-bytes-mismatch');self.reject(wire)
    def test_final_counts_and_manifest_are_digest_bound(self):
        wire,_,_,_=self.happy();last=wire.rfind(b'\nF ')+1;self.assertGreater(last,0)
        footer=wire[last:].split();footer[1]=str(int(footer[1])+1).encode()
        self.reject(wire[:last]+b' '.join(footer)+b'\n')
    def test_honest_metadata_not_android_instrumentation(self):
        wire,_,report,_=self.happy();data,_,_=host.decode(wire)
        meta=json.loads(data['metadata.json']);self.assertEqual(meta['launcher'],'offline-subreaper')
        self.assertTrue(meta['synthetic_only']);self.assertEqual(report['device_safety'],'UNKNOWN')
        meta['launcher']='android-termux';self.meta.write_text(json.dumps(meta)+'\n')
        wire,r,_=self.driver();self.assertEqual(r['state'],6);self.reject(wire)
    def test_metadata_safety_or_observer_schema_not_promoted(self):
        for key,value in [('control_permitted',True),('sealed_baseline',True),('synthetic_only',False),('observation_schema','M15O4')]:
            meta=META.copy();meta[key]=value;self.meta.write_text(json.dumps(meta)+'\n');wire,_,_=self.driver();self.reject(wire)
    def test_core_telemetry_error_still_qualifies_only_evidence(self):
        self.rawfile.write_bytes(self.raw.replace(b'"value":"368"',b'"value":"oops"',1))
        wire,_,_=self.driver();_,report,ack=host.decode(wire)
        self.assertEqual(report['telemetry'],'BLOCKED');self.assertTrue(ack.startswith(b'M15ACK1 '))
        self.assertFalse(report['control_permitted']);self.assertFalse(report['sealed_baseline'])
    def test_privacy_safe_cli_and_no_ack_on_malformed_stream(self):
        bad=self.root/'bad';bad.write_bytes(b'PRIVATE-FIXTURE-DO-NOT-ECHO');ack=self.root/'ack-output'
        result=subprocess.run([sys.executable,str(HERE/'host.py'),str(bad),'--ack',str(ack)],capture_output=True)
        self.assertEqual(result.returncode,1);self.assertFalse(ack.exists())
        self.assertNotIn(b'PRIVATE-FIXTURE-DO-NOT-ECHO',result.stdout+result.stderr)
    def test_independent_reference_encoder_exact_wire_vector(self):
        journal=b'0 PC_WAIT 0 0\n1 PC_ACK 0 0\n2 ISOLATED 0 0\n3 COLLECT 0 0\n4 OWN 1001 0\n5 REAP 1001 0\n6 FREEZE 0 0\n'
        status=b'wait_status=0\ntracked=1\nreaped=1\ncensus_closed=1\n'
        expected=reference_wire([self.raw,b'',journal,self.meta.read_bytes(),status,b''])
        wire,_,_,ack=self.happy();self.assertEqual(expected,wire)
        self.assertEqual(host.decode(expected)[2],ack)
    def test_rehashed_but_false_lifecycle_census_and_native_metadata_rejected(self):
        wire,_,_,_=self.happy();files=host.decode(wire)[0]
        original=[files[name] for name in host.NAMES]
        for slot,bad in [(2,original[2].replace(b'5 REAP 1001 0\n',b'')),
                         (4,b'wait_status=0\ntracked=1\nreaped=0\ncensus_closed=1\n'),
                         (2,original[2]+b'7 OWN 1002 0\n'),
                         (3,json.dumps({**META,'launcher':'android-termux'}).encode())]:
            altered=original.copy();altered[slot]=bad;self.reject(reference_wire(altered))

if __name__=='__main__':unittest.main(argv=[sys.argv[0],*remaining])
