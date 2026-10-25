#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline-only C/O2 replay/comparison tests. All paths and identities synthetic."""
import argparse
import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
import replay
import compare

ap=argparse.ArgumentParser();ap.add_argument('binary',type=Path);ap.add_argument('fault',type=Path)
args,extra=ap.parse_known_args();BINARY=args.binary.resolve();FAULT=args.fault.resolve()
VALUES={'battery/type':'Battery','battery/present':'1','battery/status':'Charging','battery/health':'Good',
        'battery/capacity':'50','battery/voltage_now':'4000000','battery/current_now':'-300000',
        'battery/temp':'300','battery/charge_control_limit':'0','battery/charge_control_limit_max':'10',
        'usb/type':'USB','usb/online':'1','usb/usb_type':'Unknown SDP [PD_PPS]','usb/voltage_now':'5000000',
        'usb/current_now':'300000','usb/voltage_max':'9000000','usb/current_max':'2000000',
        'usb/input_current_limit':'500000','usb/temp':'310'}
def encode(rows):return b''.join((json.dumps(r)+'\n').encode() for r in rows)
def renumber(rows):
    for i,r in enumerate(rows[:-1]):r['seq']=i
    rows[-2]['records']=len(rows)-1
    return rows

class PhaseB(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        for path,value in VALUES.items():self.put('power_supply/'+path,value)
        for path,value in {'typec/port7/power_role':'[sink] source','typec/port7/data_role':'[device] host',
                           'typec/port7/power_operation_mode':'usb_power_delivery',
                           'typec/port7-partner/supports_usb_power_delivery':'yes',
                           'typec/port7-partner/usb_power_delivery_revision':'3.0',
                           'qcom-battery/pdo2':'00019032','qcom-battery/apdo_max':'33',
                           'qcom-battery/power_max':'33'}.items():self.put(path,value)
    def put(self,path,value):
        p=self.root/'class'/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value+'\n');return p
    def run_tool(self,fault=None,extra=()):
        env=os.environ.copy()
        if fault:env['M15_TEST_FAULT']=fault
        return subprocess.run([str(FAULT if fault else BINARY),'--fixture-root',str(self.root),
                               '--samples','2','--interval-ms','1',*extra],capture_output=True,timeout=5,env=env)
    def raw(self):
        p=self.run_tool();self.assertEqual(p.returncode,0,p.stderr);return p.stdout
    def reject(self,rows):
        with self.assertRaises(ValueError):replay.analyze(encode(rows))
    def context(self,raw,environment):
        return {'schema':'M15-context-v1','environment':environment,'capture_sha256':hashlib.sha256(raw).hexdigest(),
                'topology':{'schema':'M15-topology-v1','charger_inventory_sha256':'1'*64,
                            'cable_inventory_sha256':'2'*64,'instrumentation_inventory_sha256':'3'*64,
                            'power_source':'pc-usb','evidence_path':'direct-usb'}}
    def check_unknown(self,r):
        for k in ('freshness','negotiated_contract','protection_active'):self.assertEqual(r[k],'UNKNOWN')
        self.assertFalse(r['control_permitted']);self.assertFalse(r['charging_hardware_pass'])
    def test_original_o1_fixture_exact_replay(self):
        here=Path(__file__).parent/'fixtures';raw=(here/'m15o1-synthetic.jsonl').read_bytes()
        expected=json.loads((here/'m15o1-expected.json').read_text())
        self.assertEqual(replay.o1.analyze(raw),expected);self.assertEqual(replay.analyze(raw),expected)
        for mutate in (lambda r:r.pop(4),lambda r:r[-1].update(reaped=False),lambda r:r[2].update(errno=5)):
            rows=replay.load(raw);mutate(rows)
            with self.assertRaises(ValueError):replay.analyze(encode(rows))
    def test_o1_cannot_accept_o2_extension(self):
        raw=self.raw()
        with self.assertRaises(ValueError):replay.o1.analyze(raw)
        rows=replay.load(raw)
        for row in rows:row['schema']=row['schema'].replace('M15O2','M15O1')
        with self.assertRaises(ValueError):replay.analyze(encode(rows))
    def test_o2_complete_and_exact_optional_pairs(self):
        raw=self.raw();rows=replay.load(raw);r=replay.analyze(raw)
        self.assertEqual(r['telemetry'],'READABLE');self.check_unknown(r)
        self.assertEqual(r['android_observer_compatibility'],'UNKNOWN')
        for s in range(2):
            optional=[x for x in rows if x.get('sample')==s and replay.optional_field(x)]
            self.assertEqual(len(optional),10)
            self.assertEqual(sum(x['kind']=='read_begin' for x in optional),5)
            self.assertEqual(sum(x['kind']=='read_end' for x in optional),5)
            self.assertEqual(r['samples'][s]['optional']['qcom-battery/pdo2']['value'],0x19032)
    def test_all_optional_missing_is_not_required_failure_or_zero(self):
        import shutil
        shutil.rmtree(self.root/'class/qcom-battery');shutil.rmtree(self.root/'class/typec/port7-partner')
        r=replay.analyze(self.raw());self.assertEqual(r['telemetry'],'READABLE')
        for snapshot in r['samples']:
            self.assertEqual(len(snapshot['optional']),5)
            for v in snapshot['optional'].values():
                self.assertEqual(v['errno'],2);self.assertEqual(v['rc'],-1);self.assertIsNone(v['value'])
        self.check_unknown(r)
    def test_partner_disappears_after_census_real_enoent(self):
        p=self.run_tool('partner-disappear');self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn(b'partner-disappear injected',p.stderr);r=replay.analyze(p.stdout)
        for sample in r['samples']:
            v=sample['optional']['typec/port7-partner/supports_usb_power_delivery']
            self.assertEqual(v['errno'],2);self.assertIsNone(v['value'])
        self.assertEqual(r['telemetry'],'READABLE')
    def test_optional_real_getter_errors(self):
        for mode,field,errno in [('vendor-open-error','qcom-battery/apdo_max',13),
                                  ('vendor-read-error','qcom-battery/pdo2',5),
                                  ('partner-read-error','typec/port7-partner/usb_power_delivery_revision',5)]:
            p=self.run_tool(mode);self.assertEqual(p.returncode,0,p.stderr);self.assertIn((mode+' injected').encode(),p.stderr)
            r=replay.analyze(p.stdout);self.assertEqual(r['telemetry'],'READABLE')
            for sample in r['samples']:
                self.assertEqual(sample['optional'][field]['errno'],errno);self.assertIsNone(sample['optional'][field]['value'])
    def test_malformed_vendor_values_are_not_echoed_or_numeric_zero(self):
        for name,bad in [('pdo2','secret-fixture-do-not-echo'),('pdo2','xyz'),('pdo2','123456789'),
                         ('apdo_max','-1'),('apdo_max','4294967296'),('apdo_max','01'),
                         ('power_max','NaN'),('power_max','0.0')]:
            self.put('qcom-battery/'+name,bad);raw=self.raw();r=replay.analyze(raw)
            self.assertEqual(r['telemetry'],'READABLE')
            for sample in r['samples']:
                v=sample['optional']['qcom-battery/'+name];self.assertEqual(v['problem'],'invalid_format')
                self.assertIsNone(v['value']);self.assertEqual(v['errno'],0);self.assertEqual(v['rc'],0)
            if bad.startswith('secret'):self.assertNotIn(bad.encode(),raw)
            self.put('qcom-battery/'+name,'00019032' if name=='pdo2' else '33')
    def test_malformed_partner_values(self):
        for name,value in [('supports_usb_power_delivery','true'),('supports_usb_power_delivery','secret-fixture'),
                           ('usb_power_delivery_revision','99999999999999999.0'),('usb_power_delivery_revision','3.99'),
                           ('usb_power_delivery_revision','3.0 extra'),('usb_power_delivery_revision','+3.0')]:
            self.put('typec/port7-partner/'+name,value);r=replay.analyze(self.raw())
            self.assertIsNone(r['samples'][0]['optional']['typec/port7-partner/'+name]['value'])
    def test_optional_zero_is_explicit_success_not_error_default(self):
        self.put('qcom-battery/apdo_max','0');r=replay.analyze(self.raw())
        v=r['samples'][0]['optional']['qcom-battery/apdo_max'];self.assertEqual(v['value'],0)
        self.assertEqual(v['rc'],0);self.assertEqual(v['errno'],0);self.assertIsNone(v['problem'])
    def test_empty_overlong_nul_optional(self):
        p=self.root/'class/qcom-battery/pdo2'
        for data,err in [(b'',61),(b'0'*513,75),(b'01\x002',84)]:
            p.write_bytes(data);r=replay.analyze(self.raw());v=r['samples'][0]['optional']['qcom-battery/pdo2']
            self.assertEqual(v['errno'],err);self.assertIsNone(v['value']);self.assertEqual(r['telemetry'],'READABLE')
    def test_no_partner_directory_and_no_typec_class(self):
        import shutil
        shutil.rmtree(self.root/'class/typec');r=replay.analyze(self.raw())
        self.assertEqual(r['telemetry'],'READABLE');self.assertEqual(r['samples'][0]['typec_census_errno'],2)
        self.assertEqual(len(r['samples'][0]['optional']),3);self.check_unknown(r)
    def test_missing_optional_pair_is_structural_failure(self):
        rows=replay.load(self.raw())
        for predicate in (lambda r:r.get('group')=='qcom-battery' and r.get('path')=='pdo2',
                          lambda r:'-partner/' in r.get('path','')):
            bad=[r for r in rows if not (r.get('sample')==0 and predicate(r))]
            self.reject(renumber(bad))
    def test_duplicate_optional_pair_repaired_counts_rejected(self):
        rows=replay.load(self.raw());i=next(i for i,r in enumerate(rows) if r['kind']=='read_begin' and r.get('path')=='pdo2')
        rows[i:i]=copy.deepcopy(rows[i:i+2]);self.reject(renumber(rows))
    def test_schema_unit_and_contract_drift(self):
        raw=self.raw()
        for mutate in (lambda r:r[0].update(extension='vendor-partner-v2'),lambda r:r[0].update(vendor_fields=4),
                       lambda r:r[0].update(partner_fields_per_port=3),lambda r:r[0].update(schema='M15O3'),
                       lambda r:r[4].update(schema='M15O1'),lambda r:r[4].update(unit='mA'),
                       lambda r:r[-1].update(schema='M15O1-supervisor'),lambda r:r[-1].update(reaped=1),
                       lambda r:r[2].update(arbitrary_new_key='x')):
            rows=replay.load(raw);mutate(rows);self.reject(rows)
    def test_optional_value_valid_and_errno_must_agree(self):
        raw=self.raw()
        for change in ({'value_valid':False},{'value_valid':1},{'errno':5},{'rc':-1},{'value':'bad'},
                       {'value_valid':False,'value':'private-string'},{'value_valid':True,'rc':-1,'errno':5,'value':''}):
            rows=replay.load(raw);row=next(r for r in rows if r.get('path')=='pdo2' and r['kind']=='read_end')
            row.update(change);self.reject(rows)
    def test_privacy_sensitive_fields_never_collected(self):
        secret='secret-synthetic-identity-DO-NOT-CAPTURE'
        for p in ('power_supply/battery/serial_number','qcom-battery/adapter_id','qcom-battery/verify_digest',
                  'typec/port7-partner/identity/id_header','typec/port7-partner/serial_number'):
            self.put(p,secret)
        raw=self.raw();self.assertNotIn(secret.encode(),raw)
        rows=replay.load(raw);i=next(i for i,r in enumerate(rows) if r.get('path')=='pdo2' and r['kind']=='read_begin')
        rows[i]['path']='adapter_id';rows[i+1]['path']='adapter_id';self.reject(rows)
        ctx=self.context(raw,'android');ctx['topology']['serial_number']=secret
        with self.assertRaises(ValueError):compare.topology_digest(ctx,raw,'android')
    def test_timeout_mid_optional_is_not_complete(self):
        p=self.run_tool('optional-read-block',extra=['--deadline-ms','100'])
        self.assertNotEqual(p.returncode,0);self.assertIn(b'optional-read-block injected',p.stderr)
        self.assertIn(b'"reaped":true',p.stderr)
        self.assertIn(b'"path":"pdo2"',p.stdout)
        with self.assertRaises(ValueError):replay.analyze(p.stdout)
    def test_partner_paths_are_dynamic_each_sample(self):
        (self.root/'class/typec/port7').rename(self.root/'class/typec/port12')
        (self.root/'class/typec/port7-partner').rename(self.root/'class/typec/port12-partner')
        r=replay.analyze(self.raw());self.assertIn('typec/port12-partner/supports_usb_power_delivery',r['samples'][0]['optional'])
        self.assertNotIn('typec/port7-partner/supports_usb_power_delivery',r['samples'][0]['optional'])
    def test_arbitrary_chunks_and_deletion(self):
        raw=self.raw()
        for n in (1,511,512,513,1536):self.assertTrue(replay.analyze(b''.join(raw[i:i+n] for i in range(0,len(raw),n)))['transcript_complete'])
        with self.assertRaises(ValueError):replay.analyze(raw[:512]+raw[2048:])
        with self.assertRaises(ValueError):replay.analyze(raw[:-1])
    def test_comparison_equal_topology_never_contract_equivalence(self):
        a=self.raw();n=self.raw();r=compare.compare(a,n,self.context(a,'android'),self.context(n,'native'))
        self.assertEqual(r['comparison_eligibility'],'ELIGIBLE');self.assertTrue(r['topology_equal']);self.check_unknown(r)
        self.assertEqual(r['android_observer_compatibility'],'UNKNOWN')
    def test_comparison_time_origins_are_never_aligned(self):
        a=self.raw();rows=replay.load(a)
        for row in rows[:-1]:row['mono_ms']+=987654321
        n=encode(rows);r=compare.compare(a,n,self.context(a,'android'),self.context(n,'native'))
        self.assertEqual(r['android_relative_timing'],r['native_relative_timing']);self.check_unknown(r)
    def test_mismatched_topology_is_blocked(self):
        raw=self.raw()
        for key,val in [('charger_inventory_sha256','4'*64),('cable_inventory_sha256','5'*64),
                        ('instrumentation_inventory_sha256','6'*64),('power_source','wall-charger'),('evidence_path','ram-offline')]:
            ac=self.context(raw,'android');nc=self.context(raw,'native');nc['topology'][key]=val
            r=compare.compare(raw,raw,ac,nc);self.assertEqual(r['comparison_eligibility'],'BLOCKED');self.check_unknown(r)
    def test_context_missing_drift_binding_and_invalid_hash(self):
        raw=self.raw()
        for mutate in (lambda c:c.pop('capture_sha256'),lambda c:c.update(capture_sha256='0'*64),
                       lambda c:c.update(environment='native'),lambda c:c['topology'].update(schema='M15-topology-v2'),
                       lambda c:c['topology'].update(charger_inventory_sha256='not-a-hash')):
            ac=self.context(raw,'android');mutate(ac)
            with self.assertRaises(ValueError):compare.compare(raw,raw,ac,self.context(raw,'native'))
    def test_cli_rejects_sensitive_input_without_echo(self):
        bad=self.root/'bad.jsonl';bad.write_text('{"schema":"PRIVATE-FIXTURE-SECRET"}\n')
        p=subprocess.run([os.sys.executable,str(Path(replay.__file__)),str(bad)],capture_output=True,timeout=2)
        self.assertNotEqual(p.returncode,0);self.assertNotIn(b'PRIVATE-FIXTURE-SECRET',p.stdout+p.stderr)
        self.check_unknown(json.loads(p.stdout))
    def test_compare_cli_failure_keeps_unknowns_and_no_private_echo(self):
        raw=self.raw();capture=self.root/'capture.jsonl';capture.write_bytes(raw)
        ac=self.context(raw,'android');ac['topology']['serial_number']='PRIVATE-FIXTURE-SECRET'
        ctx=self.root/'context.json';ctx.write_text(json.dumps(ac))
        p=subprocess.run([os.sys.executable,str(Path(compare.__file__)),'--android-capture',str(capture),
                          '--native-capture',str(capture),'--android-context',str(ctx),'--native-context',str(ctx)],
                         capture_output=True,timeout=2)
        self.assertNotEqual(p.returncode,0);self.assertNotIn(b'PRIVATE-FIXTURE-SECRET',p.stdout+p.stderr)
        self.check_unknown(json.loads(p.stdout))

if __name__=='__main__':unittest.main(argv=['test.py',*extra])
