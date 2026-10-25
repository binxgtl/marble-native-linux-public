#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real C on synthetic trees; supplied Termux ranges are exploratory, not a baseline."""
import argparse
import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
import replay as o3

p=argparse.ArgumentParser();p.add_argument('binary',type=Path);p.add_argument('fault',type=Path)
args,extra=p.parse_known_args();BINARY=args.binary.resolve();FAULT=args.fault.resolve()
HERE=Path(__file__).resolve().parent;OLD=HERE.parent/'phaseb'
def encode(rows):return b''.join((json.dumps(row)+'\n').encode() for row in rows)

class SupplyContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        raw=(OLD/'topology/fixtures/android.synthetic.jsonl').read_bytes()
        # Unreported values below come only from pre-existing synthetic scaffolding,
        # never from a reconstructed or purported Android baseline.
        for r in o3.legacy.load(raw):
            if r.get('kind')!='read_end':continue
            self.put(r['group']+'/'+r['path'],r['value'])
        for path,value in {'power_supply/battery/status':'Charging','power_supply/battery/capacity':'35',
                           'power_supply/battery/temp':'367','power_supply/usb/type':'USB_PD',
                           'power_supply/usb/usb_type':'Unknown SDP [PD_PPS]',
                           'power_supply/usb/voltage_now':'8432000','power_supply/battery/current_now':'-3668000',
                           'power_supply/usb/current_now':'0','power_supply/usb/current_max':'4500000',
                           'qcom-battery/pdo2':'0002d12c','qcom-battery/apdo_max':'33','qcom-battery/power_max':'33'}.items():
            self.put(path,value)
    def put(self,path,value):
        p=self.root/'class'/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value+'\n');return p
    def run_tool(self,fault=None,extra=()):
        env=os.environ.copy()
        if fault:env['M15_TEST_FAULT']=fault
        return subprocess.run([str(FAULT if fault else BINARY),'--fixture-root',str(self.root),'--samples','1',*extra],
                              env=env,capture_output=True,timeout=5)
    def raw(self):
        r=self.run_tool();self.assertEqual(r.returncode,0,r.stderr);return r.stdout
    def restrict(self,r):
        for key in ('freshness','negotiated_contract','protection_active','android_observer_compatibility'):
            self.assertEqual(r[key],'UNKNOWN')
        self.assertFalse(r['control_permitted']);self.assertFalse(r['charging_hardware_pass']);self.assertFalse(r['sealed_baseline'])
    def reject(self,rows):
        with self.assertRaises(ValueError):o3.analyze(encode(rows))
    def test_existing_o1_replay_exact(self):
        raw=(OLD/'fixtures/m15o1-synthetic.jsonl').read_bytes()
        self.assertEqual(o3.analyze(raw),o3.legacy.analyze(raw))
        self.assertEqual(o3.analyze(raw),json.loads((OLD/'fixtures/m15o1-expected.json').read_bytes()))
    def test_existing_o2_verdict_for_usb_pd_stays_blocked(self):
        rows=o3.legacy.load((OLD/'topology/fixtures/android.synthetic.jsonl').read_bytes())
        for row in rows:
            if row.get('path')=='usb/type' and row.get('kind')=='read_end':row['value']='USB_PD'
        raw=encode(rows);before=o3.legacy.analyze(raw);after=o3.analyze(raw)
        self.assertEqual(before,after);self.assertEqual(after['telemetry'],'BLOCKED')
        self.assertIn('USB supply type unverified',after['samples'][0]['errors'])
    def test_o3_real_c_explicit_usb_pd_contract(self):
        raw=self.raw();r=o3.analyze(raw)
        self.assertEqual(r['observation_schema'],'M15O3');self.assertEqual(r['telemetry'],'READABLE')
        self.assertEqual(r['power_supply_contract'],'usb-or-usb-pd-v1')
        self.assertEqual(r['legacy_o2_telemetry'],'BLOCKED');self.assertEqual(r['samples'][0]['errors'],[])
        self.assertEqual(r['samples'][0]['reported_supply_type'],'USB_PD');self.assertTrue(r['samples'][0]['supply_type_accepted'])
        self.assertEqual(r['raw_sha256'],hashlib.sha256(raw).hexdigest());self.restrict(r)
    def test_no_field_value_is_rewritten_to_usb(self):
        raw=self.raw();before=bytes(raw);r=o3.analyze(raw)
        self.assertEqual(raw,before)
        rows=o3.legacy.load(raw);self.assertEqual(next(row['value'] for row in rows if row.get('path')=='usb/type' and row.get('kind')=='read_end'),'USB_PD')
        self.assertEqual(r['samples'][0]['legacy_o2_errors'],['USB supply type unverified'])
    def test_plain_usb_still_readable_under_o3(self):
        self.put('power_supply/usb/type','USB');r=o3.analyze(self.raw())
        self.assertEqual(r['telemetry'],'READABLE');self.assertEqual(r['legacy_o2_telemetry'],'READABLE');self.restrict(r)
    def test_other_supply_types_are_not_silently_admitted(self):
        for value in ('USB_PD_PPS','USB_PD_DRP','USB_DCP','usb_pd','USB_PD ','Battery','Unknown'):
            self.put('power_supply/usb/type',value);r=o3.analyze(self.raw())
            self.assertEqual(r['telemetry'],'BLOCKED');self.assertFalse(r['samples'][0]['supply_type_accepted']);self.restrict(r)
    def test_non_type_core_failures_remain_blocking(self):
        for path,value in [('battery/health','Overheat'),('battery/capacity','101'),('battery/present','0'),('usb/online','0'),('usb/usb_type','PD_PPS')]:
            target=self.root/'class/power_supply'/path;old=target.read_bytes();target.write_text(value+'\n')
            r=o3.analyze(self.raw());self.assertEqual(r['telemetry'],'BLOCKED');self.assertTrue(r['samples'][0]['supply_type_accepted'])
            self.assertTrue(r['samples'][0]['errors']);self.assertNotIn('USB supply type unverified',r['samples'][0]['errors']);target.write_bytes(old)
    def test_missing_supply_class_keeps_real_errno(self):
        (self.root/'class/power_supply/usb/type').unlink();raw=self.raw();r=o3.analyze(raw)
        self.assertEqual(r['telemetry'],'BLOCKED');self.assertIsNone(r['samples'][0]['reported_supply_type'])
        row=next(x for x in o3.legacy.load(raw) if x.get('path')=='usb/type' and x.get('kind')=='read_end')
        self.assertEqual(row['rc'],-1);self.assertEqual(row['errno'],2);self.assertEqual(row['value'],'')
    def test_reported_ranges_signed_current_and_zero_are_preserved(self):
        for temp,voltage,current in [('367','8432000','-3668000'),('368','8477000','-4127000')]:
            self.put('power_supply/battery/temp',temp);self.put('power_supply/usb/voltage_now',voltage);self.put('power_supply/battery/current_now',current)
            raw=self.raw();r=o3.analyze(raw);self.assertEqual(r['telemetry'],'READABLE')
            values={row['path']:row for row in o3.legacy.load(raw) if row.get('kind')=='read_end'}
            for path,value in [('battery/temp',temp),('usb/voltage_now',voltage),('battery/current_now',current),('usb/current_now','0'),('usb/current_max','4500000')]:
                self.assertEqual(values[path]['value'],value);self.assertEqual(values[path]['rc'],0);self.assertEqual(values[path]['errno'],0)
            self.assertEqual(r['samples'][0]['optional']['qcom-battery/pdo2']['value'],int('0002d12c',16));self.restrict(r)
    def test_optional_failure_keeps_null_and_does_not_change_core(self):
        p=self.run_tool('vendor-read-error');self.assertEqual(p.returncode,0,p.stderr)
        r=o3.analyze(p.stdout);self.assertEqual(r['telemetry'],'READABLE')
        value=r['samples'][0]['optional']['qcom-battery/pdo2'];self.assertEqual(value['errno'],5);self.assertIsNone(value['value']);self.restrict(r)
    def test_contract_schema_or_receipt_drift_rejected(self):
        raw=self.raw()
        for mutate in (lambda r:r[0].pop('power_supply_contract'),lambda r:r[0].update(power_supply_contract='anything'),
                       lambda r:r[0].update(power_supply_contract=True),lambda r:r[3].update(schema='M15O2'),
                       lambda r:r[-1].update(schema='M15O2-supervisor'),lambda r:r[0].update(extra_key=1),
                       lambda r:r[-2].update(records=0),lambda r:r[-1].update(reaped=1)):
            rows=o3.legacy.load(raw);mutate(rows);self.reject(rows)
    def test_old_decoder_rejects_o3_and_no_implicit_upgrade(self):
        raw=self.raw()
        with self.assertRaises(ValueError):o3.legacy.analyze(raw)
        rows=o3.legacy.load((OLD/'topology/fixtures/android.synthetic.jsonl').read_bytes())
        for row in rows:row['schema']=row['schema'].replace('M15O2','M15O3')
        self.reject(rows)
    def test_exploratory_summary_is_not_a_replayable_or_sealed_trace(self):
        summary=(HERE/'fixtures/termux-exploratory-summary.json').read_bytes();j=json.loads(summary)
        self.assertEqual(j['reported_sample_count'],3);self.assertFalse(j['sealed_m15o2_baseline'])
        self.assertFalse(j['raw_capture_available']);self.assertEqual(j['individual_sample_pairing'],'UNKNOWN')
        with self.assertRaises(ValueError):o3.analyze(summary)
        with self.assertRaises(ValueError):o3.legacy.analyze(summary)
    def test_endpoint_fixtures_do_not_fabricate_unreported_measurements(self):
        for name in ('range-endpoint-a.synthetic.jsonl','range-endpoint-b.synthetic.jsonl'):
            raw=(HERE/'fixtures'/name).read_bytes();r=o3.analyze(raw)
            self.assertTrue(r['samples'][0]['supply_type_accepted']);self.assertEqual(r['telemetry'],'BLOCKED')
            self.assertTrue(r['samples'][0]['errors']);self.restrict(r)
        prov=json.loads((HERE/'fixtures/provenance.json').read_bytes());self.assertTrue(prov['synthetic_only'])
        for name,meta in prov['files'].items():
            raw=(HERE/'fixtures'/name).read_bytes();self.assertEqual(len(raw),meta['bytes']);self.assertEqual(hashlib.sha256(raw).hexdigest(),meta['sha256'])
    def test_missing_final_corruption_and_host_chunks(self):
        raw=self.raw()
        for n in (1,511,512,1536):self.assertEqual(o3.analyze(b''.join(raw[i:i+n] for i in range(0,len(raw),n)))['telemetry'],'READABLE')
        for truncated in (raw[:-1],raw[:512]+raw[2048:],raw.splitlines(keepends=True)[0]):
            with self.assertRaises(ValueError):o3.analyze(truncated)
    def test_optional_timeout_cannot_be_qualified(self):
        p=self.run_tool('optional-read-block',extra=['--deadline-ms','100'])
        self.assertNotEqual(p.returncode,0);self.assertIn(b'optional-read-block injected',p.stderr);self.assertIn(b'"reaped":true',p.stderr)
        with self.assertRaises(ValueError):o3.analyze(p.stdout)
    def test_cli_reports_explicit_version_and_rejects_exploratory_text(self):
        raw=self.raw();capture=self.root/'trace.jsonl';capture.write_bytes(raw)
        p=subprocess.run([os.sys.executable,str(HERE/'replay.py'),str(capture)],capture_output=True,timeout=3)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['observation_schema'],'M15O3')
        p=subprocess.run([os.sys.executable,str(HERE/'replay.py'),str(HERE/'fixtures/termux-exploratory-summary.json')],capture_output=True,timeout=3)
        self.assertNotEqual(p.returncode,0);self.restrict(json.loads(p.stdout))
    def test_no_implicit_live_collection(self):
        p=subprocess.run([str(BINARY)],capture_output=True,timeout=2)
        self.assertEqual(p.returncode,64);self.assertEqual(p.stdout,b'')
    def test_legacy_context_tool_cannot_mislabel_o3_as_o2_baseline(self):
        capture=self.root/'o3.jsonl';capture.write_bytes(self.raw())
        p=subprocess.run([os.sys.executable,str(OLD/'topology.py'),'context','--manifest',
                          str(OLD/'topology/fixtures/topology-pc.synthetic.json'),'--capture',str(capture),
                          '--environment','android'],capture_output=True,timeout=3)
        self.assertNotEqual(p.returncode,0);self.assertFalse(json.loads(p.stdout)['control_permitted'])

if __name__=='__main__':unittest.main(argv=['test.py',*extra])
