#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Deterministic metadata and comparison CLI regressions; no producer execution."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import topology
import compare
import fixture_bundle
import replay

HERE=Path(__file__).resolve().parent
FIX=HERE/'fixtures'
PHASEB=HERE.parent

def raw(name):return (FIX/name).read_bytes()
def document(name):return json.loads(raw(name))
def encode(rows):return b''.join((json.dumps(r)+'\n').encode() for r in rows)

class TopologyTests(unittest.TestCase):
    def setUp(self):
        self.a=raw('android.synthetic.jsonl');self.n=raw('native.synthetic.jsonl')
        self.ac=document('android.context.synthetic.json');self.nc=document('native.context.synthetic.json')
        self.manifest=document('topology-pc.synthetic.json')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.out=Path(self.tmp.name)
    def run_cli(self,script,*args):
        return subprocess.run([sys.executable,str(PHASEB/script),*map(str,args)],capture_output=True,timeout=5)
    def cli_compare(self,native_context=None):
        return self.run_cli('compare.py','--android-capture',FIX/'android.synthetic.jsonl',
                            '--native-capture',FIX/'native.synthetic.jsonl',
                            '--android-context',FIX/'android.context.synthetic.json',
                            '--native-context',native_context or FIX/'native.context.synthetic.json')
    def result(self):return compare.compare(self.a,self.n,self.ac,self.nc)
    def check_unknown(self,r):
        self.assertFalse(r['control_permitted']);self.assertFalse(r['charging_hardware_pass'])
        for k in ('freshness','negotiated_contract','protection_active','android_observer_compatibility'):
            self.assertEqual(r[k],'UNKNOWN')
    def test_fixture_bundle_reproduces_exactly_with_provenance(self):
        expected=fixture_bundle.bundle();self.assertEqual(set(expected),{p.name for p in FIX.glob('*')})
        for name,value in expected.items():self.assertEqual(raw(name),value,name)
        for name,identity in document('provenance.synthetic.json')['files'].items():
            self.assertEqual(len(raw(name)),identity['bytes']);self.assertEqual(topology.sha256(raw(name)),identity['sha256'])
        self.assertTrue(document('provenance.synthetic.json')['synthetic_only'])
    def test_fixture_generator_cli_never_overwrites(self):
        dest=self.out/'bundle';p=self.run_cli('fixture_bundle.py','--out',dest);self.assertEqual(p.returncode,0,p.stderr)
        for f in dest.iterdir():self.assertEqual(f.read_bytes(),raw(f.name))
        p=self.run_cli('fixture_bundle.py','--out',dest);self.assertNotEqual(p.returncode,0)
    def test_canonical_manifest_hash_golden_and_key_order(self):
        self.assertEqual(topology.digest(self.manifest),'129da2c65b69621d15fafe6819edfa9069cc7c5ab9e1caa80c7ce7c78931675d')
        reverse=dict(reversed(list(self.manifest.items())));self.assertEqual(topology.canonical(reverse),topology.canonical(self.manifest))
        self.assertFalse(topology.canonical(reverse).endswith(b'\n'))
    def test_schema_documents_match_closed_runtime_contract(self):
        for name,keys in [('topology-v1.schema.json',topology.TOPOLOGY_KEYS),('context-v1.schema.json',topology.CONTEXT_KEYS)]:
            schema=json.loads((HERE/'schemas'/name).read_bytes())
            self.assertFalse(schema['additionalProperties']);self.assertEqual(set(schema['required']),keys)
            self.assertEqual(set(schema['properties']),keys)
        s=json.loads((HERE/'schemas/topology-v1.schema.json').read_bytes())
        for key in topology.INVENTORIES:
            self.assertEqual(s['properties'][key],{'type':'string','pattern':'^[0-9a-f]{64}$','minLength':64,'maxLength':64})
        self.assertEqual(s['properties']['power_source']['enum'],list(topology.POWER_SOURCES))
        self.assertEqual(s['properties']['evidence_path']['enum'],list(topology.EVIDENCE_PATHS))
        c=json.loads((HERE/'schemas/context-v1.schema.json').read_bytes())
        self.assertEqual(c['properties']['environment']['enum'],list(topology.ENVIRONMENTS))
        self.assertTrue((HERE/'schemas'/c['properties']['topology']['$ref']).is_file())
    def test_missing_extra_and_schema_drift(self):
        for key in topology.TOPOLOGY_KEYS:
            bad=self.manifest.copy();bad.pop(key)
            with self.assertRaises(ValueError):topology.digest(bad)
        for key,value in [('schema','M15-topology-v2'),('serial_number','PRIVATE-FIXTURE-SECRET'),
                          ('power_source','wall-charger-unknown'),('evidence_path','adb-auto')]:
            bad=self.manifest.copy();bad[key]=value
            with self.assertRaises(ValueError):topology.digest(bad)
    def test_hashes_are_exact_lowercase_and_typed(self):
        for key in topology.INVENTORIES:
            for value in ('A'*64,'0'*63,'0'*65,'0'*64+'\n',False,0,None,[],{'sha256':'0'*64},' unknown '):
                bad=self.manifest.copy();bad[key]=value
                with self.assertRaises(ValueError):topology.digest(bad)
        for value in (None,[],0,True,'M15-topology-v1'):
            with self.assertRaises(ValueError):topology.digest(value)
    def test_no_silent_normalization_of_topology_enums(self):
        for key in ('power_source','evidence_path'):
            for value in (True,0,{},[],None,self.manifest[key].upper(),self.manifest[key]+' '):
                bad=self.manifest.copy();bad[key]=value
                with self.assertRaises((ValueError,TypeError)):topology.digest(bad)
    def test_context_creation_and_cli_roundtrip(self):
        p=self.run_cli('topology.py','context','--manifest',FIX/'topology-pc.synthetic.json',
                       '--capture',FIX/'android.synthetic.jsonl','--environment','android')
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout),self.ac)
        self.assertEqual(topology.make_context(self.manifest,self.n,'native'),self.nc)
        p=self.run_cli('topology.py','validate','--manifest',FIX/'topology-pc.synthetic.json')
        self.assertEqual(p.returncode,0,p.stderr);self.check_unknown(json.loads(p.stdout))
    def test_context_cannot_bind_incomplete_capture(self):
        for incomplete in (b'',self.a[:-1],self.a[:512]+self.a[2048:]):
            with self.assertRaises(ValueError):topology.make_context(self.manifest,incomplete,'android')
    def test_swapped_or_tampered_context_and_capture(self):
        for ac,nc in ((self.nc,self.ac),(self.ac,{**self.nc,'capture_sha256':'0'*64}),
                       ({**self.ac,'environment':'native'},self.nc)):
            with self.assertRaises(ValueError):compare.compare(self.a,self.n,ac,nc)
        with self.assertRaises(ValueError):compare.compare(self.n,self.a,self.ac,self.nc)
    def test_context_metadata_duplicate_nonfinite_oversized_and_privacy(self):
        for data in (b'{"schema":1,"schema":2}',b'{"number":NaN}',b' '*16385,b'null',b'['*1200+b']'*1200,
                     json.dumps({**self.manifest,'serial_number':'PRIVATE-FIXTURE-SECRET'}).encode()):
            path=self.out/'bad.json';path.write_bytes(data)
            p=self.run_cli('topology.py','validate','--manifest',path)
            self.assertNotEqual(p.returncode,0);self.check_unknown(json.loads(p.stdout))
            self.assertNotIn(b'PRIVATE-FIXTURE-SECRET',p.stdout+p.stderr)
    def test_manifest_missing_file_error_is_private_and_fail_closed(self):
        p=self.run_cli('topology.py','validate','--manifest',self.out/'PRIVATE-FIXTURE-SECRET')
        self.assertNotEqual(p.returncode,0);self.assertNotIn(b'PRIVATE-FIXTURE-SECRET',p.stdout+p.stderr)
        self.check_unknown(json.loads(p.stdout))
    def test_full_comparison_cli_expected_observations(self):
        p=self.cli_compare();self.assertEqual(p.returncode,0,p.stderr);r=json.loads(p.stdout)
        expect=document('expected.synthetic.json');self.assertEqual(r['schema'],'M15-comparison-v2')
        self.assertEqual(r['comparison_eligibility'],expect['eligible_result']);self.assertEqual(r['blocked_reasons'],[])
        self.check_unknown(r);self.assertEqual(r['sample_counts'],{'android':1,'native':1})
        fields=r['sample_pairs'][0]['fields'];self.assertEqual(len(fields),expect['field_count'])
        self.assertEqual([x['field'] for x in fields if x['relation']=='VALUE_DIFF'],expect['observed_differences'])
        self.assertEqual([x['field'] for x in fields if x['relation']=='UNAVAILABLE'],expect['unavailable'])
        self.assertEqual(r['android_relative_timing'],r['native_relative_timing'])
        self.assertEqual(r['android_relative_timing']['duration_ms'],expect['duration_ms'])
    def test_optional_errno_is_null_never_a_zero_match(self):
        r=self.result();field=next(x for x in r['sample_pairs'][0]['fields'] if x['field']=='qcom-battery/power_max')
        self.assertIsNone(field['native']['value']);self.assertEqual(field['native']['status'],'IO_ERROR')
        self.assertEqual(field['native']['errno'],5);self.assertEqual(field['relation'],'UNAVAILABLE')
        field=next(x for x in r['sample_pairs'][0]['fields'] if x['field']=='typec/port0-partner/supports_usb_power_delivery')
        self.assertIs(field['native']['value'],True);self.assertEqual(field['relation'],'VALUE_MATCH');self.check_unknown(r)
    def test_topology_mismatch_no_value_comparison_exit_two(self):
        p=self.cli_compare(FIX/'native-mismatch.context.synthetic.json');self.assertEqual(p.returncode,2,p.stderr)
        r=json.loads(p.stdout);self.assertEqual(r['blocked_reasons'],['TOPOLOGY_MISMATCH'])
        self.assertEqual(r['sample_pairs'],[]);self.assertFalse(r['topology_equal']);self.check_unknown(r)
    def test_core_read_failure_blocks_even_equal_topology(self):
        rows=replay.load(self.n)
        row=next(r for r in rows if r.get('path')=='battery/temp' and r['kind']=='read_end')
        row.update(rc=-1,errno=5,value='');raw_n=encode(rows)
        nc=topology.make_context(self.manifest,raw_n,'native');r=compare.compare(self.a,raw_n,self.ac,nc)
        self.assertEqual(r['blocked_reasons'],['NATIVE_CORE_UNREADABLE']);self.assertEqual(r['sample_pairs'],[]);self.check_unknown(r)
        self.assertIn('battery/temp: errno=5',r['core_telemetry']['native']['sample_errors'][0])
    def test_private_optional_role_text_never_echoed(self):
        rows=replay.load(self.n)
        row=next(r for r in rows if r.get('path')=='port0/data_role' and r['kind']=='read_end')
        row['value']='PRIVATE-FIXTURE-SECRET';raw_n=encode(rows)
        r=compare.compare(self.a,raw_n,self.ac,topology.make_context(self.manifest,raw_n,'native'))
        self.assertNotIn('PRIVATE-FIXTURE-SECRET',json.dumps(r))
        field=next(x for x in r['sample_pairs'][0]['fields'] if x['field']=='typec/port0/data_role')
        self.assertEqual(field['native']['status'],'INVALID_FORMAT');self.assertIsNone(field['native']['value'])
    def test_relative_read_timing_not_cross_boot_subtraction(self):
        r=self.result()
        for field in r['sample_pairs'][0]['fields']:
            self.assertEqual(field['android']['relative_begin_ms'],field['native']['relative_begin_ms'])
            self.assertEqual(field['android']['read_duration_ms'],2);self.assertEqual(field['native']['read_duration_ms'],2)
        rows=replay.load(self.n)
        for row in rows[:-1]:row['mono_ms']+=123456789000
        shifted=encode(rows)
        again=compare.compare(self.a,shifted,self.ac,topology.make_context(self.manifest,shifted,'native'))
        self.assertEqual(r['sample_pairs'],again['sample_pairs']);self.assertEqual(r['native_relative_timing'],again['native_relative_timing'])
    def test_port_indices_are_not_mapped_to_physical_equivalence(self):
        rows=replay.load(self.n)
        for row in rows:
            if row.get('group')=='typec':row['path']=row['path'].replace('port0','port12')
        shifted=encode(rows);r=compare.compare(self.a,shifted,self.ac,topology.make_context(self.manifest,shifted,'native'))
        ports=[x for x in r['sample_pairs'][0]['fields'] if x['field'].startswith('typec/')]
        self.assertTrue(ports);self.assertTrue(all(x['relation']=='UNAVAILABLE' for x in ports));self.check_unknown(r)
    def test_mixed_o1_o2_comparison_preserves_o1_replay(self):
        old=(PHASEB/'fixtures/m15o1-synthetic.jsonl').read_bytes()
        before=replay.o1.analyze(old)
        r=compare.compare(old,self.n,topology.make_context(self.manifest,old,'android'),self.nc)
        self.assertEqual(r['comparison_eligibility'],'ELIGIBLE');self.assertEqual(len(r['sample_pairs'][0]['fields']),27)
        self.assertEqual(before,replay.analyze(old));self.check_unknown(r)
    def test_unequal_sample_counts_are_explicit_unpaired_not_synchronized(self):
        rows=replay.load(self.n);body=copy.deepcopy(rows[:-2]);second=copy.deepcopy(rows[1:-2])
        body[0]['samples']=2
        for row in second:row['sample']=1;row['mono_ms']+=200
        body+=second;end=copy.deepcopy(rows[-2]);end['sample']=1;end['mono_ms']+=200;body.append(end)
        for i,row in enumerate(body):row['seq']=i
        body[-1]['records']=len(body);n=encode(body+[rows[-1]])
        r=compare.compare(self.a,n,self.ac,topology.make_context(self.manifest,n,'native'))
        self.assertEqual(r['sample_counts'],{'android':1,'native':2})
        self.assertEqual(r['unpaired_samples'],{'android':0,'native':1})
        self.assertEqual(len(r['sample_pairs']),1);self.check_unknown(r)
    def test_optional_invalid_format_status_is_explicit(self):
        rows=replay.load(self.n)
        row=next(r for r in rows if r.get('path')=='apdo_max' and r['kind']=='read_end')
        row.update(value='',value_valid=False);n=encode(rows)
        r=compare.compare(self.a,n,self.ac,topology.make_context(self.manifest,n,'native'))
        field=next(f for f in r['sample_pairs'][0]['fields'] if f['field']=='qcom-battery/apdo_max')
        self.assertEqual(field['native']['status'],'INVALID_FORMAT');self.assertEqual(field['native']['errno'],0)
        self.assertIsNone(field['native']['value']);self.assertEqual(field['relation'],'UNAVAILABLE');self.check_unknown(r)

if __name__=='__main__':unittest.main()
