#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""O3 integration using local synthetic byte fixtures; never runs a producer."""
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import contract
import compare_v3
import fixture_bundle_v3 as fixture_bundle
from compat import M15,o3,legacy_topology,legacy_compare

HERE=Path(__file__).resolve().parent;FIX=HERE/'fixtures'
def raw(name):return (FIX/name).read_bytes()
def document(name):return json.loads(raw(name))
def encode(rows):return b''.join((json.dumps(row,sort_keys=True)+'\n').encode() for row in rows)

class O3Integration(unittest.TestCase):
    def setUp(self):
        self.a=raw('android.synthetic.jsonl');self.n=raw('native.synthetic.jsonl')
        self.ac=document('android.context.synthetic.json');self.nc=document('native.context.synthetic.json')
        self.manifest=document('topology.synthetic.json')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.out=Path(self.tmp.name)
    def run_cli(self,name,*args):
        return subprocess.run([sys.executable,str(HERE/name),*map(str,args)],capture_output=True,timeout=5)
    def run_compare(self,nc=None):
        return self.run_cli('compare_v3.py','--android-capture',FIX/'android.synthetic.jsonl',
                            '--native-capture',FIX/'native.synthetic.jsonl',
                            '--android-context',FIX/'android.context.synthetic.json',
                            '--native-context',nc or FIX/'native.context.synthetic.json')
    def result(self):return compare_v3.compare(self.a,self.n,self.ac,self.nc)
    def restrict(self,r):
        self.assertIs(r['control_permitted'],False);self.assertIs(r['sealed_baseline'],False)
        self.assertIs(r['charging_hardware_pass'],False)
        for k in ('freshness','negotiated_contract','protection_active','android_observer_compatibility'):
            self.assertEqual(r[k],'UNKNOWN')
    def context(self,n):return contract.make_context(self.manifest,n,'native')
    def test_fixture_bundle_exact_and_provenance(self):
        expected=fixture_bundle.bundle();self.assertEqual(set(expected),{p.name for p in FIX.iterdir()})
        for name,b in expected.items():self.assertEqual(raw(name),b,name)
        provenance=document('provenance.synthetic.json');self.assertTrue(provenance['synthetic_only'])
        self.assertFalse(provenance['sealed_baseline'])
        for name,meta in provenance['files'].items():
            self.assertEqual(len(raw(name)),meta['bytes']);self.assertEqual(hashlib.sha256(raw(name)).hexdigest(),meta['sha256'])
    def test_valid_o3_context_and_comparison_cli(self):
        p=self.run_compare();self.assertEqual(p.returncode,0,p.stderr);r=json.loads(p.stdout)
        self.assertEqual(r['schema'],'M15-comparison-v3');self.assertEqual(r['observation_schema'],'M15O3')
        self.assertEqual(r['power_supply_contract'],'usb-or-usb-pd-v1');self.assertEqual(r['comparison_eligibility'],'ELIGIBLE')
        self.assertEqual(r['core_telemetry']['android']['reported_supply_types'],['USB_PD'])
        self.assertEqual(r['core_telemetry']['native']['reported_supply_types'],['USB_PD']);self.restrict(r)
        field=next(f for f in r['sample_pairs'][0]['fields'] if f['field']=='power_supply/usb/type')
        self.assertEqual(field['android']['value'],'USB_PD');self.assertEqual(field['native']['value'],'USB_PD')
        self.assertEqual(field['relation'],'VALUE_MATCH')
    def test_context_cli_round_trip_and_manifest_version(self):
        p=self.run_cli('contract.py','context','--manifest',FIX/'topology.synthetic.json',
                       '--capture',FIX/'android.synthetic.jsonl','--environment','android')
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout),self.ac)
        p=self.run_cli('contract.py','validate','--manifest',FIX/'topology.synthetic.json')
        self.assertEqual(p.returncode,0,p.stderr);self.restrict(json.loads(p.stdout))
        self.assertEqual(contract.digest(dict(reversed(list(self.manifest.items())))),self.ac['topology_sha256'])
    def test_original_raw_sha_and_size_verified(self):
        r=self.result()
        for name,b in (('android',self.a),('native',self.n)):
            binding=r['capture_bindings'][name];self.assertEqual(binding['sha256'],hashlib.sha256(b).hexdigest())
            self.assertEqual(binding['bytes'],len(b));self.assertTrue(binding['original_raw_binding_verified'])
            self.assertFalse(binding['sender_seal_verified']);self.assertEqual(binding['environment_authenticity'],'UNKNOWN')
    def test_json_reserialization_cannot_match_original_context(self):
        normalized=encode(o3.legacy.load(self.n));self.assertNotEqual(normalized,self.n)
        self.assertEqual(contract.analyze_o3(normalized)['telemetry'],'READABLE')
        with self.assertRaises(ValueError):contract.verify_context(self.nc,normalized,'native')
        rebind=self.context(normalized);self.assertEqual(rebind['capture_sha256'],hashlib.sha256(normalized).hexdigest())
        self.assertNotEqual(rebind['capture_sha256'],self.nc['capture_sha256'])
    def test_o2_projected_hash_cannot_substitute_for_raw_o3_hash(self):
        rows=o3.legacy.load(self.n)
        for r in rows:r['schema']=r['schema'].replace('M15O3','M15O2')
        rows[0].pop('power_supply_contract');projected=encode(rows)
        ctx=copy.deepcopy(self.nc);ctx['capture_sha256']=hashlib.sha256(projected).hexdigest()
        with self.assertRaises(ValueError):contract.verify_context(ctx,self.n,'native')
    def test_tampered_digest_size_and_topology_binding(self):
        for changes in ({'capture_sha256':'0'*64},{'capture_bytes':True},{'capture_bytes':0},
                        {'capture_bytes':self.nc['capture_bytes']+1},{'topology_sha256':'0'*64},
                        {'capture_sha256':'A'*64},{'capture_bytes':str(len(self.n))}):
            ctx=copy.deepcopy(self.nc);ctx.update(changes)
            with self.assertRaises(ValueError):contract.verify_context(ctx,self.n,'native')
        ctx=copy.deepcopy(self.nc);ctx['topology']['power_source']='wall-charger'
        with self.assertRaises(ValueError):contract.verify_context(ctx,self.n,'native')
    def test_valid_byte_tampering_still_breaks_original_binding(self):
        changed=self.n.replace(b'4500000',b'4500001',1);self.assertEqual(len(changed),len(self.n))
        self.assertEqual(contract.analyze_o3(changed)['telemetry'],'READABLE')
        with self.assertRaises(ValueError):compare_v3.compare(self.a,changed,self.ac,self.nc)
    def test_corruption_missing_final_and_rebound_hash_not_enough(self):
        for damaged in (self.n[:-1],self.n[:512]+self.n[2048:],b'{}\n',b''):
            ctx=copy.deepcopy(self.nc);ctx['capture_sha256']=hashlib.sha256(damaged).hexdigest();ctx['capture_bytes']=len(damaged)
            with self.assertRaises(ValueError):contract.verify_context(ctx,damaged,'native')
            with self.assertRaises(ValueError):self.context(damaged)
    def test_mixed_schema_and_missing_contract_rejected_even_with_good_hash(self):
        for mutate in (lambda r:r[1].update(schema='M15O2'),lambda r:r[0].pop('power_supply_contract'),
                       lambda r:r[0].update(power_supply_contract='USB_PD'),lambda r:r[-1].update(schema='M15O2-supervisor')):
            rows=o3.legacy.load(self.n);mutate(rows);bad=encode(rows)
            ctx=copy.deepcopy(self.nc);ctx.update(capture_sha256=hashlib.sha256(bad).hexdigest(),capture_bytes=len(bad))
            with self.assertRaises(ValueError):contract.verify_context(ctx,bad,'native')
    def test_old_context_or_topology_not_implicitly_upgraded(self):
        old=(M15/'phaseb/topology/fixtures')
        for ctx in (json.loads((old/'native.context.synthetic.json').read_bytes()),
                    {**self.nc,'schema':'M15-context-v1'},{**self.nc,'observation_schema':'M15O2'},
                    {**self.nc,'power_supply_contract':'unknown'}):
            with self.assertRaises(ValueError):contract.verify_context(ctx,self.n,'native')
        for field,value in [('schema','M15-topology-v1'),('observation_schema','M15O2'),('power_supply_contract','unknown')]:
            topo=self.manifest.copy();topo[field]=value
            with self.assertRaises(ValueError):contract.make_context(topo,self.n,'native')
    def test_o1_o2_raw_even_declared_as_o3_context_stays_rejected(self):
        for path in (M15/'phaseb/fixtures/m15o1-synthetic.jsonl',M15/'phaseb/topology/fixtures/native.synthetic.jsonl'):
            b=path.read_bytes();ctx=copy.deepcopy(self.nc);ctx.update(capture_sha256=hashlib.sha256(b).hexdigest(),capture_bytes=len(b))
            with self.assertRaises(ValueError):contract.verify_context(ctx,b,'native')
    def test_topology_mismatch_blocks_pairs_and_cli_exit_two(self):
        p=self.run_compare(FIX/'native-mismatch.context.synthetic.json');self.assertEqual(p.returncode,2,p.stderr)
        r=json.loads(p.stdout);self.assertEqual(r['blocked_reasons'],['TOPOLOGY_MISMATCH']);self.assertEqual(r['sample_pairs'],[]);self.restrict(r)
        for field,value in [('charger_inventory_sha256','4'*64),('cable_inventory_sha256','5'*64),
                            ('instrumentation_inventory_sha256','6'*64),('evidence_path','ram-offline')]:
            topo=self.manifest.copy();topo[field]=value;ctx=contract.make_context(topo,self.n,'native')
            r=compare_v3.compare(self.a,self.n,self.ac,ctx);self.assertEqual(r['blocked_reasons'],['TOPOLOGY_MISMATCH']);self.restrict(r)
    def test_errno_and_explicit_zero_are_preserved(self):
        r=self.result();fields={f['field']:f for f in r['sample_pairs'][0]['fields']}
        error=fields['qcom-battery/power_max']['native'];self.assertEqual(error['status'],'IO_ERROR')
        self.assertEqual(error['rc'],-1);self.assertEqual(error['errno'],5);self.assertIsNone(error['value'])
        zero=fields['power_supply/usb/current_now']['native'];self.assertEqual(zero['value'],0)
        self.assertEqual(zero['rc'],0);self.assertEqual(zero['errno'],0);self.assertEqual(zero['status'],'OBSERVED')
        self.assertEqual(fields['power_supply/battery/current_now']['native']['value'],-4127000)
    def test_optional_invalid_format_does_not_become_io_errno(self):
        rows=o3.legacy.load(self.n);r=next(r for r in rows if r.get('path')=='apdo_max' and r.get('kind')=='read_end')
        r.update(value='',value_valid=False);b=encode(rows)
        report=compare_v3.compare(self.a,b,self.ac,self.context(b));field=next(f for f in report['sample_pairs'][0]['fields'] if f['field']=='qcom-battery/apdo_max')
        self.assertEqual(field['native']['status'],'INVALID_FORMAT');self.assertIsNone(field['native']['value'])
        self.assertEqual(field['native']['errno'],0);self.assertEqual(field['relation'],'UNAVAILABLE')
    def test_only_o3_contract_can_accept_usb_pd_other_classes_stay_blocked(self):
        for value in ('USB_PD_PPS','USB_DCP','USB_PD_DRP','usb_pd','USB_PD '):
            rows=o3.legacy.load(self.n);row=next(r for r in rows if r.get('path')=='usb/type' and r.get('kind')=='read_end');row['value']=value
            b=encode(rows);report=compare_v3.compare(self.a,b,self.ac,self.context(b))
            self.assertEqual(report['blocked_reasons'],['NATIVE_CORE_UNREADABLE']);self.assertEqual(report['sample_pairs'],[]);self.restrict(report)
    def test_other_core_failure_not_weakened(self):
        rows=o3.legacy.load(self.n);row=next(r for r in rows if r.get('path')=='battery/health' and r.get('kind')=='read_end');row['value']='Overheat'
        b=encode(rows);report=compare_v3.compare(self.a,b,self.ac,self.context(b))
        self.assertEqual(report['blocked_reasons'],['NATIVE_CORE_UNREADABLE']);self.assertEqual(report['sample_pairs'],[]);self.restrict(report)
    def test_relative_timing_keeps_separate_origins(self):
        r=self.result();self.assertEqual(r['android_relative_timing'],r['native_relative_timing'])
        for f in r['sample_pairs'][0]['fields']:
            self.assertEqual(f['android']['relative_begin_ms'],f['native']['relative_begin_ms'])
            self.assertEqual(f['native']['read_duration_ms'],2)
        rows=o3.legacy.load(self.n)
        for row in rows[:-1]:row['mono_ms']+=876543210000
        b=encode(rows);shifted=compare_v3.compare(self.a,b,self.ac,self.context(b))
        self.assertEqual(r['sample_pairs'],shifted['sample_pairs']);self.assertEqual(r['native_relative_timing'],shifted['native_relative_timing'])
    def test_exploratory_aggregate_cannot_generate_context_or_be_sealed(self):
        b=(M15/'o3/fixtures/termux-exploratory-summary.json').read_bytes()
        with self.assertRaises(ValueError):self.context(b)
        ctx=copy.deepcopy(self.nc);ctx.update(capture_sha256=hashlib.sha256(b).hexdigest(),capture_bytes=len(b))
        with self.assertRaises(ValueError):contract.verify_context(ctx,b,'native')
        p=self.run_cli('contract.py','context','--manifest',FIX/'topology.synthetic.json','--capture',
                       M15/'o3/fixtures/termux-exploratory-summary.json','--environment','android')
        self.assertNotEqual(p.returncode,0);self.restrict(json.loads(p.stdout))
    def test_even_eligible_report_and_context_cannot_claim_sender_seal(self):
        self.assertIs(self.ac['sealed_baseline'],False);self.assertEqual(self.ac['evidence_class'],'local-framed-unsealed')
        r=self.result();self.restrict(r)
        for name in ('android','native'):self.assertFalse(r['capture_bindings'][name]['sender_seal_verified'])
        for change in ({'sealed_baseline':True},{'sealed_baseline':0},{'evidence_class':'sealed-baseline'}):
            ctx=copy.deepcopy(self.nc);ctx.update(change)
            with self.assertRaises(ValueError):contract.verify_context(ctx,self.n,'native')
    def test_context_privacy_unknown_keys_and_cli_error_exit_one(self):
        ctx=copy.deepcopy(self.nc);ctx['private_identity']='PRIVATE-FIXTURE-DO-NOT-ECHO';path=self.out/'bad.json';path.write_text(json.dumps(ctx))
        p=self.run_compare(path);self.assertEqual(p.returncode,1);self.assertNotIn(b'PRIVATE-FIXTURE-DO-NOT-ECHO',p.stdout+p.stderr);self.restrict(json.loads(p.stdout))
    def test_duplicate_nonfinite_oversized_context_metadata_is_fail_closed(self):
        for b in (b'{"schema":1,"schema":2}',b'{"number":NaN}',b' '*16385,b'null',b'['*1200+b']'*1200):
            path=self.out/'bad-metadata.json';path.write_bytes(b)
            p=self.run_compare(path);self.assertEqual(p.returncode,1);self.restrict(json.loads(p.stdout))
    def test_privacy_role_text_is_not_echoed_into_comparison(self):
        rows=o3.legacy.load(self.n)
        row=next(r for r in rows if r.get('path')=='port0/data_role' and r.get('kind')=='read_end')
        row['value']='PRIVATE-FIXTURE-DO-NOT-ECHO';b=encode(rows)
        r=compare_v3.compare(self.a,b,self.ac,self.context(b));self.assertNotIn('PRIVATE-FIXTURE-DO-NOT-ECHO',json.dumps(r))
        f=next(f for f in r['sample_pairs'][0]['fields'] if f['field']=='typec/port0/data_role')
        self.assertEqual(f['native']['status'],'INVALID_FORMAT');self.assertIsNone(f['native']['value'])
    def test_schema_documents_are_closed_and_match_runtime(self):
        for name,keys in [('topology-v2.schema.json',contract.TOPOLOGY_KEYS),('context-v2.schema.json',contract.CONTEXT_KEYS)]:
            schema=json.loads((HERE/'schemas'/name).read_bytes());self.assertFalse(schema['additionalProperties'])
            self.assertEqual(set(schema['required']),keys);self.assertEqual(set(schema['properties']),keys)
            self.assertEqual(schema['properties']['observation_schema']['const'],'M15O3')
        c=json.loads((HERE/'schemas/context-v2.schema.json').read_bytes())
        self.assertIs(c['properties']['sealed_baseline']['const'],False)
        self.assertTrue((HERE/'schemas'/c['properties']['topology']['$ref']).exists())
    def test_legacy_comparator_v2_still_has_exact_old_usb_pd_verdict(self):
        old=M15/'phaseb/topology/fixtures';a=(old/'android.synthetic.jsonl').read_bytes();n=(old/'native.synthetic.jsonl').read_bytes()
        rows=o3.legacy.load(n)
        for row in rows:
            if row.get('path')=='usb/type' and row.get('kind')=='read_end':row['value']='USB_PD'
        b=encode(rows)
        ac=json.loads((old/'android.context.synthetic.json').read_bytes());nc=json.loads((old/'native.context.synthetic.json').read_bytes())
        nc['capture_sha256']=hashlib.sha256(b).hexdigest()
        report=legacy_compare.compare(a,b,ac,nc)
        self.assertEqual(report['schema'],'M15-comparison-v2');self.assertEqual(report['comparison_eligibility'],'BLOCKED')
        with self.assertRaises(ValueError):legacy_topology.make_context(ac['topology'],self.a,'android')
    def test_sample_count_and_port_names_not_silently_aligned(self):
        rows=o3.legacy.load(self.n);body=copy.deepcopy(rows[:-2]);second=copy.deepcopy(rows[1:-2]);body[0]['samples']=2
        for row in second:row['sample']=1;row['mono_ms']+=200
        body+=second;end=copy.deepcopy(rows[-2]);end.update(sample=1,mono_ms=end['mono_ms']+200);body.append(end)
        for i,row in enumerate(body):row['seq']=i
        body[-1]['records']=len(body);b=encode(body+[rows[-1]])
        r=compare_v3.compare(self.a,b,self.ac,self.context(b));self.assertEqual(r['unpaired_samples'],{'android':0,'native':1})
        self.assertEqual(len(r['sample_pairs']),1);self.restrict(r)
        rows=o3.legacy.load(self.n)
        for row in rows:
            if row.get('group')=='typec':row['path']=row['path'].replace('port0','port12')
        b=encode(rows);r=compare_v3.compare(self.a,b,self.ac,self.context(b))
        self.assertTrue(all(f['relation']=='UNAVAILABLE' for f in r['sample_pairs'][0]['fields'] if f['field'].startswith('typec/')))

if __name__=='__main__':unittest.main()
