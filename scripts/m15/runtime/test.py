#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import copy,json,os,re,sys,tempfile,unittest
from pathlib import Path
import provenance,verify,prepare
ROOT=Path(__file__).resolve().parents[3]
class Tests(unittest.TestCase):
    def metadata(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input';p.write_bytes(b'synthetic')
            return provenance.inventory(dict.fromkeys(provenance.ROLES,p),True)
    def test_fixture_never_native(self):
        m=self.metadata();provenance.validate(m,True)
        with self.assertRaises(ValueError):provenance.validate(m)
    def test_exact_contract_and_unknowns(self):
        m=self.metadata()
        mutations=[('schema','M15-native-phase1-metadata-v1'),('launcher','offline-subreaper'),('control_permitted',True),('freshness','PROVEN'),('charger_identity','USB-PD authenticated')]
        for k,v in mutations:
            x=copy.deepcopy(m);x[k]=v
            with self.assertRaises(ValueError):provenance.validate(x,True)
        m['inventory'].pop('connector')
        with self.assertRaises(ValueError):provenance.validate(m,True)
        m=self.metadata();m['inventory']['pid1']['expected_cpio_mode']='0644'
        with self.assertRaises(ValueError):provenance.validate(m,True)
    def test_missing_preparation_inputs(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):prepare.qualify(Path(d),Path(d)/'kernel')
    def test_original_closure_and_new_tail(self):
        read=lambda p:re.findall(r'"([^"\n]+\.ko)"',(ROOT/p).read_text())
        a=read('scripts/m7-closure-load-order.inc');b=read('scripts/m8-closure-load-order.inc')
        tail=read('scripts/m15/runtime/load-m8-tail.c')
        self.assertEqual(len(a),95);self.assertEqual(len(b),100)
        self.assertEqual([x for x in b if x not in a],tail)
        self.assertEqual(set(a+tail),set(b))
    def test_actual_bootstrap_paths_and_forbidden_controls(self):
        s=(ROOT/'scripts/m15/runtime/init').read_text();b=(ROOT/'scripts/m15/runtime/bootstrap').read_text()
        self.assertIn('exec /sbin/m15-bootstrap-supervisor',s)
        self.assertIn('/sbin/m10-load-phase0',b);self.assertIn('/sbin/m15-load-m8-tail',b)
        self.assertNotIn('switch_root',s)
        for p in ('init','bootstrap','pid1.c','connector-worker.c','custodian.c','bootstrap-supervisor.c'):
            text=(ROOT/'scripts/m15/runtime'/p).read_text()
            code='\n'.join(x for x in text.splitlines() if not x.strip().startswith(('# ','/*','*')))
            self.assertNotRegex(code,r'\breboot\s*\(|\bsystemctl\s+.*reboot|/persist|/data/|force_pd|force_pps')
    def test_schema_adapter_does_not_accept_old_fixture(self):
        self.assertIsNot(verify.decode,verify.host.decode)
        raw=Path(os.environ['M15_OLD_WIRE']).read_bytes()
        verify.host.decode(raw)
        with self.assertRaises(ValueError):verify.decode(raw,allow_fixture=True)
if __name__=='__main__':unittest.main()
