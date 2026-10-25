#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Only temporary synthetic trees; never reads host /sys or touches a device."""
import argparse
import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
import analyze

VALUES={
 'battery/type':'Battery','battery/present':'1','battery/status':'Charging',
 'battery/health':'Good','battery/capacity':'50','battery/voltage_now':'4000000',
 'battery/current_now':'-300000','battery/temp':'300','battery/charge_control_limit':'0',
 'battery/charge_control_limit_max':'10','usb/type':'USB','usb/online':'1',
 'usb/usb_type':'Unknown SDP [PD_PPS]','usb/voltage_now':'5000000',
 'usb/current_now':'300000','usb/voltage_max':'9000000','usb/current_max':'2000000',
 'usb/input_current_limit':'500000','usb/temp':'310',
}
parser=argparse.ArgumentParser();parser.add_argument('binary',type=Path);parser.add_argument('--fault-binary',type=Path)
args,remaining=parser.parse_known_args();BINARY=args.binary.resolve();FAULT=args.fault_binary.resolve() if args.fault_binary else None

class Observation(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  for path,value in VALUES.items():
   p=self.root/'class/power_supply'/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value+'\n')
  for name,value in [('power_role','[sink] source'),('data_role','[device] host'),('power_operation_mode','usb_power_delivery')]:
   p=self.root/'class/typec/port7'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value+'\n')
 def run_tool(self,fault=None,extra=()):
  env=os.environ.copy()
  if fault:env['M15_TEST_FAULT']=fault
  return subprocess.run([str(FAULT if fault else BINARY),'--fixture-root',str(self.root),
                         '--samples','2','--interval-ms','1',*extra],capture_output=True,env=env,timeout=5)
 def capture(self):
  p=self.run_tool();self.assertEqual(p.returncode,0,p.stderr);return p.stdout
 def decoded(self):return [json.loads(line) for line in self.capture().splitlines()]
 def encoded(self,rows):return b''.join((json.dumps(r)+'\n').encode() for r in rows)
 def reject(self,rows):
  with self.assertRaises(ValueError):analyze.analyze(self.encoded(rows))
 def test_readable_is_not_pd_or_protection_pass(self):
  r=analyze.analyze(self.capture());self.assertEqual(r['telemetry'],'READABLE')
  self.assertFalse(r['control_permitted']);self.assertFalse(r['charging_hardware_pass'])
  self.assertEqual(r['negotiated_contract'],'UNKNOWN');self.assertEqual(r['freshness'],'UNKNOWN')
  self.assertTrue(r['samples'][0]['reported_pd_type']);self.assertIn('port7/power_role',r['samples'][0]['typec_fields'])
 def test_arbitrary_host_chunking(self):
  raw=self.capture()
  for n in (1,3,511,512,513,1536):
   self.assertTrue(analyze.analyze(b''.join(raw[i:i+n] for i in range(0,len(raw),n)))['transcript_complete'])
 def test_missing_errno_is_preserved(self):
  (self.root/'class/power_supply/battery/temp').unlink();r=analyze.analyze(self.capture())
  self.assertEqual(r['telemetry'],'BLOCKED');self.assertIn('battery/temp: errno=2',r['samples'][0]['errors'])
 def test_optional_typec_absent_is_unknown(self):
  import shutil
  shutil.rmtree(self.root/'class/typec');r=analyze.analyze(self.capture())
  self.assertEqual(r['samples'][0]['typec_census_errno'],2);self.assertEqual(r['negotiated_contract'],'UNKNOWN')
 def test_empty_nul_overflow_and_bad_integer(self):
  p=self.root/'class/power_supply/battery/temp'
  for blob in (b'',b'3\x000\n',b'3'*513,b'9999999999999999999999\n',b'30oops\n'):
   p.write_bytes(blob);self.assertEqual(analyze.analyze(self.capture())['telemetry'],'BLOCKED')
 def test_temperature_not_a_policy(self):
  (self.root/'class/power_supply/battery/temp').write_text('600\n')
  r=analyze.analyze(self.capture());self.assertEqual(r['telemetry'],'READABLE');self.assertFalse(r['control_permitted'])
 def test_unknown_health_blocks(self):
  (self.root/'class/power_supply/battery/health').write_text('Overheat\n')
  self.assertEqual(analyze.analyze(self.capture())['telemetry'],'BLOCKED')
 def test_usb_selection_validation(self):
  p=self.root/'class/power_supply/usb/usb_type'
  for value in ('PD_PPS','[PD] [PD_PPS]','[PD] PD','[Imaginary]',' [PD]','[PD]  SDP'):
   p.write_text(value+'\n');self.assertEqual(analyze.analyze(self.capture())['telemetry'],'BLOCKED')
 def test_wrong_supply_type_and_bad_thermal_index(self):
  for name,value in [('usb/type','Wireless'),('battery/charge_control_limit','11')]:
   p=self.root/'class/power_supply'/name;p.write_text(value+'\n');self.assertEqual(analyze.analyze(self.capture())['telemetry'],'BLOCKED');p.write_text(VALUES[name]+'\n')
 def test_sequence_gap_duplicate_and_order(self):
  rows=self.decoded()
  for mutate in (lambda r:r.pop(4),lambda r:r.insert(4,copy.deepcopy(r[4])),lambda r:r[4].update(seq=1000),lambda r:r[4].update(mono_ms=-1)):
   r=copy.deepcopy(rows);mutate(r);self.reject(r)
 def test_semantic_mutants_with_repaired_sequence(self):
  rows=self.decoded()
  for mutate in (lambda r:r[2].update(path='battery/arbitrary'),lambda r:r[2].update(unit='mA'),lambda r:r[2].update(errno=5),lambda r:r[-3].update(ports=2),lambda r:r[1].update(kind='read_end'),lambda r:r[2].update(sample=8)):
   r=copy.deepcopy(rows);mutate(r);self.reject(r)
 def test_start_final_and_receipt(self):
  rows=self.decoded()
  for mutate in (lambda r:r.pop(),lambda r:r.pop(-2),lambda r:r[-1].update(reaped=False),lambda r:r[-1].update(raw_status=9),lambda r:r[0].update(control_permitted=True),lambda r:r[-2].update(records=7)):
   r=copy.deepcopy(rows);mutate(r);self.reject(r)
 def test_truncation_and_corruption(self):
  raw=self.capture()
  for n in (1,2,50,512,1536,len(raw)-1):
   with self.assertRaises(ValueError):analyze.analyze(raw[:-n])
  with self.assertRaises(ValueError):analyze.analyze(raw.replace(b'"seq":1',b'"seq":0',1))
 def test_duplicate_json_key(self):
  with self.assertRaises(ValueError):analyze.analyze(self.capture().replace(b'"seq":0',b'"seq":0,"seq":0',1))
 def test_no_implicit_live_collection(self):
  p=subprocess.run([str(BINARY)],capture_output=True,timeout=2);self.assertEqual(p.returncode,64);self.assertEqual(p.stdout,b'')
 def test_stdout_failure(self):
  with open(os.devnull,'rb') as ro:
   p=subprocess.run([str(BINARY),'--fixture-root',str(self.root),'--samples','1'],stdout=ro,stderr=subprocess.PIPE,timeout=3)
  self.assertNotEqual(p.returncode,0)
 def test_backpressure_is_failure_not_dropped_success(self):
  p=subprocess.Popen([str(BINARY),'--fixture-root',str(self.root),'--samples','10','--interval-ms','1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:
   self.assertNotEqual(p.wait(timeout=5),0)
   raw,err=p.communicate(timeout=1)
   with self.assertRaises(ValueError):analyze.analyze(raw)
  finally:
   if p.poll() is None:p.kill();p.communicate()
 def test_supervised_deadline(self):
  p=self.run_tool(extra=['--interval-ms','1000','--deadline-ms','20'])
  self.assertNotEqual(p.returncode,0);self.assertIn(b'"reaped":true',p.stderr)
  with self.assertRaises(ValueError):analyze.analyze(p.stdout)
 def test_actual_read_faults(self):
  if not FAULT:self.skipTest('linker fault binary not requested')
  for mode in ('short-read','short-write','eintr'):
   p=self.run_tool(fault=mode);self.assertEqual(p.returncode,0,(mode,p.stderr));self.assertTrue(analyze.analyze(p.stdout)['transcript_complete'])
  for mode in ('read-block','output-error'):
   p=self.run_tool(fault=mode,extra=['--deadline-ms','100']);self.assertNotEqual(p.returncode,0);self.assertIn(b'"reaped":true',p.stderr)
   with self.assertRaises(ValueError):analyze.analyze(p.stdout)

if __name__=='__main__':unittest.main(argv=['test.py',*remaining])
