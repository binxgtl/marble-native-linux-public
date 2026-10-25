import hashlib,runpy
from pathlib import Path
e=runpy.run_path(str(Path(__file__).with_name('evidence.py')))
N,I='a'*32,'b'*64
STAGES=('firmware','interface','scan','association','wpa','dhcp','ping','disconnect','lease_reset','reconnect','reassociation','rewpa','redhcp','reping','network_cleanup')
B=('config','firmware','interface','supplicant_spawn','scan','association','wpa','dhcp','ping','disconnect','lease_reset','reconnect','reassociation','rewpa','redhcp','reping','cleanup')
def diagnostics():
 out=[];t=1
 def add(name):
  nonlocal t
  out.append((name,0,t));t+=100000000
 add('network_begin')
 for stage in B:
  add(stage+'_begin')
  if stage=='disconnect':
   for x in ('ack','event','status'):add('disconnect_'+x)
   t+=2000000000;add('disconnect_dwell')
  add(stage+'_return')
 add('network_return');return out

def capture(diag=None,stages=STAGES):
 rows=[]
 def row(op,payload):rows.append(f'M12I2 {len(rows)} 1.000000000 session {op} metadata 0 {payload.encode().hex()}\n'.encode())
 def f(kind,p):return f'M12I2R {kind} {len(p)}\n'.encode()+p
 d=b''.join(f'M12D3 {t} {name} {rc}\n'.encode() for name,rc,t in (diagnostics() if diag is None else diag))
 row('identity',N+' '+I);row('pre_query',f'pre-query {N} {I} amplifier_enable_permitted=0');pre=b''.join(rows);barrier=rows[-1]
 row('pre_query_ack','PID1 accepted exact PC receipt of pre_query; amplifier_enable_permitted=0');row('kernel_privacy','Intentional cutoff')
 row('connectivity',''.join('M12NET '+x+' PASS rc=0\n' for x in stages));row('diagnostics_digest',f'{len(d)} {hashlib.sha256(d).hexdigest()}')
 row('final_state','amplifier_enable_permitted=0 rf_scan_permitted=1 association_permitted=1 wifi_ready=UNKNOWN')
 j=b''.join(rows);j+=f'M12I2 END {len(rows)} {hashlib.sha256(j).hexdigest()}\n'.encode()
 return f('H',f'{N} {I}\n'.encode())+f('E',pre)+f('B',barrier)+f('E',j[len(pre):])+f('D',d)+f('F',f'events={len(j)} kernel_drops=0\n'.encode())
raw=capture();decode=lambda b:e['decode_capture'](b,N,I)
r=decode(raw);assert r['capture_complete'] and r['wifi_ready']=='RECONNECTIVITY_PASS' and r['reconnect_verified'],r
for stage in STAGES:
 assert not decode(capture(stages=tuple(x for x in STAGES if x!=stage)))['capture_complete'],stage
for name in ('disconnect_ack','disconnect_event','disconnect_status','disconnect_dwell','redhcp_return','reping_return'):
 assert not decode(capture(diag=[x for x in diagnostics() if x[0]!=name]))['capture_complete'],name
 assert not decode(capture(diag=[(n,-1 if n==name else rc,t) for n,rc,t in diagnostics()]))['capture_complete'],name
short=diagnostics();at=next(t for n,rc,t in short if n=='disconnect_status');short=[(n,rc,at+1999999999 if n=='disconnect_dwell' else t) for n,rc,t in short]
assert not decode(capture(diag=short))['capture_complete']
for b in (raw[:-1],raw+b'x',raw.replace(b'kernel_drops=0',b'kernel_drops=1'),capture(stages=STAGES+('ping',))):assert not decode(b)['capture_complete']
print('Run11 evidence PASS: exact15 stages + new disconnect event/status/dwell >=2s + fresh DHCP/ping; valid-digest missing/failing/duplicate/truncated cases reject')
