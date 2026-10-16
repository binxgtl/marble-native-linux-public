import hashlib
import unittest
from evidence import CONDITIONS, decode_capture, inspect_journal
N='1'*32; I='2'*64

def journal():
    rows=[('session','identity','metadata',0,N+' '+I)]
    rows += [(c,'unsupported','metadata',95,'not_implemented') for c in CONDITIONS]
    rows += [('session','final_state','metadata',0,'amp_enable_permitted=0 actuator_implemented=0')]
    raw=b''.join(f'M11I1 {s} 1.00 {c} {op} {impact} {rc} {payload.encode().hex()}\n'.encode() for s,(c,op,impact,rc,payload) in enumerate(rows))
    return raw+f'M11I1 END {len(rows)} {hashlib.sha256(raw).hexdigest()}\n'.encode()

def frame(kind,payload):return f'M11I1R {kind} {len(payload)}\n'.encode()+payload

def capture(data=None,drops=0):
    data=journal() if data is None else data
    return frame('K',b'6,42,1000,-;start\n')+frame('K',b'6,43,1001,-;end\n')+frame('E',data[:30])+frame('E',data[30:])+frame('F',f'events={len(data)} kernel_drops={drops}\n'.encode())

class Tests(unittest.TestCase):
    def test_complete_is_not_permission(self):
        r=decode_capture(capture(),N,I)
        self.assertTrue(r['capture_complete']);self.assertFalse(r['amplifier_enable_permitted'])
        self.assertEqual(r['runtime_proof_coverage'],0);self.assertEqual(len(r['conditions']),8)
        self.assertTrue(all(c['status']=='UNKNOWN' for c in r['conditions'].values()))
    def test_every_capture_truncation(self):
        raw=capture()
        for n in range(len(raw)):
            r=decode_capture(raw[:n],N,I);self.assertFalse(r['capture_complete'],n);self.assertFalse(r['amplifier_enable_permitted'])
    def test_every_payload_byte_corruption(self):
        raw=journal()
        for n in range(len(raw)):
            damaged=bytearray(raw);damaged[n]^=1
            with self.assertRaises(ValueError):inspect_journal(bytes(damaged),N,I)
    def test_identity(self):
        for n,i in [('3'*32,I),(N,'4'*64),('invalid',I)]:self.assertFalse(decode_capture(capture(),n,i)['capture_complete'])
    def test_kernel_gap_duplicate_order(self):
        for seq in (42,44,1):self.assertFalse(decode_capture(capture().replace(b'6,43,',f'6,{seq},'.encode()),N,I)['capture_complete'])
    def test_drops_warnings_trailing(self):
        for raw in [capture(drops=1),frame('W',b'loss\n')+capture(),capture()+b'x']:
            self.assertFalse(decode_capture(raw,N,I)['capture_complete'])
    def test_forged_records_even_with_recomputed_hash(self):
        raw=journal();prefix=raw[:raw.rfind(b'M11I1 END')]
        for old,new in [(b' 95 ',b' 0 '),(b'unsupported',b'PASS'),(b' metadata ',b' hardware_action '),(b'M11I1 1 ',b'M11I1 0 ')]:
            p=prefix.replace(old,new,1);j=p+f'M11I1 END 10 {hashlib.sha256(p).hexdigest()}\n'.encode()
            self.assertFalse(decode_capture(capture(j),N,I)['capture_complete'])
    def test_no_kernel_false(self):
        j=journal();raw=frame('E',j)+frame('F',f'events={len(j)} kernel_drops=0\n'.encode())
        self.assertFalse(decode_capture(raw,N,I)['capture_complete'])

if __name__=='__main__':unittest.main()
