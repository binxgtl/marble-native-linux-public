#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent saved-file verifier for offline Windows receiver. No device I/O."""
import hashlib,json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'native1'))
import host
def verify(path):
    with path.open('rb') as f:raw=f.read(16*1024*1024+1)
    _,report,ack=host.decode(raw)
    receipt={'schema':'M15-native4-offline-receipt-v1','sha256':hashlib.sha256(raw).hexdigest(),
             'bytes':len(raw),'verification':report,'control_permitted':False,
             'storage_power_loss_survival':'UNKNOWN','sender_receipt':'UNKNOWN'}
    with path.with_suffix('.receipt.json').open('xb') as f:
        data=(json.dumps(receipt,sort_keys=True)+'\n').encode()
        if f.write(data)!=len(data):raise OSError('short receipt')
        f.flush();os.fsync(f.fileno())
    return ack
if __name__=='__main__':
    try:sys.stdout.buffer.write(verify(Path(sys.argv[1])))
    except Exception:sys.exit(1)
