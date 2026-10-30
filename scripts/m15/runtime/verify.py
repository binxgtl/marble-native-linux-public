#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Strict native adapter, preserving the frozen M15E1 decoder and O3 parser."""
import hashlib,inspect,json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'native1'))
import host
from provenance import validate
# Reuse only the exact decoder; the explicitly versioned metadata admission
# changes here. No raw rewriting, synthetic substitution or resynchronization.
source=inspect.getsource(host.decode)
old='''    if set(metadata)!=FIELDS or metadata['schema']!='M15-native-phase1-metadata-v1' or metadata['synthetic_only'] is not True:
        raise ValueError('phase1-synthetic-metadata-only')
    if metadata['launcher']!='offline-subreaper' or metadata['evidence_path']!='ram-escrow-deferred-export':raise ValueError('instrumentation-mismatch')'''
if source.count(old)!=1:raise ValueError('frozen-decoder-contract-drift')
# Run1 to Run5 took 3 samples and Run6 takes 10. Custodian fixes the count; metadata binds its hash.
samples="if contract.o3.legacy.load(data['capture.raw'])[0]['samples']!=3:raise ValueError('three-sample-contract')"
if source.count(samples)!=1:raise ValueError('frozen-decoder-contract-drift')
source=source.replace(samples,"if contract.o3.legacy.load(data['capture.raw'])[0]['samples'] not in (3,10):raise ValueError('sample-count-contract')")
source=source.replace('def decode(raw):','def decode(raw,*,allow_fixture=False):',1).replace(old,'    validate(metadata,allow_fixture)')
source=source.replace("'synthetic_only':True,","'synthetic_only':metadata['synthetic_only'],")
scope=dict(vars(host),validate=validate);exec(compile(source,'<M15 native metadata adapter>','exec'),scope)
_decode=scope['decode']
def decode(raw,*,allow_fixture=False):
    files,report,ack=_decode(raw,allow_fixture=allow_fixture)
    data=files['kernel.txt'];marker=b'M15_PARENT_JOURNAL\n'
    if data.count(marker)!=1:raise ValueError('native-kernel-boundary')
    kmsg,journal=data.split(marker)
    previous=None;first=None
    for row in kmsg.splitlines(keepends=True):
        m=host.re.fullmatch(rb'[0-9]+,([0-9]+),[0-9]+,[^;\n]+;[^\x00]*\n',row)
        if not m:
            # kmsg optional dictionary lines belong to the preceding record.
            if previous is not None and host.re.fullmatch(rb' [A-Z0-9_]+=[^\x00\n]*\n',row):continue
            raise ValueError('native-kernel-record')
        n=int(m[1])
        if previous is not None and n!=previous+1:raise ValueError('native-kernel-gap')
        previous=n
        if first is None:first=n
    if previous is None or not journal.endswith(b'\n') or b'KERNEL_COVERAGE_END before_freeze' not in journal:raise ValueError('native-kernel-incomplete')
    for event in (b'CONNECTOR_READY',b'REMOVED',b'UNBOUND',b'ATTACHED',b'COLLECT_RETURNED'):
        if event not in journal:raise ValueError('native-parent-stage-missing')
    metadata=json.loads(files['metadata.json'])
    report.update(schema='M15-native-runtime-host-verification-v1',native_runtime_proven=False,
                  comparison_eligible=False,physical_connector_reported=not metadata['synthetic_only'],
                  kernel_first_sequence=first,kernel_last_sequence=previous,
                  charger_identity='operator-reported',runtime_kernel_identity_verified=False)
    return files,report,ack
def verify(path,allow_fixture=False):
    with path.open('rb') as f:raw=f.read(16*1024*1024+1)
    _,report,ack=decode(raw,allow_fixture=allow_fixture)
    receipt={'schema':'M15-native-runtime-saved-file-v1','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
             'verification':report,'sender_receipt':'UNKNOWN','storage_power_loss_survival':'UNKNOWN'}
    with path.with_suffix('.receipt.json').open('xb') as f:
        payload=(json.dumps(receipt,sort_keys=True)+'\n').encode()
        if f.write(payload)!=len(payload):raise OSError('short receipt')
        f.flush();os.fsync(f.fileno())
    return ack
if __name__=='__main__':
    try:sys.stdout.buffer.write(verify(Path(sys.argv[1])))
    except Exception:sys.exit(1)
