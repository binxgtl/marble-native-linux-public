#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline integration facts. No connector/getter/module or recovery actions."""
import hashlib
import re

class Boundary:
    def __init__(self, run):
        if not re.fullmatch('[0-9a-f]{32}',run) or run=='0'*32:raise ValueError('run')
        self.run=run;self.sequence=0;self.phase='pc';self.failed=False
        self.pending=None;self.journal=[];self.owners={};self.escrow_lost=False
    def reject(self,reason):
        self.failed=True;raise ValueError(reason)
    def call_begin(self,name):
        if self.failed or self.pending is not None:self.reject('overlapping-or-failed')
        expected={'pc':'admission','isolate':'unbind','wall':'attachment','reconnect':'rebind'}
        if expected.get(self.phase)!=name:self.reject('operation-order')
        self.pending=name;self.journal.append(('begin',name))
    def call_end(self,name,rc,error):
        if self.failed or self.pending!=name:self.reject('unmatched-end')
        if type(rc)!=int or type(error)!=int or error<0:self.reject('errno-contract')
        self.journal.append(('end',name,rc,error));self.pending=None
        if rc!=0 or error!=0:self.reject('operation-failed')
    def event(self,sequence,run,name,facts):
        if self.failed or self.pending is not None or sequence!=self.sequence or run!=self.run:self.reject('ipc-binding')
        contracts={
            'pc':('admitted',{'host_receipt':True},'isolate'),
            'isolate':('isolated',{'transmitter_reaped':True,'unbind_readback_empty':True},'wall'),
            'wall':('attached',{'operator_declared_wall':True,'pc_absent':True},'collect'),
            'collect':('frozen',{'collector_receipt':True,'census_closed':True},'reconnect'),
            'reconnect':('connected',{'pc_configured':True},'export'),
            'export':('ack',{'saved_file_verified':True,'ack_bound':True},'recovered')}
        expected,required,next_phase=contracts.get(self.phase,(None,None,None))
        if expected is None or name!=expected or type(facts)!=dict or set(facts)!=set(required) or any(facts[k] is not True for k in required):self.reject('event-contract')
        calls={'pc':'admission','isolate':'unbind','wall':'attachment','reconnect':'rebind'}
        if self.phase in calls and (not self.journal or self.journal[-1]!=('end',calls[self.phase],0,0)):self.reject('missing-returned-operation')
        if name in ('frozen','ack') and any(v is None for v in self.owners.values()):self.reject('unresolved-owner')
        self.sequence+=1;self.phase=next_phase
    def own(self,pid,start):
        key=(pid,start)
        if self.failed or pid<=1 or start<0 or key in self.owners:self.reject('owner')
        self.owners[key]=None
    def reaped(self,pid,start,status,custodian=False):
        key=(pid,start)
        if key not in self.owners or self.owners[key] is not None:self.reject('unknown-reap')
        self.owners[key]=status
        if custodian and (self.phase!='recovered' or status!=0):
            self.escrow_lost=True;self.failed=True
    def timeout(self):
        # Deliberately no manufactured call_end, success, kill or teardown fact.
        self.failed=True
    @property
    def release_permitted(self):
        return not self.failed and self.phase=='recovered' and all(v==0 for v in self.owners.values())

class KernelSpool:
    def __init__(self,budget):
        if type(budget)!=int or budget<=0 or budget>8388608:raise ValueError('budget')
        self.budget=budget;self.raw=bytearray();self.next=None;self.failed=False;self.frozen=False
    def append(self,record):
        if self.failed or self.frozen:raise ValueError('spool-terminal')
        m=re.fullmatch(rb'[0-9]+,([0-9]+),[0-9]+,[^;\n]*;[^\n]*\n',record)
        if not m or len(self.raw)+len(record)>self.budget:
            self.failed=True;raise ValueError('spool-format-or-budget')
        seq=int(m[1])
        if self.next is not None and seq!=self.next:
            self.failed=True;raise ValueError('kernel-sequence-loss')
        self.next=seq+1;self.raw.extend(record)
    def freeze(self):
        if self.failed or self.frozen:raise ValueError('spool-terminal')
        self.frozen=True
        return bytes(self.raw),hashlib.sha256(self.raw).hexdigest()

def provenance(value):
    """Versioned synthetic integration sidecar; NOT accepted as real native context."""
    hashes={'source','observer','launcher','kernel','closure','firmware','topology','evidence_path'}
    keys=hashes|{'schema','synthetic_only','launcher_kind','control_permitted','sealed_baseline'}
    if type(value)!=dict or set(value)!=keys:raise ValueError('provenance-schema')
    if value['schema']!='M15-native-integration-fixture-v1' or value['synthetic_only'] is not True:raise ValueError('fixture-only')
    if value['launcher_kind']!='dedicated-custodian' or value['control_permitted'] is not False or value['sealed_baseline'] is not False:raise ValueError('native-contract')
    for name in hashes:
        if type(value[name])!=str or not re.fullmatch('[0-9a-f]{64}',value[name]):raise ValueError('hash')
    return {'comparison_eligible':False,'native_runtime_proven':False,'control_permitted':False}
