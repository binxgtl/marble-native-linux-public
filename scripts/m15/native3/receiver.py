#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline binary-stream storage adapter. No serial opener or device commands."""
import hashlib
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'native1'))
import host

class Receiver:
    """Caller supplies bounded chunks; ACK is unavailable until saved-file replay.

    fsync is an OS flush request, not proof of media survival through power loss.
    Capture and receipt are exclusively created. Every failed state is sticky.
    """
    def __init__(self, path, *, write=os.write, sync=os.fsync):
        self.path=Path(path);self.write=write;self.sync=sync
        self.failed=False;self.finished=False;self.count=0;self.digest=hashlib.sha256()
        self.fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    def abort(self):
        self.failed=True
        if self.fd is not None:
            fd,self.fd=self.fd,None
            os.close(fd)
    def feed(self, raw):
        if self.failed or self.finished:raise ValueError('receiver-terminal')
        try:
            if not isinstance(raw,bytes) or self.count+len(raw)>16*1024*1024:raise ValueError('receiver-budget')
            at=0
            while at<len(raw):
                n=self.write(self.fd,raw[at:])
                if not isinstance(n,int) or n<=0 or n>len(raw)-at:raise OSError('short-write-failure')
                self.digest.update(raw[at:at+n]);self.count+=n;at+=n
        except BaseException:
            self.abort();raise
    def finish(self, expected_bytes):
        if self.failed or self.finished:raise ValueError('receiver-terminal')
        try:
            if type(expected_bytes)!=int or self.count!=expected_bytes:raise ValueError('incomplete-receiver')
            self.sync(self.fd);os.close(self.fd);self.fd=None
            with self.path.open('rb') as f:raw=f.read(16*1024*1024+1)
            if len(raw)!=self.count or hashlib.sha256(raw).digest()!=self.digest.digest():raise ValueError('saved-byte-mismatch')
            _,report,ack=host.decode(raw)
            receipt={'schema':'M15-offline-receiver-v1','raw_bytes':self.count,
                     'raw_sha256':self.digest.hexdigest(),'flush_returned':True,
                     'storage_power_loss_survival':'UNKNOWN','synthetic_only':True,
                     'control_permitted':False,'verification':report}
            payload=(json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()
            with self.path.with_suffix(self.path.suffix+'.receipt.json').open('xb') as f:
                if f.write(payload)!=len(payload):raise OSError('receipt-short-write')
                f.flush();self.sync(f.fileno())
            self.finished=True
            return ack
        except BaseException:
            self.abort();raise
