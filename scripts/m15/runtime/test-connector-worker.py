#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real connector worker over a plain tree that fills in the order the device does.

Run2 regression: the worker used to require the Type-C port at its first instruction.
The tree is synthetic, so this proves ordering only, not any device behaviour.
"""
import os,select,shutil,stat,subprocess,sys,time
from pathlib import Path
binary,root=sys.argv[1],Path(sys.argv[2])
WAIT=3
def tree():
    shutil.rmtree(root,ignore_errors=True)
    for d in ('sys/class/typec','sys/class/udc','sys/class/tty/ttyGS0','sys/devices/ucsi/typec','sys/devices/dwc','dev'):(root/d).mkdir(parents=True)
    (root/'sys/class/tty/ttyGS0/dev').write_text('238:0\n')
def port(role='source [sink]\n'):
    p=root/'sys/devices/ucsi/typec/port0';p.mkdir();(p/'power_role').write_text(role)
    (root/'sys/class/typec/port0').symlink_to('../../devices/ucsi/typec/port0')
def partner():
    (root/'sys/devices/ucsi/typec/port0/port0-partner').mkdir()
    (root/'sys/class/typec/port0-partner').symlink_to('../../devices/ucsi/typec/port0/port0-partner')
def udc():
    p=root/'sys/devices/dwc/a600000.dwc3';p.mkdir();(p/'state').write_text('not attached\n')
    (root/'sys/class/udc/a600000.dwc3').symlink_to('../../devices/dwc/a600000.dwc3')
def start():
    return subprocess.Popen([binary],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
def quiet(process,seconds):
    assert not select.select([process.stdout],[],[],seconds)[0],'worker spoke early'
    assert process.poll() is None
def line(process,seconds=4):
    assert select.select([process.stdout],[],[],seconds)[0],'worker silent'
    return process.stdout.readline().decode().strip()
def until(path,seconds=4):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if path.exists() and path.read_text():return path.read_text()
        time.sleep(.01)
    raise AssertionError('missing '+str(path))
def stop(process):
    process.kill();process.wait(timeout=5)
    for f in (process.stdin,process.stdout,process.stderr):f.close()
gadget=root/'config/usb_gadget/m15'

tree();p=start()
try:
    # Nothing exists yet, as when bootstrap ends at the PMIC channel.
    quiet(p,.3);port();quiet(p,.2);partner();quiet(p,.2)
    assert not (root/'config').exists(),'gadget built before the UDC'
    udc()
    assert until(gadget/'UDC')=='a600000.dwc3'
    assert (gadget/'idVendor').read_text()=='0x1d6b' and (gadget/'idProduct').read_text()=='0x0104'
    assert (gadget/'configs/c.1/acm.usb0').is_symlink()
    quiet(p,.2);assert not (root/'dev/ttyGS0').exists(),'tty node before configured'
    (root/'sys/devices/dwc/a600000.dwc3/state').write_text('configured\n')
    assert line(p)=='CONNECTOR_READY'
    st=(root/'dev/ttyGS0').lstat();assert stat.S_ISCHR(st.st_mode) and os.major(st.st_rdev)==238 and os.minor(st.st_rdev)==0
finally:stop(p)
print('PASS late port, partner and UDC: no failure, gadget after UDC, tty node after configured')

for name,steps in (('nothing',()),('no-partner',(port,)),('no-udc',(port,partner))):
    tree()
    for step in steps:step()
    p=start();begin=time.monotonic()
    try:
        quiet(p,.5);assert line(p,WAIT+2)=='CONNECTOR_FAILED'
        assert time.monotonic()-begin>=WAIT-.1,'failed before the budget'
        assert not (root/'config').exists() and not (root/'dev/ttyGS0').exists()
    finally:stop(p)
    print('PASS bounded wait, then failure:',name)

tree();port('[source] sink\n');partner();udc();p=start()
try:
    assert line(p)=='CONNECTOR_FAILED' and not (root/'config').exists()
finally:stop(p)
print('PASS source role refused before any gadget')
shutil.rmtree(root)
print('PASS connector worker ordering; synthetic tree, physical behaviour UNKNOWN')
