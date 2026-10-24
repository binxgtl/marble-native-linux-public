"""Run the actual post-run listing against a stand-in adb (Windows: adb.cmd); no phone, no real adb.
Checks the exact read-only command set, the metadata-only output without the serial, and the
refusals. M11_PWSH may name the PowerShell executable (CI: pwsh)."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
pwsh = os.environ.get('M11_PWSH', 'pwsh')
STANDIN = 'deadbeef'  # the stand-in adb's synthetic device id, not a device
FAKE = '\r\n'.join([
    '@echo off',
    'echo %*>>"%~dp0calls.log"',
    'if "%1"=="devices" goto devices',
    'if "%6"=="/sys/fs/pstore" goto pstore',
    'if "%6"=="/data/vendor/diag" goto diag',
    'exit /b 1',
    ':devices',
    'echo List of devices attached',
    'if "%FAKE_MODE%"=="wrong" (echo 0badc0de device) else (echo deadbeef device)',
    'if "%FAKE_MODE%"=="multi" echo 12345678 device',
    'exit /b 0',
    ':pstore',
    'echo total 0',
    'echo dr-xr-x---  2 system log  0 1972-08-09 19:12 .',
    'echo drwxr-xr-x 10 root   root 0 1970-01-01 08:00 ..',
    'if "%FAKE_MODE%"=="pstorefile" echo -r--r-----  1 system log  1234 2026-10-20 10:00 console-ramoops-0',
    'exit /b 0',
    ':diag',
    'echo total 191370',
    'echo drwxrws--x  2 root log  3452 1972-05-20 13:59 .',
    'echo -rw-r--r--  1 root log 89160 2026-09-13 11:33:45.683999998 +0700 last_kmsg',
    'echo -rw-r--r--  1 root log 2097196 2026-09-13 11:33:45.515999999 +0700 last_kmsg_7',
    'echo -rw-r--r--  1 root log  4096 2026-09-13 11:33:45.000000000 +0700 diag_other',
    'exit /b 0', ''])


def run(d, mode, out):
    env = dict(os.environ, FAKE_MODE=mode)
    cmd = [pwsh, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(HERE / 'post-run-listing.ps1'),
           '-OutFile', str(out), '-Serial', STANDIN, '-Adb', str(d / 'adb.cmd'), '-TimeoutSeconds', '10']
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


with tempfile.TemporaryDirectory() as td:
    d = Path(td)
    (d / 'adb.cmd').write_bytes(FAKE.encode())
    out = d / 'listing.json'
    r = run(d, 'normal', out)
    assert r.returncode == 0, (r.stdout, r.stderr)
    calls = [c.strip() for c in (d / 'calls.log').read_text().splitlines()]
    assert calls == ['devices', f'-s {STANDIN} shell ls -la /sys/fs/pstore', f'-s {STANDIN} shell ls -la /data/vendor/diag'], calls
    text = out.read_text(encoding='utf-8-sig')
    data = json.loads(text)
    assert STANDIN not in text and data['serial_matched'] is True
    assert data['pstore'] == {'rc': 0, 'entries': [], 'empty': True}, data['pstore']
    names = [e['name'] for e in data['vendor_last_logs']['entries']]
    assert names == ['last_kmsg', 'last_kmsg_7'] and data['vendor_last_logs']['entries'][1]['size'] == 2097196, data
    print('PASS post-run listing: exactly devices + two ls -la listings; metadata only; serial not stored; empty pstore recorded')

    out2 = d / 'listing2.json'
    (d / 'calls.log').unlink()
    r = run(d, 'pstorefile', out2)
    data = json.loads(out2.read_text(encoding='utf-8-sig'))
    assert r.returncode == 0 and data['pstore']['empty'] is False
    assert data['pstore']['entries'] == [{'name': 'console-ramoops-0', 'type': '-', 'size': 1234, 'mtime': '2026-10-20 10:00'}], data
    print('PASS post-run listing: a pstore record is listed by name and size only (its content is never read)')

    for mode, why in (('wrong', 'Wrong adb device'), ('multi', 'Multiple adb devices')):
        o = d / f'listing-{mode}.json'
        r = run(d, mode, o)
        assert r.returncode != 0 and why in r.stdout + r.stderr and not o.exists(), (mode, r.stdout, r.stderr)
    r = run(d, 'normal', out)
    assert r.returncode != 0 and 'never overwrite' in r.stdout + r.stderr
    print('PASS post-run listing refuses a wrong device, several devices and an existing output')

source = (HERE / 'post-run-listing.ps1').read_text()
invocations = re.findall(r'& \$Adb ([^)\n;]*)', source)
assert sorted(invocations) == sorted(['devices', '-s $Serial shell ls -la /sys/fs/pstore', '-s $Serial shell ls -la /data/vendor/diag']), invocations
for bad in ('shell cat', 'shell rm', 'shell dd', 'shell su', 'reboot', ' push ', ' pull ', 'setprop'):
    assert bad not in source, bad
assert 'xiaomi' not in source.lower() and 'platform-tools' not in source.lower()
print('PASS post-run listing source: only the three read-only adb invocations; no write, read of content or tool location')
