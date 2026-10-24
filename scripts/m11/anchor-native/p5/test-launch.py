"""Execute the actual P5 (Run26) launcher's PlanOnly branch; never invokes a phone tool.
M11_PWSH may name the PowerShell executable (CI: pwsh)."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
HERE = Path(__file__).resolve().parent
pwsh = os.environ.get('M11_PWSH', 'pwsh')
NONCE, IDENTITY = 'a' * 32, 'b' * 64
with tempfile.TemporaryDirectory() as d:
    p = Path(d) / 'manifest.json'
    summary = Path(d) / 'stock-summary.txt'
    summary.write_text('allowed=1 len=10 strict=absent passthrough=absent crc32=00000000\n')
    hosts = {n: hashlib.sha256((HERE / n).read_bytes()).hexdigest()
             for n in ('host-observer.ps1', 'host-reader.ps1', 'receiver.cs', 'check-capture.py', 'launch.ps1')}
    staging = dict(boot_path='never-open.img', boot_sha256='0' * 64, journal_nonce=NONCE, runtime_identity=IDENTITY,
                   stock_summary_path=str(summary), stock_summary_sha256=hashlib.sha256(summary.read_bytes()).hexdigest())
    m = dict(schema='m11-run26-candidate-v1', hardware='NOT BOOTED', host_source_sha256=hosts, local_staging=staging)
    p.write_text(json.dumps(m))
    cmd = [pwsh, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(HERE / 'launch.ps1'),
           '-Manifest', str(p), '-OutDir', str(Path(d) / 'capture'), '-PlanOnly']
    run = subprocess.run(cmd, capture_output=True, text=True); assert run.returncode == 0, run.stderr
    plan = json.loads(run.stdout)
    args = plan['observer_arguments']
    assert Path(plan['observer']).resolve() == (HERE / 'host-observer.ps1').resolve()
    assert args[2] == plan['observer'] and plan['protocol'] == 'M11I3' and plan['usb_serial'] == 'M11R26'
    assert args[args.index('-JournalNonce') + 1] == NONCE and args[args.index('-JournalIdentity') + 1] == IDENTITY
    assert args[args.index('-Seconds') + 1] == '600' and args[args.index('-StockSummary') + 1] == str(summary)
    assert not (Path(d) / 'capture').exists()
    # The actual invocation uses the same observer, window, journal and B3 arguments as the executed plan.
    source = (HERE / 'launch.ps1').read_text()
    live = source[source.index('$receiver=Start-Process'):source.index('& $adb')]
    for needle in ('$observer', "'-Seconds','600'", '-JournalNonce', '-JournalIdentity', '-StockSummary'):
        assert needle in live, needle
    assert 'xiaomi' not in source.lower() and 'platform-tools' not in source.lower()  # tool location never encoded
    assert source.index('$PlanOnly') < source.index('$ConfirmOneShot') < source.index('& $adb')
    for broken in (dict(journal_nonce=''), dict(runtime_identity='X' * 64), dict(stock_summary_sha256=''),
                   dict(stock_summary_path='')):
        m['local_staging'] = dict(staging, **broken); p.write_text(json.dumps(m))
        assert subprocess.run(cmd, capture_output=True, text=True).returncode != 0, broken
    m['local_staging'] = staging
    for bad in (dict(schema='m11-run23-candidate-v1'), dict(schema='m11-run' + '25-candidate-v1'), dict(hardware='BOOTED')):
        p.write_text(json.dumps(dict(m, **bad)))
        assert subprocess.run(cmd, capture_output=True, text=True).returncode != 0, bad
    hosts['host-observer.ps1'] = '0' * 64; p.write_text(json.dumps(m))
    run = subprocess.run(cmd, capture_output=True, text=True); assert run.returncode != 0
    # without -PlanOnly and without -ConfirmOneShot nothing is sent
    hosts['host-observer.ps1'] = hashlib.sha256((HERE / 'host-observer.ps1').read_bytes()).hexdigest(); p.write_text(json.dumps(m))
    run = subprocess.run(cmd[:-1], capture_output=True, text=True)
    assert run.returncode != 0 and 'Explicit one-shot hardware approval required' in run.stderr + run.stdout, run
print('PASS actual P5 launch PlanOnly selects the receive-only M11R26 observer (600 s) with the journal nonce/identity '
      'and the B3 stock summary; missing identity/summary, a wrong schema, host-source drift and a missing approval '
      'are rejected; no tool location encoded; zero phone commands')
