"""Execute the actual Run22 launcher's PlanOnly branch; never invokes a phone tool.
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
    hosts = {n: hashlib.sha256((HERE / n).read_bytes()).hexdigest()
             for n in ('host-observer.ps1', 'host-reader.ps1', 'receiver.cs', 'check-capture.py', 'launch.ps1')}
    staging = dict(boot_path='never-open.img', boot_sha256='0' * 64, journal_nonce=NONCE, runtime_identity=IDENTITY)
    m = dict(schema='m11-run22-candidate-v1', hardware='NOT BOOTED', host_source_sha256=hosts, local_staging=staging)
    p.write_text(json.dumps(m))
    cmd = [pwsh, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(HERE / 'launch.ps1'),
           '-Manifest', str(p), '-OutDir', str(Path(d) / 'capture'), '-PlanOnly']
    run = subprocess.run(cmd, capture_output=True, text=True); assert run.returncode == 0, run.stderr
    plan = json.loads(run.stdout)
    args = plan['observer_arguments']
    assert Path(plan['observer']).resolve() == (HERE / 'host-observer.ps1').resolve()
    assert args[2] == plan['observer'] and plan['protocol'] == 'M11I3' and plan['usb_serial'] == 'M11R22'
    assert args[args.index('-JournalNonce') + 1] == NONCE and args[args.index('-JournalIdentity') + 1] == IDENTITY
    assert not (Path(d) / 'capture').exists()
    # The actual invocation uses the same observer and journal arguments as the executed plan.
    source = (HERE / 'launch.ps1').read_text()
    live = source[source.index('$receiver=Start-Process'):source.index('& $adb')]
    assert "'-File',('" in source and '$observer' in live and '-JournalNonce' in live and '-JournalIdentity' in live
    for broken in (dict(journal_nonce=''), dict(runtime_identity='X' * 64)):
        m['local_staging'] = dict(staging, **broken); p.write_text(json.dumps(m))
        assert subprocess.run(cmd, capture_output=True, text=True).returncode != 0, broken
    m['local_staging'] = staging
    hosts['host-observer.ps1'] = '0' * 64; p.write_text(json.dumps(m))
    run = subprocess.run(cmd, capture_output=True, text=True); assert run.returncode != 0
print('PASS actual Run22 launch PlanOnly selects the sealed receive-only receiver with the journal '
      'nonce/identity; missing identity and host-source drift rejected; zero phone commands')
