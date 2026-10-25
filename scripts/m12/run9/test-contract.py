import subprocess,sys,tempfile
from pathlib import Path
from wpa_contract import valid,fixture
with tempfile.TemporaryDirectory(prefix='m12-contract-') as d:
    p=Path(d)/'synthetic'
    count=0
    for length in range(1,33):
        good=fixture(length)
        data=[(good,True),(b'update_config=0\n'+good,False),(b'update_config=1\n'+good,False),
              (good.replace(b'\n',b'\r\n'),False),(good.replace(b'disabled=1\n',b''),False),
              (good.replace(b'key_mgmt=WPA-PSK',b'key_mgmt=NONE'),False),
              (good.replace(b'ssid=',b'ssid="',1),False),(good+b'unknown=0\n',False)]
        for value,expected in data:
            assert valid(value)==expected
            p.write_bytes(value)
            r=subprocess.run([sys.argv[1],str(p)],timeout=5)
            assert (r.returncode==0)==expected,(length,expected,r.returncode)
            count+=1
print(f'Canonical staging contract and actual C parser: {count} synthetic positive/rejection cases PASS; no private values')
