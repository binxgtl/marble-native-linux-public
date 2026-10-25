"""Canonical private-file structure. Real network values never enter this module."""
import re
PATTERN=(rb'ctrl_interface=DIR=/run/m12/wpa GROUP=0\nap_scan=1\nnetwork=\{\n'
         rb'ssid=(?:[0-9a-f]{2}){1,32}\npsk=[0-9a-f]{64}\nkey_mgmt=WPA-PSK\n'
         rb'scan_ssid=0\ndisabled=1\n\}\n')
def valid(data):return re.fullmatch(PATTERN,data) is not None
def fixture(length=1):
    assert 1<=length<=32
    return (b'ctrl_interface=DIR=/run/m12/wpa GROUP=0\nap_scan=1\nnetwork={\nssid='+b'00'*length+
            b'\npsk='+b'0'*64+b'\nkey_mgmt=WPA-PSK\nscan_ssid=0\ndisabled=1\n}\n')
