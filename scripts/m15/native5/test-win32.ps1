# SPDX-License-Identifier: GPL-2.0-only
param([Parameter(Mandatory=$true)][string]$Out)
$ErrorActionPreference='Stop'
Add-Type -Path "$PSScriptRoot/../native4/Receiver.cs","$PSScriptRoot/../native4/ComAdapter.cs","$PSScriptRoot/Win32Com.cs","$PSScriptRoot/test-win32.cs"
$n=[M15Offline.NativeIoTests]::Run()
$result=@{schema='M15-Win32-binding-fake-v1';tests=$n;result='PASS';device_opened=$false;usbser_qualified=$false;control_permitted=$false}
$parent=Split-Path -Parent $Out
if ($parent) {New-Item -ItemType Directory -Force $parent | Out-Null}
$result | ConvertTo-Json | Set-Content -Encoding utf8 $Out
$result | ConvertTo-Json
