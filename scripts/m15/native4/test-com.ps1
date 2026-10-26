param([Parameter(Mandatory=$true)][string]$Out)
$ErrorActionPreference='Stop'
Add-Type -Path @("$PSScriptRoot/Receiver.cs","$PSScriptRoot/ComAdapter.cs")
$count=[M15Offline.ComTests]::Run()
$report=[ordered]@{schema='M15-COM-offline-lifecycle-v1';tests=$count;result='PASS';real_com_opened=$false;native_win32_binding='NOT_IMPLEMENTED';usbser_qualified=$false;control_permitted=$false;runtime=[Environment]::Version.ToString()}
$json=$report|ConvertTo-Json
[IO.File]::WriteAllText($Out,$json)
$json
