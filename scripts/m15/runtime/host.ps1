param([Parameter(Mandatory=$true)][ValidateSet('admit','export')][string]$Phase,
 [Parameter(Mandatory=$true)][string]$Port,
 [Parameter(Mandatory=$true)][string]$Metadata,
 [Parameter(Mandatory=$true)][string]$Admission,
 [string]$Raw)
# Actual named COM entry. Offline tests never call WindowsIo.Open.
$ErrorActionPreference='Stop'
Add-Type -Path @("$PSScriptRoot/../native4/Receiver.cs","$PSScriptRoot/../native4/ComAdapter.cs","$PSScriptRoot/../native5/Win32Com.cs","$PSScriptRoot/../native6/PcSmoke.cs","$PSScriptRoot/NativeHost.cs")
$python=(Get-Command python).Source
& $python -c 'import sys,json;sys.path.insert(0,sys.argv[1]);from provenance import validate;validate(json.load(open(sys.argv[2],encoding="utf-8")))' $PSScriptRoot $Metadata
if($LASTEXITCODE -ne 0){throw 'Native metadata invalid'}
$binding=(Get-FileHash -LiteralPath $Metadata -Algorithm SHA256).Hash.ToLowerInvariant()
$nonce='';$expectedAck='';$handle=$null
if($Phase -eq 'export'){
 $prior=Get-Content -LiteralPath $Admission -Raw | ConvertFrom-Json
 if($prior.schema -ne 'M15-native-admission-v1' -or $prior.binding -ne $binding){throw 'Admission session mismatch'}
 $nonce=$prior.nonce
 if(!$Raw -or (Test-Path -LiteralPath $Raw)){throw 'New raw path required'}
} elseif(Test-Path -LiteralPath $Admission){throw 'Admission already exists; no automatic retry'}
try {
 $handle=[M15Offline.WindowsIo]::Open($Port,110000,100000)
 $nonce=[M15Offline.NativeHost]::Admit($handle,$binding,$nonce,($Phase -eq 'export'))
 if($Phase -eq 'admit'){
  $receipt=@{schema='M15-native-admission-v1';nonce=$nonce;binding=$binding;charger_identity='operator-reported';control_permitted=$false}|ConvertTo-Json -Compress
  [M15Offline.NativeHost]::Save($Admission,[Text.Encoding]::UTF8.GetBytes($receipt+"`n"))
  'Admission submitted. Disconnect PC only after continuous BLUE; follow separately approved runbook.'
 } else {
  $verify=[Func[string,byte[]]]{
   param($path)
   [M15Offline.PcSmoke]::VerifyBinding($path,$nonce,$binding)
   $answer=& $python "$PSScriptRoot/verify.py" $path
   if($LASTEXITCODE -ne 0){throw 'Native saved-file verification failed'}
   $script:expectedAck=($answer -join "`n")+"`n"
   return [Text.Encoding]::ASCII.GetBytes($script:expectedAck)
  }
  $bytes=[M15Offline.Receiver]::Capture($handle,$Raw,$verify,180000)
  [M15Offline.NativeHost]::Terminal($handle,$script:expectedAck,($Raw+'.terminal.txt'))
  "Saved $bytes exact bytes; bound sender terminal receipt received. Device safety UNKNOWN; recovery requires approved plan."
 }
} finally {if($null -ne $handle){$handle.Dispose()}}
