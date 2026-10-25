# Read-only post-run listing for Run31 (p4/post-run-listing.ps1, the Run25 listing; docs/m11-argon-run31-plan.md).
# Run it only after the one-shot candidate returned to Android, next to the reset oracle. Device
# commands, exactly: `adb devices`, `adb -s <serial> shell ls -la /sys/fs/pstore` and
# `adb -s <serial> shell ls -la /data/vendor/diag`. Nothing is read beyond these listings, and
# nothing is written, cleared or deleted on the phone. Only names, sizes and mtimes are stored; the
# serial is never stored (output or this file), and the tool location is given by the operator.
param([Parameter(Mandatory=$true)][string]$OutFile,[Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{8}$')][string]$Serial,
 [Parameter(Mandatory=$true)][string]$Adb,[ValidateRange(10,900)][int]$TimeoutSeconds=300)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutFile){throw 'Listing output already exists; never overwrite'}
if(-not (Test-Path -LiteralPath $Adb -PathType Leaf)){throw 'adb not found at the operator-given path'}
$deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds);$ready=$false
while([DateTime]::UtcNow -lt $deadline){
 $lines=@((& $Adb devices) | Where-Object {$_ -match '\sdevice$'})
 if($lines.Count -gt 1){throw 'Multiple adb devices; STOP'}
 if($lines.Count -eq 1){if(($lines[0] -split '\s+')[0] -ne $Serial){throw 'Wrong adb device; STOP'};$ready=$true;break}
 Start-Sleep -Seconds 2
}
if(-not $ready){throw 'Android did not return within the timeout; record the physical state and classify only'}
# One `ls -la` line -> name, size, mtime (metadata only; '.' and '..' dropped).
function Parse-Listing([string[]]$text){
 $out=@()
 foreach($l in $text){
  if($l -match '^([-dlcbps][-rwxsStT]{9})\S*\s+\d+\s+\S+\s+\S+\s+(\d+)\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?: [+-]\d{4})?)\s+(.+)$'){
   $name=$Matches[4].Trim()
   if($name -in @('.','..')){continue}
   $out+=[ordered]@{name=$name;type=$Matches[1].Substring(0,1);size=[long]$Matches[2];mtime=$Matches[3]}
  }
 }
 ,$out
}
$utc=[DateTime]::UtcNow.ToString('o')
$pstoreText=@(& $Adb -s $Serial shell ls -la /sys/fs/pstore);$pstoreRc=$LASTEXITCODE
$diagText=@(& $Adb -s $Serial shell ls -la /data/vendor/diag);$diagRc=$LASTEXITCODE
$pstore=Parse-Listing $pstoreText
$diag=@((Parse-Listing $diagText) | Where-Object {$_.name -like 'last_*'})
[ordered]@{utc=$utc;serial_matched=$true;
 pstore=[ordered]@{rc=$pstoreRc;entries=$pstore;empty=($pstoreRc -eq 0 -and $pstore.Count -eq 0)};
 vendor_last_logs=[ordered]@{rc=$diagRc;entries=$diag};
 meaning='Metadata only. An empty pstore is expected (pstore review) and never evidence that no panic happened or that RAM was cleared; any pstore content is copied separately and stays local. The vendor last_* files come from mtdoops, which a native boot does not load: a negative control, not evidence of the native boot.'} |
 ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding utf8
Write-Output "pstore rc=$pstoreRc entries=$($pstore.Count); vendor last_* entries=$($diag.Count)"
