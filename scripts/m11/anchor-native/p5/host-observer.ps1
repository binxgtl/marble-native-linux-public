param([Parameter(Mandatory=$true)][string]$OutDir,[ValidateRange(1,900)][int]$Seconds=600,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{32}$')][string]$JournalNonce,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{64}$')][string]$JournalIdentity,
 [Parameter(Mandatory=$true)][string]$StockSummary)
# P5 (Run26 speaker candidate) receive-only observer: p4/host-observer.ps1 (the Run23 observer) with the
# M11R26 USB identity, the 600 s default window and the P5 host check, which also compares the cmdline
# verdict and tokens with the local stock summary (B3). Never writes to the device.
$ErrorActionPreference='Stop'
. "$PSScriptRoot/host-reader.ps1"
if(-not (Test-Path -LiteralPath $StockSummary -PathType Leaf)){throw 'Stock cmdline summary (B3) absent'}
if(Test-Path -LiteralPath $OutDir){throw 'Capture directory already exists'}
New-Item -ItemType Directory -Path $OutDir | Out-Null
$until=[DateTime]::UtcNow.AddSeconds($Seconds)
$port=$null;$raw=$null;$source=$null
$status=[ordered]@{receiver='p5-continuous-binary-v2';start_utc=[DateTime]::UtcNow.ToString('o');errors=@();shutdown_clean=$false;flush_clean=$false;complete=$false}
try {
 while([DateTime]::UtcNow -lt $until -and $null -eq $port){
  $devices=@(Get-PnpDevice -PresentOnly)
  $parent=@($devices | Where-Object InstanceId -eq 'USB\VID_1D6B&PID_0104\M11R26')
  $acm=@($devices | Where-Object {$_.InstanceId -like 'USB\VID_1D6B&PID_0104&MI_00*' -and $_.FriendlyName -match '\(COM[0-9]+\)'})
  if($parent.Count -gt 1 -or $acm.Count -gt 1){throw 'Ambiguous USB identity'}
  if($parent.Count -ne 1 -or $acm.Count -ne 1){Start-Sleep -Milliseconds 100;continue}
  # Require ACM child to belong to this exact composite device, not another USB.
  $actualParent=(Get-PnpDeviceProperty -InstanceId $acm[0].InstanceId -KeyName 'DEVPKEY_Device_Parent').Data
  if($actualParent -ne $parent[0].InstanceId){throw 'ACM parent identity mismatch'}
  if($acm[0].FriendlyName -notmatch '\((COM[0-9]+)\)'){throw 'Invalid COM name'}
  $status.port=$Matches[1];$port=[IO.Ports.SerialPort]::new($status.port,115200,'None',8,'One')
  $port.ReadBufferSize=1048576;$port.ReadTimeout=200;$port.Handshake='None';$port.DiscardNull=$false;$port.DtrEnable=$true;$port.RtsEnable=$true
  $source=[M11Integrity.SerialSource]::new($port);$port.Open();$status.open_utc=[DateTime]::UtcNow.ToString('o')
  $status.requested_read_buffer=$port.ReadBufferSize
 }
 if($null -eq $port){throw 'Discovery deadline'}
 $raw=[IO.FileStream]::new((Join-Path $OutDir 'acm-raw.bin'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,1048576)
 $remaining=[int][Math]::Max(0,($until-[DateTime]::UtcNow).TotalMilliseconds)
 $status.receipt=Receive-M11SealedRaw -Source $source -Raw $raw -Milliseconds $remaining
 $status.flush_clean=$status.receipt.FlushClean
} catch {$status.failure=$_.Exception.GetBaseException().Message}
finally {
 try {if($null -ne $raw){$raw.Flush($true);$raw.Dispose()}} catch {$status.failure='raw close/flush: '+$_.Exception.Message;$status.flush_clean=$false}
 try {if($null -ne $port){$port.Dispose()};$status.shutdown_clean=$true} catch {$status.failure='serial close: '+$_.Exception.Message}
 if($null -ne $source){$status.errors=@($source.Errors());$source.Detach()}
 $status.end_utc=[DateTime]::UtcNow.ToString('o')
 $path=Join-Path $OutDir 'acm-raw.bin'
 if(Test-Path -LiteralPath $path){$status.raw_sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower();$status.raw_bytes=(Get-Item -LiteralPath $path).Length}
 $status | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutDir 'receiver.json') -Encoding utf8
}
# The P5 check runs even on an incomplete capture: its report then carries only the diagnostic
# classification, never a PASS.
& python "$PSScriptRoot/check-capture.py" (Join-Path $OutDir 'acm-raw.bin') --receipt (Join-Path $OutDir 'receiver.json') --out (Join-Path $OutDir 'decoded') --journal-nonce $JournalNonce --journal-identity $JournalIdentity --stock-summary $StockSummary
$checked=$LASTEXITCODE
if($status.Contains('failure')){throw $status.failure}
if($checked -ne 0){throw 'Strict sender/receiver evidence incomplete or not the expected P5 shape'}
$status.complete=$true
$status | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutDir 'receiver.json') -Encoding utf8
