# The sole Run21 launcher: the audited Run20 launcher with only the Run21 identities changed. No execution without explicit fresh one-shot approval.
param([Parameter(Mandatory=$true)][string]$Manifest,[Parameter(Mandatory=$true)][string]$OutDir,[switch]$PlanOnly,[switch]$ConfirmOneShot)
$ErrorActionPreference='Stop'
$root=(Resolve-Path "$PSScriptRoot/../../..").Path
$m=Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
if($m.schema -ne 'm11-run21-candidate-v1' -or $m.hardware -ne 'NOT BOOTED'){throw 'Invalid/unapproved identity'}
if($m.local_staging.journal_nonce -notmatch '^[0-9a-f]{32}$' -or $m.local_staging.runtime_identity -notmatch '^[0-9a-f]{64}$'){throw 'Journal nonce/identity absent from the manifest'}
foreach($p in $m.host_source_sha256.PSObject.Properties){
 $file=Join-Path $PSScriptRoot $p.Name
 if((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower() -ne $p.Value){throw "Host source changed: $($p.Name)"}
}
$observer=Join-Path $PSScriptRoot 'host-observer.ps1'
$plan=[ordered]@{observer=$observer;observer_arguments=@('-NoProfile','-File',$observer,'-OutDir',$OutDir,'-Seconds','420','-JournalNonce',$m.local_staging.journal_nonce,'-JournalIdentity',$m.local_staging.runtime_identity);protocol='M11I3';usb_serial='M11R21';boot=$m.local_staging.boot_path;boot_sha256=$m.local_staging.boot_sha256}
if($PlanOnly){$plan | ConvertTo-Json -Depth 6;exit 0}
if(-not $ConfirmOneShot){throw 'Explicit one-shot hardware approval required; no device command sent'}
$canonical=Join-Path $root 'artifacts/m11/hwtest-run21-one-shot'
if([IO.Path]::GetFullPath($OutDir) -ne [IO.Path]::GetFullPath($canonical)){throw 'Only canonical one-shot evidence directory is allowed'}
if(Test-Path -LiteralPath $OutDir){throw 'Run already has evidence; never retry'}
$boot=$plan.boot
if((Get-FileHash -LiteralPath $boot -Algorithm SHA256).Hash.ToLower() -ne $plan.boot_sha256){throw 'Boot SHA mismatch'}
if((Get-Item -LiteralPath $boot).Length -ne $m.local_staging.boot_size){throw 'Boot size mismatch'}
$freeze=(& git -C $root log -1 --format=%H -- manifests/m11-run21-candidate.json).Trim()
if((& git -C $root rev-parse HEAD) -ne $freeze -or (& git -C $root status --short)){throw 'Freeze HEAD/clean tree mismatch'}
$adb='D:\idk.omg\xiaomi\platform-tools\adb.exe';$fastboot='D:\idk.omg\xiaomi\platform-tools\fastboot.exe'
$serial=$m.approved_device_serial
# The approved device serial lives only in the frozen local manifest (never exported).
if($serial -notmatch '^[0-9a-f]{8}$'){throw 'Approved device identity absent or malformed'}
# Start the corrected receiver before boot. It waits for USB outside its read loop.
$receiver=Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-File',('"'+$observer+'"'),'-OutDir',('"'+$OutDir+'"'),'-Seconds','420','-JournalNonce',$m.local_staging.journal_nonce,'-JournalIdentity',$m.local_staging.runtime_identity)
$startup=[DateTime]::UtcNow.AddSeconds(15)
while(-not (Test-Path -LiteralPath $OutDir) -and [DateTime]::UtcNow -lt $startup){if($receiver.HasExited){throw 'Receiver exited before startup'};Start-Sleep -Milliseconds 100}
if(-not (Test-Path -LiteralPath $OutDir) -or $receiver.HasExited){throw 'Receiver startup failed; no phone command sent'}
& $adb -s $serial reboot bootloader
if($LASTEXITCODE -ne 0){throw 'Bootloader transition failed; no candidate boot'}
if(-not (Test-Path -LiteralPath $OutDir)){throw 'Receiver startup absent; no candidate boot'}
$deadline=[DateTime]::UtcNow.AddSeconds(30);$found=$false
while([DateTime]::UtcNow -lt $deadline){
 $lines=@((& $fastboot devices) | Where-Object {$_ -match '\sfastboot$'})
 if($lines.Count -gt 1){throw 'Multiple fastboot devices; STOP'}
 if($lines.Count -eq 1){if(($lines[0] -split '\s+')[0] -ne $serial){throw 'Wrong fastboot device; STOP'};$found=$true;break}
 Start-Sleep -Milliseconds 200
}
if(-not $found){throw 'No fastboot device; no candidate boot'}
if($receiver.HasExited){throw 'Receiver exited; no candidate boot'}
# Consume before issuing exactly one boot, even if transport/output fails.
$consume=Join-Path $OutDir 'one-shot-consumed.json'
[ordered]@{utc=[DateTime]::UtcNow.ToString('o');boot=$boot;receiver_pid=$receiver.Id;never_retry=$true} | ConvertTo-Json | Set-Content -LiteralPath $consume -Encoding utf8
$before=[DateTime]::UtcNow.ToString('o');$output=& $fastboot -s $serial boot $boot 2>&1;$rc=$LASTEXITCODE
[ordered]@{before_utc=$before;after_utc=[DateTime]::UtcNow.ToString('o');output=@($output|ForEach-Object ToString);rc=$rc} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutDir 'fastboot.json') -Encoding utf8
Write-Output "One-shot command returned rc=$rc. Observe physically; no further candidate commands."
