# M17: the single boot of a frozen G3 or later image (docs/m17-g3.md, docs/m17-g4.md). One attempt, no retry, no flash, no slot change.
# Never prints or stores the device serial.
param([Parameter(Mandatory=$true)][string]$Session,[Parameter(Mandatory=$true)][string]$Go,[Parameter(Mandatory=$true)][string]$ManifestPath)
$ErrorActionPreference='Stop'
$root=(Resolve-Path "$PSScriptRoot/../..").Path
$tools='D:/idk.omg/xiaomi/platform-tools'
$adb="$tools/adb.exe";$fb="$tools/fastboot.exe"
function Save-New($path,$value){$b=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 8)+"`n");$f=[IO.File]::Open($path,[IO.FileMode]::CreateNew);try{$f.Write($b);$f.Flush($true)}finally{$f.Dispose()}}
function Count-State($exe,$state){@(& $exe devices 2>$null|Where-Object{$_ -match "^\S+\s+$state$"}).Count}
try{
 Set-Location $root
 if(!$Go.Trim()){throw 'Operator GO text required'}
 if(git status --porcelain -- scripts manifests .github){throw 'Worktree dirty'}
 if($ManifestPath -notmatch '^manifests/m17-g[3-9][a-z]-candidate\.json$'){throw 'Manifest must be a new g3a..g9z candidate'}
 $manifest=Get-Content -LiteralPath $ManifestPath -Raw|ConvertFrom-Json
 if($manifest.status -ne 'FROZEN - NOT BOOTED'){throw 'Manifest is not a frozen live candidate'}
 # post.ps1 -Baseline must have passed in this session: it is the evidence the after-check compares with.
 $baseline=Join-Path $Session 'android-before.json'
 if(!(Test-Path -LiteralPath $baseline -PathType Leaf) -or (Get-Content -LiteralPath $baseline -Raw|ConvertFrom-Json).schema -ne 'marble-m19-android-check-v1'){throw 'No valid Android baseline in this session'}
 $boot=Join-Path $root "$($manifest.local_staging.a)/$($manifest.local_staging.boot_name)"
 if((Get-FileHash $boot -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.local_staging.boot_sha256){throw 'Image hash mismatch'}
 if((Get-Item $boot).Length -ne $manifest.local_staging.boot_bytes){throw 'Image size mismatch'}
 $marker=Join-Path $root "artifacts/m17/$($manifest.label)-candidate/execution-reserved.json"
 if(Test-Path $marker){throw 'Candidate already reserved or consumed; NEVER RETRY'}
 # G3 reports over USB to the PC's receiver; G4 on has no PC link (its manifest names no host).
 if($manifest.one_shot.host -and !(Test-Path "$Session/host-ready.json")){throw 'Host receiver is not waiting'}
 Save-New "$Session/authorization.json" @{utc=[DateTime]::UtcNow.ToString('o');operator_instruction=$Go;ephemeral_boot_only=$true;attempt_limit=1;flash=$false;boot_sha256=$manifest.local_staging.boot_sha256}
 if((Count-State $fb 'fastboot') -eq 0){
  if((Count-State $adb 'device') -ne 1){throw 'Expected one authorized Android device'}
  # A clean reboot, so userdata is unmounted cleanly before the run reads it.
  $out=@(& $adb reboot bootloader 2>&1);$rc=$LASTEXITCODE
  Save-New "$Session/reboot-bootloader.json" @{utc=[DateTime]::UtcNow.ToString('o');rc=$rc}
  if($rc -ne 0){throw 'ADB reboot bootloader failed'}
  $until=[DateTime]::UtcNow.AddSeconds(60)
  do{if((Count-State $fb 'fastboot') -gt 0){break};Start-Sleep -Milliseconds 300}while([DateTime]::UtcNow -lt $until)
 }
 if((Count-State $fb 'fastboot') -ne 1){throw 'Expected exactly one fastboot device'}
 Save-New $marker @{utc=[DateTime]::UtcNow.ToString('o');session=$Session;attempt_reserved=$true;no_retry=$true;boot_sha256=$manifest.local_staging.boot_sha256}
 $before=[DateTime]::UtcNow.ToString('o')
 # THE ONLY BOOT INVOCATION. Never retried, even if its output or rc is incomplete.
 $out=@(& $fb boot $boot 2>&1);$rc=$LASTEXITCODE
 Save-New "$Session/fastboot-boot.json" @{before_utc=$before;after_utc=[DateTime]::UtcNow.ToString('o');rc=$rc;candidate_consumed=$true;retry=$false}
 "$($manifest.label) one-shot fastboot completed rc=$rc before_utc=$before"
 exit $rc
}catch{
 Save-New "$Session/launcher.failure.json" @{utc=[DateTime]::UtcNow.ToString('o');error=$_.Exception.ToString();retry=$false}
 Write-Error -ErrorRecord $_ -ErrorAction Continue
 exit 1
}
