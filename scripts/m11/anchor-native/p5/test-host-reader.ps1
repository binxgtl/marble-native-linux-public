# P5 (Run26): p4/test-host-reader.ps1 (the Run23 receiver test) over a synthetic P5 capture, with the M11R26 observer identity.
param([Parameter(Mandatory=$true)][string]$Fixture)
$ErrorActionPreference='Stop'
Add-Type -Path @("$PSScriptRoot/receiver.cs","$PSScriptRoot/test-receiver.cs") -ReferencedAssemblies @((Get-ChildItem "$PSHOME/ref/*.dll").FullName + [IO.Ports.SerialPort].Assembly.Location)
. "$PSScriptRoot/host-reader.ps1"
$port=[IO.Ports.SerialPort]::new()
$serialSource=[M11Integrity.SerialSource]::new($port)
foreach($kind in @([IO.Ports.SerialError]::RXOver,[IO.Ports.SerialError]::Frame)){
 $event=[Activator]::CreateInstance([IO.Ports.SerialErrorReceivedEventArgs],[Reflection.BindingFlags]'Instance,NonPublic',$null,@($kind),$null)
 $handler=[M11Integrity.SerialSource].GetMethod('OnError',[Reflection.BindingFlags]'Instance,NonPublic')
 $handler.Invoke($serialSource,@($port,$event)) | Out-Null
}
if(($serialSource.Errors() -join ',') -ne 'RXOver,Frame'){throw 'Direct serial error handler lost errors'}
$serialSource.Detach();$port.Dispose()
Write-Output 'PASS actual SerialSource callback records RXOver and Frame; no serial open'

function Assert($b,$m){if(-not $b){throw $m}}
$data=[IO.File]::ReadAllBytes((Resolve-Path $Fixture))
foreach($width in @(1,7,511,512,513,8191,65536)){
 $s=[FixtureSource]::new();$s.Data=$data;$s.Width=$width;$s.TimeoutOnce=$true;$raw=[TestSink]::new()
 $r=Receive-M11SealedRaw $s $raw 30000
 Assert ($r.Reason -eq 'terminal-frame' -and $r.Bytes -eq $data.Length -and $r.FlushClean) "partition $width receipt"
 Assert ([Convert]::ToBase64String($raw.ToArray()) -eq [Convert]::ToBase64String($data)) "partition $width raw mismatch"
 $raw.Dispose();Write-Output "PASS partition $width"
}
foreach($fault in @('disconnect','timeout','bad-count','RXOver','Frame','short-write','backpressure','flush','partial-final','missing-final')){
 $s=[FixtureSource]::new();$s.Data=$data;$s.Fault=$fault;$s.FaultAt=1000;$s.Width=1024
 if($fault -eq 'partial-final'){$s.FaultAt=-1;$s.Data=$data[0..($data.Length-2)]}
 if($fault -eq 'missing-final'){$s.FaultAt=-1;$s.Data=$data[0..900]}
 $raw=[TestSink]::new();$raw.Fault=$fault
 $budget=if($fault -eq 'backpressure'){$s.Width=65536;30000}else{2000}
 $r=Receive-M11SealedRaw $s $raw $budget
 $expected=switch($fault){'disconnect'{'read-error'} 'timeout'{'deadline'} 'bad-count'{'invalid-read-count'} 'RXOver'{'serial-error'} 'Frame'{'serial-error'} 'short-write'{'raw-write-error'} 'backpressure'{'terminal-frame'} 'flush'{'flush-error'} default{'unexpected-eof'}}
 Assert ($r.Reason -eq $expected) "$fault expected $expected got $($r.Reason)"
 if($fault -eq 'backpressure'){Assert ($r.Bytes -eq $data.Length) 'backpressure dropped bytes'}
 $raw.Dispose();Write-Output "PASS receiver $fault"
}
# Reader/observer syntax and hot-path constraints are supplementary to execution.
foreach($f in @('host-reader.ps1','host-observer.ps1','launch.ps1')){
 $t=$null;$e=$null;[Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot/$f",[ref]$t,[ref]$e)|Out-Null
 Assert ($e.Count -eq 0) "$f syntax"
}
$observer=[IO.File]::ReadAllText("$PSScriptRoot/host-observer.ps1")
Assert ($observer.Contains('USB\VID_1D6B&PID_0104\M11R26') -and -not $observer.Contains('M11R2' + '5') -and -not $observer.Contains('M11R23') -and -not $observer.Contains('M11R20')) 'observer parent identity must be M11R26 only'
Assert ($observer.Contains('--journal-nonce $JournalNonce') -and $observer.Contains('--journal-identity $JournalIdentity') -and $observer.Contains('--stock-summary $StockSummary')) 'observer must pass the journal identity and the B3 stock summary to the P5 check'
$receiverSource=[IO.File]::ReadAllText("$PSScriptRoot/receiver.cs")
Assert (-not ($receiverSource -match 'port\.Write|BaseStream|WriteLine|M11R20')) 'receiver must be receive-only (no ACK/serial write)'
Write-Output 'PASS observer M11R26 identity + journal and B3 arguments, receive-only receiver'
Write-Output 'PASS Windows receiver binary integrity, clean terminal, buffering, explicit errors; no COM opened'
