param([Parameter(Mandatory=$true)][string]$Wire,[Parameter(Mandatory=$true)][string]$Out)
$ErrorActionPreference='Stop'
Add-Type -Path "$PSScriptRoot/Receiver.cs"
[IO.Directory]::CreateDirectory($Out) | Out-Null
$bytes=[IO.File]::ReadAllBytes((Resolve-Path $Wire))
$python=(Get-Command python).Source
$verify=[Func[string,byte[]]]{
 param($path)
 $answer=& $python "$PSScriptRoot/verify_saved.py" $path
 if($LASTEXITCODE -ne 0){throw 'Independent saved-file validation failed'}
 return [Text.Encoding]::ASCII.GetBytes(($answer -join "`n")+"`n")
}
$count=0
foreach($chunk in @(1,3,511,512,1536,65536)){
 $port=[M15Offline.FakeTransport]::new($bytes,$chunk,'')
 $path=Join-Path $Out "valid-$chunk.raw"
 $n=[M15Offline.Receiver]::Capture($port,$path,$verify,30000)
 if($n -ne $bytes.Length -or $port.Ack.Length -eq 0){throw 'Capture mismatch'}
 if((Get-FileHash $path).Hash -ne (Get-FileHash $Wire).Hash){throw 'Raw mismatch'}
 $count++
}
foreach($fault in @('read','pending','overrun','ack')){
 $port=[M15Offline.FakeTransport]::new($bytes,512,$fault);$failed=$false
 try{[M15Offline.Receiver]::Capture($port,(Join-Path $Out "$fault.raw"),$verify,30000)|Out-Null}catch{$failed=$true}
 if(!$failed -or $port.Ack.Length -ne 0){throw "Fault accepted: $fault"};$count++
}
$mutants=@{}
$mutants['delete1536']=[byte[]]($bytes[0..1023]+$bytes[2560..($bytes.Length-1)])
$mutants['partial']=[byte[]]$bytes[0..($bytes.Length-2)]
$mutants['trailing']=[byte[]]($bytes+@(88))
$mutants['header']=[byte[]]$bytes.Clone();$mutants['header'][0]=88
$mutants['digest']=[byte[]]$bytes.Clone();$mutants['digest'][$bytes.Length-2]=103
foreach($name in $mutants.Keys){
 $port=[M15Offline.FakeTransport]::new($mutants[$name],511,'');$failed=$false
 try{[M15Offline.Receiver]::Capture($port,(Join-Path $Out "$name.raw"),$verify,30000)|Out-Null}catch{$failed=$true}
 if(!$failed -or $port.Ack.Length -ne 0){throw "Corruption accepted: $name"};$count++
}
"PASS $count Windows receiver cases; no COM opened; physical delivery UNKNOWN"
