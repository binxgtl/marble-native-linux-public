param([Parameter(Mandatory=$true)][string]$Wire,[Parameter(Mandatory=$true)][string]$Terminal,[Parameter(Mandatory=$true)][string]$Out)
$ErrorActionPreference='Stop'
Add-Type -Path @("$PSScriptRoot/../native4/Receiver.cs","$PSScriptRoot/../native6/PcSmoke.cs","$PSScriptRoot/NativeHost.cs")
[IO.Directory]::CreateDirectory($Out)|Out-Null
$bytes=[IO.File]::ReadAllBytes((Resolve-Path $Wire))
$first=[Array]::IndexOf($bytes,[byte]10)
if($first -lt 0 -or $first -gt 200){throw 'Fixture header'}
$header=[Text.Encoding]::ASCII.GetString($bytes,0,$first).Split(' ')
$nonce=$header[1];$binding=$header[2];$python=(Get-Command python).Source
$script:expectedAck=''
$verify=[Func[string,byte[]]]{
 param($path)
 [M15Offline.PcSmoke]::VerifyBinding($path,$nonce,$binding)
 # This explicit fixture admission exists only in offline tests. Production
 # host.ps1 invokes verify.py without allow_fixture and rejects these bytes.
 $answer=& $python -c 'import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import verify;sys.stdout.buffer.write(verify.verify(Path(sys.argv[2]),allow_fixture=True))' $PSScriptRoot $path
 if($LASTEXITCODE -ne 0){throw 'Native fixture replay failed'}
 $script:expectedAck=($answer -join "`n")+"`n"
 return [Text.Encoding]::ASCII.GetBytes($script:expectedAck)
}
$count=0
foreach($chunk in @(1,512,1536,65536)){
 $t=[M15Offline.FakeTransport]::new($bytes,$chunk,'');$raw=Join-Path $Out "native-$chunk.raw"
 $n=[M15Offline.Receiver]::Capture($t,$raw,$verify,30000)
 if($n -ne $bytes.Length -or (Get-FileHash $raw).Hash -ne (Get-FileHash $Wire).Hash){throw 'Native saved bytes'}
 $done=[M15Offline.FakeTransport]::new([IO.File]::ReadAllBytes((Resolve-Path $Terminal)),1,'')
 [M15Offline.NativeHost]::Terminal($done,$script:expectedAck,($raw+'.terminal.txt'));$count++
}
$mutants=@{}
$mutants['delete1536']=[byte[]]($bytes[0..1023]+$bytes[2560..($bytes.Length-1)])
$mutants['partial']=[byte[]]$bytes[0..($bytes.Length-2)]
$mutants['trailing']=[byte[]]($bytes+@(88))
$mutants['header']=[byte[]]$bytes.Clone();$mutants['header'][0]=88
$mutants['digest']=[byte[]]$bytes.Clone();$mutants['digest'][$bytes.Length-2]=103
foreach($name in $mutants.Keys){
 $t=[M15Offline.FakeTransport]::new($mutants[$name],511,'');$bad=$false
 try{[M15Offline.Receiver]::Capture($t,(Join-Path $Out "$name.raw"),$verify,30000)|Out-Null}catch{$bad=$true}
 if(!$bad -or $t.Ack.Length -ne 0){throw "Native corruption accepted: $name"};$count++
}
& $python "$PSScriptRoot/verify.py" $Wire
if($LASTEXITCODE -eq 0){throw 'Synthetic runtime capture promoted to native'};$count++
@{cases=$count;pass=$true;actual_c_stream=$true;com_open=$false;hardware=$false}|ConvertTo-Json|Set-Content (Join-Path $Out 'native-receiver-tests.json')
# The deliberately rejected production replay left LASTEXITCODE=1. All assertions
# above must pass before clearing that expected native-process status for CI.
exit 0
