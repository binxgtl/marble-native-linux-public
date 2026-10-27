param([Parameter(Mandatory=$true)][string]$Out)
$ErrorActionPreference='Stop'
Add-Type -Path @("$PSScriptRoot/../native4/Receiver.cs","$PSScriptRoot/PcSmoke.cs")
$nonce='1'*32;$binding='2'*64;$count=0
foreach($fault in @('','wrong-binding','zero-nonce','wrong-tag','trailing','partial','read','ack','overrun')){
 $line="M15PCSMOKE1 $nonce $binding`n";$driverFault=''
 switch($fault){
  'wrong-binding' {$line=$line.Replace($binding,('3'*64))}
  'zero-nonce' {$line=$line.Replace($nonce,('0'*32))}
  'wrong-tag' {$line=$line.Replace('M15PCSMOKE1','M15E1')}
  'trailing' {$line+='x'}
  'partial' {$line=$line.TrimEnd("`n")}
  'read' {$driverFault='read'}
  'ack' {$driverFault='ack'}
  'overrun' {$driverFault='overrun'}
 }
 $t=[M15Offline.FakeTransport]::new([Text.Encoding]::ASCII.GetBytes($line),1,$driverFault)
 $failed=$false
 try{$got=[M15Offline.PcSmoke]::Admit($t,$binding,30000)}catch{$failed=$true}
 if($fault -eq ''){
  if($failed -or $got -ne $nonce -or [Text.Encoding]::ASCII.GetString($t.Ack.ToArray()) -ne "M15PC1 $nonce $binding`n"){throw 'Admission failed'}
 }elseif(!$failed -or $t.Ack.Length -ne 0){throw "Fault accepted: $fault"}
 $count++
}
$tmp=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString()+'.fixture')
try {
 [IO.File]::WriteAllText($tmp,"M15E1 $nonce $binding 6`n")
 [M15Offline.PcSmoke]::VerifyBinding($tmp,$nonce,$binding);$count++
 foreach($bad in @('nonce','binding')){
  $failed=$false
  try{
   if($bad -eq 'nonce'){[M15Offline.PcSmoke]::VerifyBinding($tmp,('3'*32),$binding)}
   else{[M15Offline.PcSmoke]::VerifyBinding($tmp,$nonce,('3'*64))}
  }catch{$failed=$true}
  if(!$failed){throw 'Cross-session capture accepted'};$count++
 }
} finally {Remove-Item -LiteralPath $tmp}
@{cases=$count;pass=$true;hardware=$false;com_open=$false}|ConvertTo-Json|Set-Content $Out
