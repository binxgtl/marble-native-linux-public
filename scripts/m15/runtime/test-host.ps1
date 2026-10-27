param([Parameter(Mandatory=$true)][string]$Out)
$ErrorActionPreference='Stop'
Add-Type -Path @("$PSScriptRoot/../native4/Receiver.cs","$PSScriptRoot/NativeHost.cs")
$nonce='1'*32;$binding='2'*64;$count=0
foreach($tag in @('M15NATIVE1','M15RETURN1')){
 foreach($fault in @('','binding','nonce','partial','overrun','ack','experiment')){
  $line="$tag $nonce $binding pc-wall-pc`n";$f=''
  if($fault -eq 'experiment'){$line=$line.Replace('pc-wall-pc','pc-admission-only')}
  if($fault -eq 'binding'){$line=$line.Replace($binding,('3'*64))}
  if($fault -eq 'nonce'){$line=$line.Replace($nonce,('0'*32))}
  if($fault -eq 'partial'){$line=$line.TrimEnd("`n")}
  if($fault -in @('overrun','ack')){$f=$fault}
  $t=[M15Offline.FakeTransport]::new([Text.Encoding]::ASCII.GetBytes($line),1,$f);$bad=$false
  try{[M15Offline.NativeHost]::Admit($t,$binding,$nonce,($tag -eq 'M15RETURN1'),'pc-wall-pc')|Out-Null}catch{$bad=$true}
  if($bad -ne ($fault -ne '') -or ($bad -and $t.Ack.Length -ne 0)){throw "Admission $tag $fault"};$count++
 }
}
$ack="M15ACK1 $nonce $binding $binding`n"
foreach($fault in @('','binding','partial','overrun')){
 $line='M15DONE1 '+$ack.Substring(8);$f=''
 if($fault -eq 'binding'){$line=$line.Replace($binding,('3'*64))}
 if($fault -eq 'partial'){$line=$line.TrimEnd("`n")}
 if($fault -eq 'overrun'){$f='overrun'}
 $t=[M15Offline.FakeTransport]::new([Text.Encoding]::ASCII.GetBytes($line),1,$f);$bad=$false
 $path=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString()+'.receipt')
 try{[M15Offline.NativeHost]::Terminal($t,$ack,$path)}catch{$bad=$true}
 if($bad -ne ($fault -ne '') -or ((Test-Path $path) -eq $bad)){throw "Terminal $fault"}
 if(Test-Path $path){Remove-Item -LiteralPath $path};$count++
}
@{cases=$count;pass=$true;com_open=$false;hardware=$false}|ConvertTo-Json|Set-Content $Out
