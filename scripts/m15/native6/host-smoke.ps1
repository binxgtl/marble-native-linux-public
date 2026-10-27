param([Parameter(Mandatory=$true)][string]$Port,
      [Parameter(Mandatory=$true)][string]$ExpectedBinding,
      [Parameter(Mandatory=$true)][string]$Raw)
# Explicit execution opens the named COM device. Do NOT invoke during offline CI.
$ErrorActionPreference='Stop'
Add-Type -Path @("$PSScriptRoot/../native4/Receiver.cs","$PSScriptRoot/../native4/ComAdapter.cs","$PSScriptRoot/../native5/Win32Com.cs","$PSScriptRoot/PcSmoke.cs")
$python=(Get-Command python).Source
$verify=[Func[string,byte[]]]{
 param($path)
 [M15Offline.PcSmoke]::VerifyBinding($path,$nonce,$ExpectedBinding)
 $answer=& $python "$PSScriptRoot/../native4/verify_saved.py" $path
 if($LASTEXITCODE -ne 0){throw 'Saved-file verification failed; no ACK'}
 return [Text.Encoding]::ASCII.GetBytes(($answer -join "`n")+"`n")
}
if(Test-Path -LiteralPath $Raw){throw 'Refuse existing raw evidence'}
$portHandle=$null
try {
 $portHandle=[M15Offline.WindowsIo]::Open($Port,110000,100000)
 $nonce=[M15Offline.PcSmoke]::Admit($portHandle,$ExpectedBinding,120000)
 $bytes=[M15Offline.Receiver]::Capture($portHandle,$Raw,$verify,180000)
 "PC-smoke saved-file verified: $bytes bytes; ACK submitted; sender receipt UNKNOWN; retain RAM"
} catch {
 # No raw deletion, reconnect, retry or device cleanup.
 throw
} finally {
 if($null -ne $portHandle){$portHandle.Dispose()}
}
