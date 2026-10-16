# Import defines binary receiver only; never opens a device.
if(-not ('M11Integrity.Reader' -as [type])){
 Add-Type -Path "$PSScriptRoot/receiver.cs" -ReferencedAssemblies @((Get-ChildItem "$PSHOME/ref/*.dll").FullName + [IO.Ports.SerialPort].Assembly.Location)
}
function Receive-M11SealedRaw {
 param([M11Integrity.Source]$Source,[IO.Stream]$Raw,[int]$Milliseconds=420000,[long]$MaxBytes=67108864)
 [M11Integrity.Reader]::Receive($Source,$Raw,$Milliseconds,$MaxBytes)
}
