#Reference: https://community.spiceworks.com/topic/1994651-check-for-missing-wannacry-patches-with-powershell

#List of patches that remediate WannaCry
$patches = "KB4012212", "KB4012217", "KB4015551", "KB4019216", "KB4012216", "KB4015550", "KB4019215", "KB4013429", "KB4019472", "KB4015217", "KB4015438", "KB4016635", "KB4019213", "KB4019217", "KB4019264"
$computer = $ENV:COMPUTERNAME

#Detect if any of the patches are updated already
$patch = Get-HotFix -ComputerName $computer |
  Where-Object {$patches -contains $_.HotfixID} |
  Select-Object -property "HotFixID"

#Output vulnerability fact about this machine
if($patch) {
  Write-Output "wannacry_vulnerable=false"
} else {
  Write-Output "wannacry_vulnerable=true"
}
