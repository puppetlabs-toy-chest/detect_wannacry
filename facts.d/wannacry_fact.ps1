#Reference: https://community.spiceworks.com/topic/1994651-check-for-missing-wannacry-patches-with-powershell

#List of patches that remediate WannaCry
$patches = "KB4013429","KB4012606","KB4013198","KB4012598","KB4012598","KB4012598","KB4012598","KB4012598","KB4012212","KB4012215","KB4012212","KB4012215","KB4012213","KB4012216","KB4012214","KB4012217","KB4012213","KB4012216","KB4012606","KB4013198","KB4013429","KB4013429","KB4016871", "KB4019472", "KB4019213", "KB4019217", "KB4019264" 
$computer = $ENV:COMPUTERNAME

# From https://bogner.sh/2017/05/how-to-check-if-ms17-010-has-already-been-installed/
#
# Windows 2008's Get-HotFix may not display all installed HotFixes, so a second method is required
# to collect installed HotFixes
$wu = new-object -com “Microsoft.Update.Searcher”

$totalupdates = $wu.GetTotalHistoryCount()
if ($totalupdates -ne 0) {
  $all = $wu.QueryHistory(0,$totalupdates)
}

# Define a new array to gather output
$UpdateCollection= @()

Foreach ($update in $all)
{
  $string = $update.title

  $Regex = “KB\d*”
  $KB = $string | Select-String -Pattern $regex | Select-Object { $_.Matches }

  $output = New-Object -TypeName PSobject
  $output | add-member NoteProperty “HotFixID” -value $KB.‘ $_.Matches ‘.Value
  $output | add-member NoteProperty “Title” -value $string
  $UpdateCollection += $output
}

Foreach ($hotfix in Get-Hotfix) {
  $output = New-Object -TypeName PSobject
  $output | add-member NoteProperty “HotFixID” -value $hotfix.HotFixID
  $output | add-member NoteProperty “Title” -value $hotfix.Description
  $UpdateCollection += $output 
}

#Detect if any of the patches are updated already
$patch = $UpdateCollection |
  Where-Object {$patches -contains $_.HotfixID} |
  Select-Object -property "HotFixID"

#Output vulnerability fact about this machine
if($patch) {
  Write-Output "wannacry_vulnerable=false"
} else {
  Write-Output "wannacry_vulnerable=true"
}
