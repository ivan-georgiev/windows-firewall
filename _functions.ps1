#Requires -Version 7.0
#Requires -RunAsAdministrator
[CmdletBinding()]
param()

Write-Verbose -Message "Load all ps1 files started" -Verbose
$psFiles = (Get-ChildItem -Path "./src" -Recurse -File -Filter "*.ps1" -ErrorAction Stop).FullName
foreach ($file in $psFiles) {
  try {
    . "$file" -ErrorAction Stop
  } catch {
    Write-Error -Message "Error sourcing [$($file)]." -ErrorAction Continue
    throw
  }
}
Write-Verbose -Message "Load all ps1 files completed" -Verbose
