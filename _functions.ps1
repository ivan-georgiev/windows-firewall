Write-Verbose -Message "Load all ps1 files started"
$psFiles = (Get-ChildItem -Path "./src" -Recurse -File -Filter "*.ps1" -ErrorAction Stop).FullName
foreach ($file in $psFiles) {
  . "$file" -ErrorAction Stop
}
Write-Verbose -Message "Load all ps1 files completed"
