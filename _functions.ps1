$psFiles = (Get-ChildItem -Path "./src" -Recurse -File -Filter "*.ps1").FullName
foreach ($file in $psFiles) {
  . "$file"
}


Create-FHBaselineReport -ErrorAction Stop -Verbose
