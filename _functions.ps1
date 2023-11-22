$psFiles = (Get-ChildItem -Path "." -Recurse -File -Filter "*.ps1").FullName
foreach ($file in $psFiles) {
  . "$file" -ErrorAction Stop
}


#Create-FHBaselineReport -ErrorAction Stop -Verbose
#Map-FHRunningConnectionsWithFirewallRules -ErrorAction Stop -Verbose
# Create-FHRules -Verbose -ErrorAction Stop -DeleteIfExists
# Compare-FHWithBaselineReport -ErrorAction Stop -Verbose
# Show-FHStateSummary -BaselineReportFile Baseline-Private-latest.json -ErrorAction Stop -Verbose
# Show-FHActiveConnectionsRulesDetails -ErrorAction Stop -Verbose

# Enable-FHWindowsFirewall -ErrorAction Stop -Verbose
# Show-FHActiveConnectionsRulesDetails -ErrorAction Stop -Verbose

$config = Get-FHRulesToCreateConfig -ErrorAction Stop
Create-FHFirewallRules -RulesToCreateConfig $config -ErrorAction Stop -Verbose
