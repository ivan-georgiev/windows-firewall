$psFiles = (Get-ChildItem -Path "./src" -Recurse -File -Filter "*.ps1").FullName
foreach ($file in $psFiles) {
  . "$file" -ErrorAction Stop
}
. ./Get-FHRulesToCreateConfig.ps1

#Create-FHBaselineReport -ErrorAction Stop -Verbose
#Map-FHRunningConnectionsWithFirewallRules -ErrorAction Stop -Verbose
# Create-FHRules -Verbose -ErrorAction Stop -DeleteIfExists
# Compare-FHWithBaselineReport -ErrorAction Stop -Verbose
# Show-FHStateSummary -BaselineReportFile Baseline-Private-latest.json -ErrorAction Stop -Verbose
Show-FHActiveConnectionsRulesDetails -UseBaselineReportFile -ErrorAction Stop -Verbose
#Enable-FHWindowsFirewall -ErrorAction Stop -Verbose
#Show-FHActiveConnectionsRulesDetails -ErrorAction Stop -Verbose

#$config = Get-FHRulesToCreateConfig -ErrorAction Stop
#Create-FHFirewallRules -RulesToCreateConfig $config -ErrorAction Stop -Verbose
