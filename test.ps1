$VerbosePreference = "Continue"
$ErrorActionPreference = "Stop"

. ./_functions.ps1


Show-FHStateSummary -ErrorAction Stop -Verbose

#Create-FHBaselineReport -ErrorAction Stop -Verbose
#Map-FHRunningConnectionsWithFirewallRules -ErrorAction Stop -Verbose
# Create-FHRules -Verbose -ErrorAction Stop -DeleteIfExists
# Compare-FHWithBaselineReport -ErrorAction Stop -Verbose
# Show-FHStateSummary -BaselineReportFile Baseline-Private-latest.json -ErrorAction Stop -Verbose
#Show-FHActiveConnectionsRulesDetails -UseBaselineReportFile -ErrorAction Stop -Verbose
#Enable-FHWindowsFirewall -ErrorAction Stop -Verbose
#Show-FHActiveConnectionsRulesDetails -ErrorAction Stop -Verbose

#$config = Get-FHRulesToCreateConfig -AdditionalConfigFile "Scan-20231123-193728.json" -Verbose  -ErrorAction Stop
#$config = Get-FHRulesToCreateConfig -Verbose  -ErrorAction Stop
#Create-FHFirewallRules -RulesToCreateConfig $config -DeleteIfExists:$false -ErrorAction Stop -Verbose

#Create-FHScanReport -ErrorAction Stop -Verbose
