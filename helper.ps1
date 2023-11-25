$VerbosePreference = "Continue"
$ErrorActionPreference = "Stop"

# Load FH-Cmdlets
. .\_functions.ps1 -ErrorAction Stop

throw "helper.ps1 is not intended to be run. Execute specific lines, or copy-paste them."

# Check current network profile. Private is recommended to be set.
$activeProfile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile
$activeProfile

# set Network profile/category to Private. Validate category has changed
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction Stop
$activeProfile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile
$activeProfile

# Create Baseline report of current state of Firewall rules
Create-FHBaselineReport -ErrorAction Stop -Verbose

# Show summary of current firewall rules
Show-FHRulesSummary -BaselineReportFile "Baseline-$activeProfile-latest.json" -ErrorAction Stop -Verbose

# Create Common rules in Firewall
Create-FHFirewallRules -ErrorAction Stop -Verbose -GetConfig
# or just minimal for local network and windows services
Create-FHFirewallRules -ErrorAction Stop -Verbose -GetConfig -Filter Minimal, Windows
# Filter Options: Minimal, Windows, Browsers, BrowserHelpers, HP, Unsorted

# Enable Outbound blocking
Enable-FHOutboundBlocking -NetworkProfileName $activeProfile -ErrorAction Stop -Verbose

# Report changed rules
$null = Compare-FHWithBaselineReport -ErrorAction Stop -Verbose

# Generate report of Blocked programs and save generated file name in var
$customConfig = Create-FHBlockedConnectionsReport -ErrorAction Stop -Verbose
$customConfig

# Reapply rules, including generated custom config.
# None value in Filter is not present in config and will not select Comon rules again
Create-FHFirewallRules -ErrorAction Stop -Verbose -GetConfig -Filter None -AdditionalConfigFile $customConfig

# Disable Rules for Program, Service or App
# Names are from Show-FHRulesSummary output
# Cmdlet supports -Revert switch, which will Enable the item.
Disable-FHFirewallRulesForEntity -Name "c:\windows\system32\wermgr.exe" -EntityType Program -ErrorAction Stop -Verbose

Disable-FHFirewallRulesForEntity -Name "AJRouter" -EntityType ServiceName -ErrorAction Stop -Verbose

Disable-FHFirewallRulesForEntity -Name "AllJoyn Router Service" -EntityType ServiceDisplayName -ErrorAction Stop -Verbose

Disable-FHFirewallRulesForEntity -Name "FH-2D25E820900C5461C490863A3DD18D3E0E1C1BDD-onedrivestandaloneupdater.exe" -EntityType RuleDisplayName -ErrorAction Stop -Verbose

# Block all Outbound traffic, remove -Revert to disable the rule again and unblock the traffic
Disable-FHFirewallRulesForEntity -Name "FH-BlockAllOutbound" -EntityType RuleDisplayName -ErrorAction Stop -Verbose -Revert
