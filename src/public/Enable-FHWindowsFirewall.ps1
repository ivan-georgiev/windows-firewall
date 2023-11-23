function Enable-FHWindowsFirewall {
  [CmdletBinding()]
  param(
    [Parameter()]
    [ValidateSet("Private", "Public", "Domain")]
    [string] $NetworkProfileName = "Private"
  )

  # set connection profile to $NetworkProfileName
  Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory $NetworkProfileName -ErrorAction Stop

  # ensure all profiles are enabled
  Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -ErrorAction Stop

  # Set DefaultOutboundAction to Block
  $HashArguments = @{
    DefaultInboundAction            = "Block"
    DefaultOutboundAction           = "Block"
  }
  Set-NetFirewallProfile @HashArguments -ErrorAction Stop
}
