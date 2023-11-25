function Enable-FHOutboundBlocking {
  [CmdletBinding()]
  param(
    [Parameter()]
    [ValidateSet("Private", "Public", "Domain")]
    [string] $NetworkProfileName = "Private"
  )

  # set connection profile to $NetworkProfileName
  Write-Verbose -Message "Set NetworkProfile to [$NetworkProfileName]"
  Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory $NetworkProfileName -ErrorAction Stop

  Write-Verbose -Message "Ensure all profiles are enabled"
  Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -ErrorAction Stop

  # Set DefaultOutboundAction to Block
  Write-Verbose -Message "Set DefaultInboundAction and DefaultOutboundAction to Block"
  $HashArguments = @{
    DefaultInboundAction  = "Block"
    DefaultOutboundAction = "Block"
  }
  Set-NetFirewallProfile @HashArguments -ErrorAction Stop

  Write-Verbose -Message "Configure Aduits"
  Enable-FHFirewallAuditEvents -ErrorAction Stop -Verbose
}
