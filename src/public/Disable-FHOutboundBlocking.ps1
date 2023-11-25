

function Disable-FHOutboundBlocking {
  [CmdletBinding()]
  param ()

  $HashArguments = @{
    DefaultOutboundAction = "Allow"
  }
  Write-Verbose -Message "Set DefaultOutboundAction to Allow"
  Set-NetFirewallProfile @HashArguments -ErrorAction Stop

  Write-Verbose -Message "Configure Aduits"
  Disable-FHFirewallAuditEvents -ErrorAction Stop -Verbose
}
