

function Enable-FHOutboundBlocking {
  [CmdletBinding()]
  param (
  )
  $HashArguments = @{
    DefaultOutboundAction = "Allow"
  }
  Set-NetFirewallProfile @HashArguments -ErrorAction Stop
  Disable-FHFirewallAuditEvents -ErrorAction Stop -Verbose
}
