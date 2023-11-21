

function Disable-FHOutboundBlocking {
  [CmdletBinding()]
  param (
  )
  $HashArguments = @{
    DefaultOutboundAction = "Allow"
  }
  Set-NetFirewallProfile @HashArguments -ErrorAction Stop
}
