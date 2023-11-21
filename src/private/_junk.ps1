function Get-RulesToCreate {
  [CmdletBinding()]
  param ()

  # return
  @(
    {
      DisplayGroup = "Core Networking Diagnostics"
    },
    {
      DisplayGroup = "File and Printer Sharing"
    }
  )
}

function Get-RulesToEnable {
  [CmdletBinding()]
  param ()

  #New-NetFirewallRule -DisplayName "Allow TCP 12345 and 5000-5020 over Teredo" -Direction Inbound -Action Allow -EdgeTraversalPolicy Allow -Protocol TCP -LocalPort 12345,5000-5020 -Program "C:\Program Files (x86)\TestIPv6App.exe"

  # return
  @(
    @{
      Enabled       = "True"
      Direction     = "Outbound"
      Action        = "Allow"
      DisplayName   = "FH-LocalNetwork"
      Group         = "FirewallHelper"
      Description   = "Enabled LocalNetwork Traffic"
      Profile       = "Any"
      LocalAddress  = "Any"
      LocalPort     = "Any"
      RemoteAddress = @(
        "LocalSubnet4", "DNS4", "DHCP4", "WINS4", "DefaultGateway4", "Intranet4", "PlayToDevice4"
      )
      RemotePort    = "Any"
      Service       = $null
      Program       = $null
      Package       = $null
    }
  )
}



#Create-ActiveProfileBaselineReport -ErrorAction Stop -Verbose
# Map-RunningConnectionsWithFirewallRules -ErrorAction Stop -Verbose
$t = @{
  Enabled       = "True"
  PolicyStore   = "PersistentStore"
  Direction     = "Outbound"
  Action        = "Allow"
  Name          = "zFH-LocalNetwork2"
  DisplayName   = "zFH-LocalNetwork2"
  Group         = "zFirewallHelper"
  Description   = "Enabled LocalNetwork Traffic"
  Profile       = "Any"
  LocalAddress  = "Any"
  LocalPort     = "Any"
  RemoteAddress = @(
    "LocalSubnet4", "DNS4", "DHCP4", "WINS4", "DefaultGateway4", "Intranet4", "PlayToDevice4"
  )
  RemotePort    = "Any"
  #Service = $null
  #Program = $null
  #Package = $null
}
#New-NetFirewallRule @t
#Compare-WithBaselineReport -Verbose -ErrorAction Stop
