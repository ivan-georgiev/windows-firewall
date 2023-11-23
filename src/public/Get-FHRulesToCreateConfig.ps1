function Get-FHRulesToCreateConfig {
  [CmdletBinding()]
  param (
    [Parameter()]
    [string] $AdditionalConfigFile
  )

  $additionalConfig = @()
  if ($PSBoundParameters.ContainsKey('AdditionalConfigFile')) {
    $additionalConfig = Get-Content -Path $AdditionalConfigFile -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
  }

  $baseRulesFromJson = Get-Content -Path "BaseRulesConfig.json" -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
  $baseRulesFromPs1 = . "./BaseRulesConfig.ps1"

  $combinedConfig = $baseRulesFromPs1 + $baseRulesFromJson + $additionalConfig

  # return
  [PSCustomObject]@{
    CommonParams = @{
      Enabled       = "True"
      PolicyStore   = "PersistentStore"
      Direction     = "Outbound"
      Action        = "Allow"
      Group         = "AFirewallHelper"
      Profile       = "Any"
      LocalAddress  = "Any"
      LocalPort     = "Any"
      Protocol      = "Any"
      RemoteAddress = "Any"
      RemotePort    = "Any"
      Description   = "Rule Created by Firewall Helper script"
    }
    Rules       = $combinedConfig
  }
}
