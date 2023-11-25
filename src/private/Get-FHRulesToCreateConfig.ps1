function Get-FHRulesToCreateConfig {
  [CmdletBinding()]
  param (
    [Parameter()]
    [string] $AdditionalConfigFile,

    [Parameter()]
    [string[]] $Filter = @()
  )

  $baseRulesFromJson = Get-Content -Path "BaseRulesConfig.json" -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
  $baseRulesFromPs1 = . "./BaseRulesConfig.ps1"

  $additionalConfig = @()
  if ($PSBoundParameters.ContainsKey('AdditionalConfigFile')) {
    $additionalConfig = Get-Content -Path $AdditionalConfigFile -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
  }

  $combinedConfig = $additionalConfig
  foreach ($cfg in $baseRulesFromJson.GetEnumerator()) {
    if ($Filter.Length -eq 0 -or $filter -contains $cfg.Key) {
      $combinedConfig += $cfg.Value
    }
  }
  foreach ($cfg in $baseRulesFromPs1.GetEnumerator()) {
    if ($Filter.Length -eq 0 -or $filter -contains $cfg.Key) {
      $combinedConfig += $cfg.Value
    }
  }

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
    Rules        = $combinedConfig
  }
}
