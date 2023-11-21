

function Disable-FHFirewallRulesForEntity {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string] $Name,

    [Parameter(Mandatory)]
    [ValidateSet("ServiceName", "ServiceDisplayName", "RuleDisplayName", "Exe", "AppDisplayName")]
    [string[]] $EntityType,

    [Parameter()]
    [ValidateSet("Private", "Public", "Domain")]
    [string] $NetworkProfileName = "Private",

    [Parameter()]
    [switch] $Revert
  )

  switch ($EntityType) {
    "ServiceName" {
      $rules = Get-NetFirewallServiceFilter -Service $Name -ErrorAction Stop |  Get-NetFirewallRule -ErrorAction Stop
      $rulesFiltered = $rules | Where-Object -FilterScript { $_.Direction -eq "Outbound" -and @("Any", $NetworkProfileName) -contains $_.Profile } -ErrorAction Stop
      if ($Revert.IsPresent) {
        $rulesFiltered | Enable-NetFirewallRule -ErrorAction Stop
      } else {
        $rulesFiltered | Disable-NetFirewallRule -ErrorAction Stop
      }
    }
    "ServiceDisplayName" {
      $serviceName = (Get-Service -DisplayName $Name -ErrorAction Stop).Name
      $rules = Get-NetFirewallServiceFilter -Service $serviceName -ErrorAction Stop |  Get-NetFirewallRule -ErrorAction Stop
      $rulesFiltered = $rules | Where-Object -FilterScript { $_.Direction -eq "Outbound" -and $_.Enabled -eq "True" -and @("Any", $NetworkProfileName) -contains $_.Profile } -ErrorAction Stop
      if ($Revert.IsPresent) {
        $rulesFiltered | Enable-NetFirewallRule -ErrorAction Stop
      } else {
        $rulesFiltered | Disable-NetFirewallRule -ErrorAction Stop
      }
    }
    "RuleDisplayName" {
      if ($Revert.IsPresent) {
        Enable-NetFirewallRule -DisplayName $Name -ErrorAction Stop
      } else {
        Disable-NetFirewallRule -DisplayName $Name -ErrorAction Stop
      }

    }
    "Exe" {
      # get all app filters
      $appFilters = Get-NetFirewallApplicationFilter -All -ErrorAction Stop

      foreach ($af in $appFilters) {

        # resolve exe path from rule
        if ($af.Program.contains("%")) {
          $exePath = cmd /c echo $applicationFilter.Program
        } else {
          $exePath = $af.Program
        }
        $exePath = $exePath.Trim('"')

        # check if exe matches
        if ($exePath -eq $Name) {
          # get related rules
          $rulesAll = $af | Get-NetFirewallRule -ErrorAction Stop
          $rules = $rulesAll | Where-Object -FilterScript { $_.Direction -eq "Outbound" }
          Write-Verbose -Message "Found rules for exe [$exePath]: [$($rules.DisplayName)]"

          if ($Revert.IsPresent) {
            $rules | Enable-NetFirewallRule -ErrorAction Stop
          } else {
            $rules | Disable-NetFirewallRule -ErrorAction Stop
          }
        }
      }

    }
    "AppDisplayName" {
      throw "Not supprorted yet"
    }
  }
}
