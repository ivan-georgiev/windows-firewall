function Get-FirewallOutboundDisplayGroups {
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

function Enable-Firewall {
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
    AllowUnicastResponseToMulticast = "True"
    LogFileName                     = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
  }
  Set-NetFirewallProfile @HashArguments -ErrorAction Stop

  # enable some redefined rules
  $outboundRules = Get-NetFirewallRule -Direction Outbound -Enabled False
  foreach ($rule in Get-FirewallOutboundDisplayGroups) {
    $ruleToEnable = $outboundRules  | Where-Object -FilterScript { $_.DisplayGroup -eq $rule.DisplayGroup }
    $ruleToEnable
    #$ruleToEnable | Set-NetFirewallRule -Enabled -ErrorAction Stop
  }
}

function Disable-OutboundFirewall {
  [CmdletBinding()]
  param (
  )

  $HashArguments = @{
    DefaultInboundAction            = "Block"
    DefaultOutboundAction           = "Allow"
    AllowUnicastResponseToMulticast = "True"
    LogFileName                     = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
  }

  Set-NetFirewallProfile @HashArguments -ErrorAction Stop
}

function Get-FirewallAuthorizedEntities {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet("Private", "Public", "Domain")]
    [string] $NetworkProfileName
  )

  $activeProfile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile
  if ($activeProfile -ne $NetworkProfileName) {
    throw "Current ActiveProfile is not [$NetworkProfileName] but [$activeProfile]. Run Enable-Firewall cmdlet."
  }

  $unkonwnAppsRules = [System.Collections.ArrayList]@()
  $localSubnetRules = [System.Collections.ArrayList] @()
  $authorizedServices = @{}
  $authorizedApps = @{}
  $authorizedExes = @{}
  $allRules = [System.Collections.ArrayList] @()

  Write-Verbose -Message "Get Enabled Outbound Rules"
  $outboundRules = Get-NetFirewallRule -Direction Outbound -Enabled True -ErrorAction Stop `
  | Where-Object -FilterScript { $_.Profile -contains $activeProfile -or $_.Profile -contains "Any" }
  $rulesCount = $($outboundRules | Measure-Object).Count
  Write-Verbose -Message "Found [$rulesCount] Enabled outbound rules"

  for ($i = 100; $i -lt $rulesCount; $i++) {

    $rule = $outboundRules[$i]
    Write-Verbose -Message "Processing $i/$rulesCount - $($rule.DisplayName)"

    # add to all rules list
    [void] $allRules.Add($rule.DisplayName)

    # get address filter and ignore local subnet
    $addressFilter = $rule | Get-NetFirewallAddressFilter
    if ($addressFilter.RemoteIP -eq "LocalSubnet" -and $addressFilter.RemoteAddress -eq "LocalSubnet") {
      Write-Verbose -Message "Local Subnet target rule. Continue."
      [void] $localSubnetRules.Add($rule.DisplayName)
    }

    # get services details
    $serviceFilter = $rule | Get-NetFirewallServiceFilter
    if ($serviceFilter.Service -ne "Any") {
      Write-Verbose -Message "Service rule."
      if ($null -eq $authorizedServices[$serviceFilter.Service]) {
        $authorizedServices.Add($serviceFilter.Service, [System.Collections.ArrayList]@())
      }
      [void] $authorizedServices[$serviceFilter.Service].Add($rule.DisplayName)
      continue
    }

    # get application details
    $applicationFilter = $rule | Get-NetFirewallApplicationFilter
    # if App, resolve it base on the SID
    if ($applicationFilter.Package) {
      Write-Verbose -Message "App rule."
      try {
        # an alternative path is "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\$($applicationFilter.Package)"
        $details = Get-Item -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\$($applicationFilter.Package)"
        $appDisplayName = $details.GetValue("DisplayName")
        # Values are in DisplayName and Monikier
        if ($null -eq $authorizedApps[$appDisplayName]) {
          $authorizedApps.Add($appDisplayName, [System.Collections.ArrayList]@())
        }
        [void] $authorizedApps[$appDisplayName].Add($rule.DisplayName)
      } catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning -Message "Registry error during App resolving. Add to Unknown apps list."
        [void] $unkonwnAppsRules.Add($rule.DisplayName)
        continue
      }
    } else {
      Write-Verbose -Message "Exe rule."
      if ($applicationFilter.Program -eq "System") {
        Write-Verbose -Message "System exe. Continue."
      }
      if ($null -eq $authorizedExes[$applicationFilter.Program]) {
        $authorizedExes.Add($applicationFilter.Program, [System.Collections.ArrayList]@())
      }
      [void] $authorizedExes[$applicationFilter.Program].Add($rule.DisplayName)
    }
  }
  # return
  [PSCustomObject]@{
    "AuthorizedServices" = $authorizedServices
    "AuthorizedApps"     = $authorizedApps
    "AuthorizedExes"     = $authorizedExes
    "UnkonwnAppsRules"   = $unkonwnAppsRules
    "LocalSubnetRules"   = $localSubnetRules
    "AllRules"           = $allRules
  }
}



function Create-BaselineReport {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet("Private", "Public", "Domain")]
    [string] $NetworkProfileName
  )

  # result file
  $baselineFilename = "Baseline-$NetworkProfileName-$(((Get-Date).ToUniversalTime()).ToString('yyyyMMdd-HHmmss')).json"

  # generate rules report
  $enitities = Get-FirewallAuthorizedEntities -NetworkProfileName $NetworkProfileName -ErrorAction Stop -Verbose

  # save rules report to a file
  $enitities | ConvertTo-Json -Depth 5 | Out-File -FilePath $baselineFilename -Encoding utf8 -ErrorAction Stop -Confirm:$false

  # save result to latest, not just timestamp
  Copy-Item -Path $baselineFilename -Destination "Baseline-$NetworkProfileName-latest.json" -Force -Confirm:$false -ErrorAction Stop

  # result
  $baselineFilename
}



function Create-ActiveProfileBaselineReport {
  [CmdletBinding()]
  param()

  $activeProfile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile
  Write-Verbose -Message "Active network profile: [$activeProfile]"

  # result
  Create-BaselineReport -NetworkProfileName $activeProfile -ErrorAction Stop -Verbose
}


function Compare-ActiveStateWithBaselineReport {
  [CmdletBinding()]
  param(
    [Parameter()]
    [string] $BaselineReportFile
  )

  $activeProfile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile
  Write-Verbose -Message "Active network profile: [$activeProfile]"

  if ($PSBoundParameters.ContainsKey('BaselineReportFile')) {
    $baselineFile = $BaselineReportFile
  } else {
    $baselineFile = "Baseline-$activeProfile-latest.json"
  }
  Write-Verbose -Message "Compare Current state with [$baselineFile]"

  $baselineEntities = Get-Content -Path $baselineFile -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
  # generate rules report

  $enitities = Get-FirewallAuthorizedEntities -NetworkProfileName $activeProfile -ErrorAction Stop -Verbose

}

Compare-ActiveStateWithBaselineReport -ErrorAction Stop -Verbose
