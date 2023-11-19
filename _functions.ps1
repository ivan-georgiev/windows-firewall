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

  $servicesHashmap = @{}
  $services = Get-Service -ErrorAction SilentlyContinue
  foreach ($srv in $services) {
    $servicesHashmap.Add($srv.Name, [PSCustomObject]@{
        "DisplayName" = $srv.DisplayName
        "Description" = $srv.Description
      })
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

  for ($i = 0; $i -lt ($rulesCount - 130); $i++) {

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
        $authorizedServices.Add($serviceFilter.Service, @{
            "Rules"   = [System.Collections.ArrayList]@()
            "Details" = $servicesHashmap[$serviceFilter.Service]
          })
      }
      [void] $authorizedServices[$serviceFilter.Service]["Rules"].Add($rule.DisplayName)
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
          $authorizedApps.Add($appDisplayName, @{
              "Rules"   = [System.Collections.ArrayList]@()
              "Details" = $null
            })
        }
        [void] $authorizedApps[$appDisplayName]["Rules"].Add($rule.DisplayName)
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
        $authorizedExes.Add($applicationFilter.Program, @{
            "Rules"   = [System.Collections.ArrayList]@()
            "Details" = $null
          })
      }
      [void] $authorizedExes[$applicationFilter.Program]["Rules"].Add($rule.DisplayName)
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
    "ServicesHashmap"    = $servicesHashmap
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
  $entities = Get-FirewallAuthorizedEntities -NetworkProfileName $NetworkProfileName -ErrorAction Stop -Verbose

  # save rules report to a file
  $entities | ConvertTo-Json -Depth 5 | Out-File -FilePath $baselineFilename -Encoding utf8 -ErrorAction Stop -Confirm:$false

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

  $entities = Get-FirewallAuthorizedEntities -NetworkProfileName $activeProfile -ErrorAction Stop -Verbose

  $rulesDiff = Compare-ObjectWithNullSupport -ReferenceObject $baselineEntities.AllRules -DifferenceObject $entities.AllRules -ErrorAction Stop
  if ($rulesDiff.New) {
    Write-Verbose -Message "=== New Firewall Rules:`n$($rulesDiff.New -join "`n") `n`n"
  }
  if ($rulesDiff.Deleted) {
    Write-Verbose -Message "=== Deleted Firewall Rules:`n$($rulesDiff.Deleted -join "`n") `n`n"
  }

  $servicesDiff = Compare-ObjectWithNullSupport -ReferenceObject $baselineEntities.AuthorizedServices.Values.Details.DisplayName -DifferenceObject $entities.AuthorizedServices.Values.Details.DisplayName -ErrorAction Stop
  if ($servicesDiff.New) {
    Write-Verbose -Message "=== New Firewall authorized Services:`n$($servicesDiff.New -join "`n") `n`n"
  }
  if ($servicesDiff.Deleted) {
    Write-Verbose -Message "=== Deleted Firewall rules affecting Services:`n$($servicesDiff.Deleted -join "`n") `n`n"
  }

  $exesDiff = Compare-ObjectWithNullSupport -ReferenceObject $baselineEntities.AuthorizedExes.GetEnumerator().Name -DifferenceObject $entities.AuthorizedExes.GetEnumerator().Name -ErrorAction Stop
  if ($exesDiff.New) {
    Write-Verbose -Message "=== New Firewall authorized Exes:`n$($exesDiff.New -join "`n") `n`n"
  }
  if ($exesDiff.Deleted) {
    Write-Verbose -Message "=== Deleted Firewall rules affecting Exes:`n$($exesDiff.Deleted -join "`n") `n`n"
  }

  $appsDiff = Compare-ObjectWithNullSupport -ReferenceObject $baselineEntities.AuthorizedApps.GetEnumerator().Name -DifferenceObject $entities.AuthorizedApps.GetEnumerator().Name -ErrorAction Stop
  if ($appsDiff.New) {
    Write-Verbose -Message "=== New Firewall authorized Apps:`n$($appsDiff.New -join "`n") `n`n"
  }
  if ($appsDiff.Deleted) {
    Write-Verbose -Message "=== Deleted Firewall rules affecting Apps:`n$($appsDiff.Deleted -join "`n") `n`n"
  }

  #return
  [PSCustomObject]@{
    RulesDiff    = $rulesDiff
    ServicesDiff = $servicesDiff
    ExesDiff     = $exesDiff
    AppsDiff     = $appsDiff
  }
}

function Compare-ObjectWithNullSupport {
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [AllowEmptyCollection()]
    [string[]] $ReferenceObject,

    [Parameter()]
    [AllowNull()]
    [AllowEmptyCollection()]
    [string[]] $DifferenceObject
  )

  if ($null -eq $ReferenceObject) {
    return [PSCustomObject]@{
      New     = $DifferenceObject
      Deleted = $null
    }
  }

  if ($null -eq $DifferenceObject) {
    return [PSCustomObject]@{
      New     = $null
      Deleted = $ReferenceObject
    }
  }

  $diff = Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject -ErrorAction Stop
  $new = $diff | Where-Object -Property SideIndicator -EQ ">=" | Select-Object -ExpandProperty InputObject -ErrorAction Stop
  $deleted = $diff | Where-Object -Property SideIndicator -EQ "<=" | Select-Object -ExpandProperty InputObject -ErrorAction Stop
  return [PSCustomObject]@{
    New     = $new
    Deleted = $deleted
  }

}


function Disable-RulesForEntity {
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
      throw "Not supprorted yet"
    }
    "AppDisplayName" {
      throw "Not supprorted yet"
    }
  }

}


# review active connections and compare agains blocked log
# get own rules config: service, exe, app
# apply own rules config




#Compare-ActiveStateWithBaselineReport -ErrorAction Stop -Verbose
#Create-ActiveProfileBaselineReport -ErrorAction Stop -Verbose
