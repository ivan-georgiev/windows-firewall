

function Get-FHFirewallAuthorizedEntities {
  [CmdletBinding()]
  param(
    [Parameter()]
    [ValidateSet("Private", "Public", "Domain")]
    [string] $NetworkProfileName
  )

  if ($PSBoundParameters.ContainsKey('NetworkProfileName')) {
    $profileName = $NetworkProfileName
  } else {
    # get active profile
    $profileName = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile
  }


  # variables for result objects properties
  $unkonwnAppsRules = [System.Collections.ArrayList]@()
  $localSubnetRules = [System.Collections.ArrayList] @()
  $authorizedServices = @{}
  $authorizedApps = @{}
  $authorizedExes = @{}
  $allRules = @{}
  $ipv6Rules = [System.Collections.ArrayList] @()
  $systemExeRules = [System.Collections.ArrayList] @()
  $anyExeRules = [System.Collections.ArrayList] @()
  $servicesHashmap = @{}

  Write-Verbose -Message "Get Windows Services"
  $services = Get-Service -ErrorAction SilentlyContinue
  foreach ($srv in $services) {
    $servicesHashmap.Add($srv.Name, [PSCustomObject]@{
        "DisplayName" = $srv.DisplayName
        "Description" = $srv.Description
      })
  }

  # get current user SID
  $currentUserSid = (Get-LocalUser -Name $env:USERNAME -ErrorAction Stop | Select-Object -ExpandProperty SID -ErrorAction Stop).Value

  Write-Verbose -Message "Get Enabled Firewall Outbound Rules"
  $outboundRules = Get-NetFirewallRule -Direction Outbound -Enabled True -ErrorAction Stop -PolicyStore ActiveStore
  # filter rules affecting selected network profile
  $outboundRules = $outboundRules | Where-Object -FilterScript { $_.Profile.ToString().Contains($profileName) -or $_.Profile.ToString() -eq "Any" }
  # remove rules not owned by current user or Any
  $outboundRules = $outboundRules | Where-Object -FilterScript { -not $_.Owner -or $_.Owner -eq $currentUserSid }


  # loop all rules
  $rulesCount = $($outboundRules | Measure-Object).Count
  Write-Verbose -Message "Found [$rulesCount] Enabled outbound rules."
  for ($i = 0; $i -lt ($rulesCount); $i++) {
    $rule = $outboundRules[$i]
    Write-Verbose -Message "Processing $i/$rulesCount - [$($rule.DisplayName) /$($rule.Name)/]"

    # add to all rules
    $allRules.Add($rule.Name, $rule.DisplayName)

    # get address filter and ignore local subnet
    $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    if ($addressFilter.RemoteIP -like "LocalSubnet*" -and $addressFilter.RemoteAddress -like "LocalSubnet*") {
      Write-Verbose -Message "Local Subnet target rule. Continue."
      [void] $localSubnetRules.Add($rule.Name)
      continue
    }

    # get port filter and check if rule is for IPv6 which is ignored by design
    # Protocol numbers: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
    if ($portFilter.Protocol -like '*IPv6*' -or @(41, 43, 58, 59, 60) -contains $portFilter.Protocol) {
      Write-Verbose -Message "IPv6 rule. Continue."
      [void] $ipv6Rules.Add($rule.Name)
      continue
    }

    # get services details
    $serviceFilter = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
    if ($serviceFilter.Service -ne "Any") {
      Write-Verbose -Message "Service rule."
      if ($null -eq $authorizedServices[$serviceFilter.Service]) {
        $authorizedServices.Add($serviceFilter.Service, @{
            "Rules"   = [System.Collections.ArrayList]@()
            "Details" = $servicesHashmap[$serviceFilter.Service]
          })
      }
      [void] $authorizedServices[$serviceFilter.Service]["Rules"].Add($rule.Name)
      continue
    }

    # get application details
    $applicationFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
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
        [void] $authorizedApps[$appDisplayName]["Rules"].Add($rule.Name)
        continue
      } catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning -Message "Registry error during App resolving. Add to Unknown apps list."
        [void] $unkonwnAppsRules.Add($rule.Name)
        continue
      }
    } else {
      Write-Verbose -Message "Exe rule."
      if ($applicationFilter.Program -eq "System") {
        Write-Verbose -Message "System exe. Continue."
        [void] $systemExeRules.Add($rule.Name)
        continue
      }

      if ($applicationFilter.Program -eq "Any") {
        Write-Verbose -Message "Any exe. Continue."
        [void] $anyExeRules.Add(@($rule.Name, $addressFilter.RemoteAddress))
        continue
      }
      # some rules use CMD variables, run cmd to resolve them
      if ($applicationFilter.Program.contains("%")) {
        $exePath = cmd /c echo $applicationFilter.Program
      } else {
        $exePath = $applicationFilter.Program
      }
      $exePath = $exePath.Trim('"')

      if ($null -eq $authorizedExes[$exePath]) {
        $authorizedExes.Add($exePath, @{
            "Rules"   = [System.Collections.ArrayList]@()
            "Details" = $null
          })
      }
      [void] $authorizedExes[$exePath]["Rules"].Add($rule.Name)
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
    "IPv6Rules"          = $ipv6Rules
    "SystemExeRules"     = $systemExeRules
    "AnyExeRules"        = $anyExeRules
  }
}
