function Create-FHScanReport {
  [CmdletBinding()]
  param(
    [Parameter()]
    [string] $EventFilterStartTime = (Get-Date -Format 'yyyy-MM-dd')
  )

  # result
  $config = [System.Collections.ArrayList]@()
  # result file
  $scanFilename = "Scan-$(((Get-Date).ToUniversalTime()).ToString('yyyyMMdd-HHmmss')).json"

  Write-Verbose -Message "Getting blocked enities since [$EventFilterStartTime]"
  $blockedEntities = Get-FHBlockedEntitiesBasedOnEventlog -EventFilterStartTime $EventFilterStartTime -ErrorAction Stop -Verbose

  Write-Verbose -Message "Creating config for blocked Services"
  foreach ($item in $blockedEntities.BlockedServicesList) {
    foreach ($service in $item.Service) {
      [void] $config.add(@{
          Service     = $service.Name
          Description = "Allow '$($service.DisplayName)' service"
          Comment     = "Connections count: $($item.ExecutableDetails.Counter). Blocked IPs: $($item.BlockedIPs). $($service.Description) "
        })
    }
  }
  $serviceRulesCount = ($config | Measure-Object).Count
  Write-Verbose -Message "Created [$serviceRulesCount] rules for Services"

  Write-Verbose -Message "Creating config for blocked Programs"
  foreach ($item in $blockedEntities.BlockedProgramsList) {
    [void] $config.add(@{
        Program = $item.ProcessesExe
        Comment = "Connections count: $($item.Counter). Blocked IPs: $($item.BlockedIps -join ', ')"
      })
  }
  $programRulesCount = (($config | Measure-Object).Count - $serviceRulesCount)
  Write-Verbose -Message "Created [$programRulesCount] rules for Programs"

  # save rules to file
  Write-Verbose -Message "Saving to file [$scanFilename]"
  $config | ConvertTo-Json -Depth 5 -ErrorAction Stop | Out-File -FilePath $scanFilename -Encoding utf8 -Confirm:$false -ErrorAction Stop

  # return filename
  $scanFilename
}
