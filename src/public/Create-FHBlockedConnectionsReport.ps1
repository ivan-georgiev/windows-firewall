function Create-FHBlockedConnectionsReport {
  [CmdletBinding()]
  param(
    [Parameter()]
    [string] $EventFilterStartTime = (Get-Date -Format 'yyyy-MM-dd'),

    [Parameter()]
    [switch] $DoNotUseBaselineReportFile
  )

  $activeProfile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile
  Write-Verbose -Message "Active network profile: [$activeProfile]"
  # get firewall details
  $entities = $null
  if (-not $DoNotUseBaselineReportFile.IsPresent) {
    try {
      $baselineFile = Get-Item -Path "Baseline-$activeProfile-latest.json" -ErrorAction Stop
      Write-Verbose -Message "Detected Baseline file [$($baselineFile.Name)] from [$($baselineFile.LastWriteTime)]."
      # get MPSSVC Rule-Level Policy Change
      try {
        # get 4946 MPSSVC Rule-Level Policy Change  events
        $events = Get-WinEvent -FilterHashtable @{
          LogName   = 'Security'
          StartTime = "$($baselineFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
          ID        = @(4946)
        } -ErrorAction Stop -Verbose:$false
        Write-Warning -Message "Rule changed events found. Generate new baseline report."
        $null = Create-FHBaselineReport -NetworkProfileName $activeProfile -ErrorAction Stop
      } catch {
        # if there are no events return $null
        if ($_.Exception.Message -eq "No events were found that match the specified selection criteria.") {
          Write-Verbose -Message "No MPSSVC Rule-Level Policy Change events found. Baseline file will not be regenerated. Delete it if needed or pass -DoNotUseBaselineReportFile."
        } else {
          # raise other errors
          throw
        }
      }
      # get baseline file content
      $entities = Get-Content -Path "Baseline-$activeProfile-latest.json" -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
      Write-Warning -Message "Error getting baseline file content [$($_.Exception.Message)]. Generate new baseline report."
      $null = Create-FHBaselineReport -NetworkProfileName $activeProfile -ErrorAction Stop
      # get baseline content
      $entities = Get-Content -Path "Baseline-$activeProfile-latest.json" -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
    }
  }
  if ($null -eq $entities) {
    Write-Verbose -Message "Baseline file not detected. Get enitities dynamically"
    $entities = Get-FHFirewallAuthorizedEntities -NetworkProfileName $activeProfile -ErrorAction Stop -Verbose
  }

  # result
  $config = [System.Collections.ArrayList]@()
  $report = [System.Collections.ArrayList]@()
  # result file
  $date = $(((Get-Date).ToUniversalTime()).ToString('yyyyMMdd-HHmmss'))
  $configFilename = "Config-$date.json"
  $reportFilename = "ConfigReport-$date.json"

  Write-Verbose -Message "Getting blocked enities since [$EventFilterStartTime]"
  $blockedEntities = Get-FHBlockedExes -EventFilterStartTime $EventFilterStartTime -ErrorAction Stop -Verbose

  Write-Verbose -Message "Creating config for blocked Programs"
  foreach ($item in $blockedEntities.BlockedProgramsList) {

    $comment = [System.Text.StringBuilder]::new()
    $description = [System.Text.StringBuilder]::new()

    # file details
    $itemDetails = Get-Item -Path $item.ProcessesExe -ErrorAction Stop
    [void] $description.Append("Product: $($itemDetails.VersionInfo.ProductName). ")
    if ($itemDetails.VersionInfo.ProductProductName -ne $itemDetails.VersionInfo.FileDescription) {
      [void] $description.Append("FileDescription: $($itemDetails.VersionInfo.FileDescription). ")
    }

    # associated services details
    if (($item.AssociatedServices | Measure-Object).Count -gt 0) {
      [void]$description.Append("Associated services: $($item.AssociatedServices.Name -join ", "). ")
    }
    if (($item.AssociatedServices | Measure-Object).Count -eq 1) {
      [void]$description.Append("Service details: $($entities.ServicesHashmap[$item.AssociatedServices[0].Name].Description). ")
    }

    # rules details
    $rules = $entities.AuthorizedExes[$item.ProcessesExe].Rules
    if (-not $rules) {
      [void] $config.add(@{
          Program     = $item.ProcessesExe
          Description = $description.ToString()
        })
    }
  } else {
    [void]$comment.Append("Firewall Rules: $($rules -join ', '). ")
  }

  [void]$comment.Append("IPs: $($item.BlockedIps -join ', '). ")
  [void]$comment.Append("Connections count: $($item.Counter). ")

  [void] $report.add(@{
      Program     = $item.ProcessesExe
      Description = $description.ToString()
      Comment     = $comment.ToString()
    })

  if (($report | Measure-Object).Count -eq 0) {
    Write-Verbose -Message "Nothing to report. No files will be created."
    return
  }

  # save report rules to file
  Write-Verbose -Message "Saving Report to file [$reportFilename]"
  $report | Sort-Object -Property "Program", "Service" | ConvertTo-Json -Depth 5 -ErrorAction Stop | Out-File -FilePath $reportFilename -Encoding utf8 -Confirm:$false -ErrorAction Stop

  # save config file, if not empty
  $programRulesCount = ($config | Measure-Object).Count
  if ($programRulesCount -eq 0) {
    Write-Verbose -Message "Nothing to record. Config file will not be created."
    return
  }
  Write-Verbose -Message "Created [$programRulesCount] rules for Programs"

  # save config rules to file
  Write-Verbose -Message "Saving Config to file [$configFilename]"
  $config | Sort-Object -Property "Program", "Service" | ConvertTo-Json -Depth 5 -ErrorAction Stop | Out-File -FilePath $configFilename -Encoding utf8 -Confirm:$false -ErrorAction Stop

  # return filename
  $configFilename
}
