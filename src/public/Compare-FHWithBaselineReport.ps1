
function Compare-FHWithBaselineReport {
  [CmdletBinding()]
  param(
    [Parameter()]
    [string] $BaselineReportFile,

    [Parameter()]
    [string] $CurrentStateFile
  )

  # get current state from file or dynamically
  if ($PSBoundParameters.ContainsKey('CurrentStateFile')) {
    Write-Verbose -Message "CurrentStateFile passed: [$CurrentStateFile]"
    $entities = Get-Content -Path $CurrentStateFile -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
    $activeProfile = ($CurrentStateFile -split "-")[1]
  } else {
    $activeProfile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile
    Write-Verbose -Message "Active network profile: [$activeProfile]"

    Write-Verbose -Message "Generate CurrentState report for active profile started"
    $entities = Get-FHFirewallAuthorizedEntities -NetworkProfileName $activeProfile -ErrorAction Stop -Verbose
    Write-Verbose -Message "Generate CurrentState report for active profile completed"
  }

  # get baseline state
  if ($PSBoundParameters.ContainsKey('BaselineReportFile')) {
    Write-Verbose -Message "BaselineReportFile passed: [$BaselineReportFile]"
    $baselineFile = $BaselineReportFile
    $baselineProfile = ($baselineFile -split "-")[1]

    # validate network profiles match
    if ($activeProfile -ne $baselineProfile) {
      throw "Network profile of Baseline [$baselineProfile] does not match Active profile [$activeProfile]"
    }
  } else {
    $baselineFile = "Baseline-$activeProfile-latest.json"
  }
  $baselineEntities = Get-Content -Path $baselineFile -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
  $dateGenerated = $baselineEntities.DateGenerated

  # generate rules report
  $rulesDiff = Compare-FHObjectWithNullSupport -ReferenceObject $baselineEntities.AllRules.GetEnumerator().Name -DifferenceObject $entities.AllRules.GetEnumerator().Name -ErrorAction Stop
  if ($rulesDiff.New) {
    Write-Verbose -Message "`n=== New Firewall Rules:"
    foreach ($r in $rulesDiff.New) {
      Write-Verbose -Message "$($baselineEntities.AllRules[$r]) /$r/"
    }
  }
  if ($rulesDiff.Deleted) {
    Write-Verbose -Message "`n=== Deleted Firewall Rules:"
    foreach ($r in $rulesDiff.Deleted) {
      Write-Verbose -Message "$($baselineEntities.AllRules[$r]) / $r /"
    }
  }

  $servicesDiff = Compare-FHObjectWithNullSupport -ReferenceObject $baselineEntities.AuthorizedServices.Values.Details.DisplayName -DifferenceObject $entities.AuthorizedServices.Values.Details.DisplayName -ErrorAction Stop
  if ($servicesDiff.New) {
    Write-Verbose -Message "`n=== New Firewall authorized Services:`n$($servicesDiff.New -join "`n") `n`n"
  }
  if ($servicesDiff.Deleted) {
    Write-Verbose -Message "`n=== Deleted Firewall rules affecting Services:`n$($servicesDiff.Deleted -join "`n") `n`n"
  }

  $exesDiff = Compare-FHObjectWithNullSupport -ReferenceObject $baselineEntities.AuthorizedExes.GetEnumerator().Name -DifferenceObject $entities.AuthorizedExes.GetEnumerator().Name -ErrorAction Stop
  if ($exesDiff.New) {
    Write-Verbose -Message "`n=== New Firewall authorized Exes:`n$($exesDiff.New -join "`n") `n`n"
  }
  if ($exesDiff.Deleted) {
    Write-Verbose -Message "`n=== Deleted Firewall rules affecting Exes:`n$($exesDiff.Deleted -join "`n") `n`n"
  }

  $appsDiff = Compare-FHObjectWithNullSupport -ReferenceObject $baselineEntities.AuthorizedApps.GetEnumerator().Name -DifferenceObject $entities.AuthorizedApps.GetEnumerator().Name -ErrorAction Stop
  if ($appsDiff.New) {
    Write-Verbose -Message "`n=== New Firewall authorized Apps:`n$($appsDiff.New -join "`n") `n`n"
  }
  if ($appsDiff.Deleted) {
    Write-Verbose -Message "`n=== Deleted Firewall rules affecting Apps:`n$($appsDiff.Deleted -join "`n") `n`n"
  }


  # get MPSSVC Rule-Level Policy Change
  try {
    # get 4946 MPSSVC Rule-Level Policy Change  events
    $events = Get-WinEvent -FilterHashtable @{
      LogName   = 'Security'
      StartTime = "$dateGenerated"
      ID        = @(4946)
    } -ErrorAction Stop -Verbose:$false | Sort-Object -Property TimeCreated -Descending

    Write-Verbose -Message "`n === Rule changes events:`n $($events.Message.ToString().Split([Environment]::NewLine) | Select-String 'Rule Name:')`n`n"
  } catch {
    # if there are no events return $null
    if ($_.Exception.Message -eq "No events were found that match the specified selection criteria.") {
      Write-Verbose -Message "No MPSSVC Rule-Level Policy Change events found."
    } else {
      # raise other errors
      throw
    }
  }

  #return
  [PSCustomObject]@{
    RulesDiff    = $rulesDiff
    ServicesDiff = $servicesDiff
    ExesDiff     = $exesDiff
    AppsDiff     = $appsDiff
  }
}
