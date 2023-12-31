﻿function Create-FHBaselineReport {
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
  Write-Verbose -Message "Network profile: [$profileName]"

  $currentDate = Get-Date

  # result file
  $baselineFilename = "Baseline-$profileName-$(($currentDate.ToUniversalTime()).ToString('yyyyMMdd_HHmmss')).json"

  # generate rules report
  $entities = Get-FHFirewallAuthorizedEntities -NetworkProfileName $profileName -ErrorAction Stop -Verbose
  $entities | Add-Member -NotePropertyName DateGenerated -NotePropertyValue ($currentDate.ToUniversalTime()).ToString('yyyy-MM-dd HH:mm:ss') -ErrorAction Stop

  # save rules report to a file
  $entities | ConvertTo-Json -Depth 5 | Out-File -FilePath $baselineFilename -Encoding utf8 -ErrorAction Stop -Confirm:$false

  # save result to latest, not just timestamp
  Copy-Item -Path $baselineFilename -Destination "Baseline-$profileName-latest.json" -Force -Confirm:$false -ErrorAction Stop

  # result
  $baselineFilename
}
