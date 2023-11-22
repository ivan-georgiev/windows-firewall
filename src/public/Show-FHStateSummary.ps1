
function Show-FHStateSummary {
  [CmdletBinding()]
  param(
    [Parameter()]
    [string] $BaselineReportFile,

    [Parameter()]
    [PSCustomObject] $AuthorizedEnitiesObject
  )

  if ($PSBoundParameters.ContainsKey('BaselineReportFile')) {
    Write-Verbose -Message "BaselineReportFile summary [$BaselineReportFile]"
    $entities = Get-Content -Path $BaselineReportFile -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
  } elseif ($PSBoundParameters.ContainsKey('AuthorizedEnitiesObject')) {
    $entities = $AuthorizedEnitiesObject
  } else {
    $activeProfile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile
    Write-Verbose -Message "Active network profile: [$activeProfile]"

    Write-Verbose -Message "Generate CurrentState report for active profile started"
    $entities = Get-FHFirewallAuthorizedEntities -NetworkProfileName $activeProfile -ErrorAction Stop -Verbose
  }

  Write-Verbose -Message "===== Rules granting all entities access non-local access:`n$($entities.AnyExeRules -join "`n")`n`n"
  Write-Verbose -Message "===== Authorized exes:`n$(($entities.AuthorizedExes.getEnumerator().Name | Sort-Object) -join "`n")`n`n"
  Write-Verbose -Message "===== Authorized services:`n$(($entities.AuthorizedServices.dhcp.Details.DisplayName | Sort-Object) -join "`n")`n`n"
  Write-Verbose -Message "===== Authorized Apps:`n$(($entities.AuthorizedApps.GetEnumerator().Name | Sort-Object) -join "`n")`n`n"
}
