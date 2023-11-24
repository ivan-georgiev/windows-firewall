function Enable-FHFirewallAuditEvents {
  [CmdletBinding()]
  param(
    [Parameter()]
    [ValidateSet("FilteringPlatformConnection", "RuleLevelChanges")]
    [string] $Category = "FilteringPlatformConnection"
  )

  if ($Category -eq "FilteringPlatformConnection") {
    auditpol /set /category:"System" /subcategory:"Filtering Platform Connection" /success:disable  /failure:enable
    if ($LASTEXITCODE -ne 0 -or -not $?) {
      throw "auditpol error"
    }
    return
  }

  if ($Category -eq "RuleLevelChanges") {
    auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /Success:Enable /Failure:Enable
    if ($LASTEXITCODE -ne 0 -or -not $?) {
      throw "auditpol error"
    }
    return
  }
}
