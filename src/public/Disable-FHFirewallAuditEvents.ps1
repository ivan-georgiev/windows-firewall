function Disable-FHFirewallAuditEvents {
  [CmdletBinding()]
  param(
    [Parameter()]
    [ValidateSet("FilteringPlatformConnection", "RuleLevelChanges")]
    [string] $Category = "FilteringPlatformConnection"
  )

  if ($Category -eq "FilteringPlatformConnection") {
    auditpol /set /subcategory:"Filtering Platform Connection" /success:disable  /failure:disable
    if ($LASTEXITCODE -ne 0 -or -not $?) {
      throw "auditpol error"
    }
    return
  }

  if ($Category -eq "RuleLevelChanges") {
    auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /Success:disable /Failure:disable
    if ($LASTEXITCODE -ne 0 -or -not $?) {
      throw "auditpol error"
    }
    return
  }
}
