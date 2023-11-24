function Enable-FHFirewallAuditEvents {
  [CmdletBinding()]
  param(
    [Parameter()]
    [ValidateSet("FilteringPlatformConnection", "RuleLevelChanges", "All")]
    [string] $Category = "All"
  )

  if (@("FilteringPlatformConnection", "All") -contains $Category) {
    & auditpol /set /category:"System" /subcategory:"Filtering Platform Connection" /success:disable  /failure:disable
    if ($LASTEXITCODE -ne 0 -or -not $?) {
      throw "auditpol error"
    }
    return
  }

  if (@("RuleLevelChanges", "All") -contains $Category) {
    & auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /Success:Enable /Failure:disable
    if ($LASTEXITCODE -ne 0 -or -not $?) {
      throw "auditpol error"
    }
    return
  }
}
