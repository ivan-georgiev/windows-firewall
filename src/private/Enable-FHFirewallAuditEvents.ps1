function Enable-FHFirewallAuditEvents {
  [CmdletBinding()]
  param(
    [Parameter()]
    [ValidateSet("FilteringPlatformConnection", "RuleLevelChanges", "All")]
    [string] $Category = "All"
  )

  Write-Verbose -Message "Configure Audit FilteringPlatformConnection"
  if (@("FilteringPlatformConnection", "All") -contains $Category) {
    $null = & auditpol /set /category:"System" /subcategory:"Filtering Platform Connection" /success:disable  /failure:enable
    if ($LASTEXITCODE -ne 0 -or -not $?) {
      throw "auditpol error"
    }
  }

  Write-Verbose -Message "Configure Audit RuleLevelChanges"
  if (@("RuleLevelChanges", "All") -contains $Category) {
    $null = & auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /Success:Enable /Failure:Enable
    if ($LASTEXITCODE -ne 0 -or -not $?) {
      throw "auditpol error"
    }
  }
}
