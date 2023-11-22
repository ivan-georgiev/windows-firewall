
function Create-FHFirewallRules {
  [CmdletBinding()]
  param(

    [Parameter()]
    [PSCustomObject] $RulesToCreateConfig,

    [Parameter()]
    [switch] $DeleteIfExists
  )

  $commonParams = $RulesToCreateConfig.CommonParams
  $rulesToCreate = $RulesToCreateConfig.Rules

  foreach ($ruleParams in $rulesToCreate) {
    $params = Merge-FHHashtables -HashtableA $commonParams -HashtableB $ruleParams -ErrorAction Stop
    $params.Name = $params.DisplayName
    Write-Verbose -Message "Params: [$($params | ConvertTo-Json -Depth 1)]"
    try {

      if ($DeleteIfExists.IsPresent) {
        Get-NetFirewallRule -Name $params.Name -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.Group -eq $params.Group } | Remove-NetFirewallRule -ErrorAction Stop -Confirm:$false
      }
      New-NetFirewallRule @params -ErrorAction Stop
    } catch [Microsoft.Management.Infrastructure.CimException] {
      #$_.Exception.GetType().FullName
      if ("AlreadyExists" -eq $_.Exception.NativeErrorCode) {
        Write-Warning -Message "Rule already exists. Add force flag to delete before create."
        continue
      }
      # raise all other errors
      throw
    }
  }
}
