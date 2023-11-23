
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

    [hashtable] $params = Merge-FHHashtables -HashtableA $commonParams -HashtableB $ruleParams -ErrorAction Stop

    # remove comments
    $params.Remove("Comment")

    # create DisplayName
    if (-not $params.DisplayName) {
      if ($params.Program) {
        $params.DisplayName = "FH-" + (Covert-FHStringToSha1 -InputString $params.Program) + "-" + ($params.Program -split '\\')[-1]
      }
      if ($params.Service) {
        $params.DisplayName = "FH-$($params.Service)"
      }
      if ($params.Package) {
        Write-Error -Message "Package rules must have DisplayName property. Skip." -ErrorAction Continue
        continue
      }
    }
    # Set Name to DisplayName to prevent duplication
    $params.Name = $params.DisplayName

    #Write-Verbose -Message "Params: [$($params | ConvertTo-Json -Depth 1)]"
    try {
      if ($DeleteIfExists.IsPresent) {
        Get-NetFirewallRule -Name $params.Name -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.Group -eq $params.Group } | Remove-NetFirewallRule -ErrorAction Stop -Confirm:$false
      }
      Write-Verbose -Message "Creating rule [$($params.Name)]"
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
