
function Create-FHFirewallRules {
  [CmdletBinding()]
  param(

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject] $RulesToCreateConfig,

    [Parameter()]
    [ValidateNotNull()]
    [string] $AdditionalConfigFile,

    [Parameter()]
    [switch] $DeleteIfExists,

    [Parameter()]
    [switch] $GetConfig,

    [Parameter()]
    [string[]] $Filter = @()
  )

  # run get config cmdlet if swith is passed
  if ($GetConfig.IsPresent) {
    $params = @{
      Filter = $Filter
    }
    if ($PSBoundParameters.ContainsKey('AdditionalConfigFile')) {
      $params.Add('AdditionalConfigFile', $AdditionalConfigFile)
    }
    $config = Get-FHRulesToCreateConfig @params -Verbose -ErrorAction Stop
    $commonParams = $config.CommonParams
    $rulesToCreate = $config.Rules
  } else {
    # used passed objet
    $commonParams = $RulesToCreateConfig.CommonParams
    $rulesToCreate = $RulesToCreateConfig.Rules
  }

  $servicesList = (Get-Service -ErrorAction SilentlyContinue).Name

  Write-Verbose -Message "Found [$(($rulesToCreate | Measure-Object).Count)] rules"
  foreach ($ruleParams in $rulesToCreate) {

    [hashtable] $params = Merge-FHHashtables -HashtableA $commonParams -HashtableB $ruleParams -ErrorAction Stop

    # do not create rules for non-existing Entities
    if ($params.Program -and $params.Program -ne "System") {
      try {
        $itemDetails = Get-Item -Path $params.Program -ErrorAction Stop
      } catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning -Message "File [$($params.Program)] not found. Skip rule."
        continue
      }
    }
    if ($params.Service) {
      if ($servicesList -notcontains $params.Service) {
        Write-Warning -Message "Service [$($params.Service)] not found. Skip rule."
        continue
      }
    }
    # TODO: App existence validation


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

      # https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure#create-an-inbound-program-or-service-rule
      # To use the Apply to this service or Apply to service with this service short name options, the service must be configured with a security identifier (SID) with a type of RESTRICTED or UNRESTRICTED.
      # If the result is NONE, then a firewall rule cannot be applied to that service.
      if ($params.Service) {
        $output = & sc qsidtype $params.Service
        if ($LASTEXITCODE -ne 0 -or -not $?) {
          throw "Cannot identify Service SID type"
        }
        # example: SERVICE_SID_TYPE:  NONE
        $lastRow = $output[-1]
        Write-Verbose -Message "Service SID type info: [$lastRow]"
        if ($output[-1].Contains("NONE")) {
          Write-Verbose -Message "Update SID type to Unrestricted"
          & sc sidtype $params.Service unrestricted
          if ($LASTEXITCODE -ne 0 -or -not $?) {
            throw "Cannot set Service SID type"
          }
        }
        $params.DisplayName = "FH-$($params.Service)"
      }
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
