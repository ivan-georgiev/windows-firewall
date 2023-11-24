function Get-FHBlockedExes {
  [CmdletBinding()]
  param(
    [Parameter()]
    [hashtable] $ServicesHashtable,

    [Parameter()]
    [string] $EventFilterStartTime = (Get-Date -Format 'yyyy-MM-dd')
  )

  if ($PSBoundParameters.ContainsKey('ServicesHashtable')) {
    $servicesHashmap = $ServicesHashtable
  } else {
    # get running services
    $services = Get-Service -ErrorAction SilentlyContinue |`
      Where-Object -FilterScript { $_.BinaryPathName } | `
      Select-Object -Property Name, DisplayName, BinaryPathName, Description
    $servicesHashmap = @{}
    foreach ($svc in $services) {
      $binaryRaw = $svc.BinaryPathName
      if ($binaryRaw) {
        $binary = (($binaryRaw.Trim('"')) -split ".exe")[0]
        $binary = "$binary.exe".ToLower()
        $svc | Add-Member  -MemberType NoteProperty -Name "Path" -Value $binary -ErrorAction Stop
        if ($null -eq $servicesHashmap[$binary]) {
          $servicesHashmap.Add($binary, [System.Collections.ArrayList]@())
        }
        [void] $servicesHashmap[$binary].Add($svc)
      }
    }
  }

  # init result
  $blockedProgramsHashmap = @{}

  # get blocked connections
  $blockedConnectionsEvents = Get-FHTBlockedConnectionEvents -StartTime $EventFilterStartTime -ErrorAction Stop -Verbose
  $eventsCount = ($blockedConnectionsEvents | Measure-Object).Count
  Write-Verbose -Message "Fetched [$eventsCount] Firewall events from EventLog"

  foreach ($e in $blockedConnectionsEvents) {
    # per-exe report, exe is lower case
    $processesExe = $e.Application
    [string] $procId = $e.ProcessId

    # init exe details if not in collection
    if ($null -eq $blockedProgramsHashmap[$processesExe]) {
      $blockedProgramsHashmap[$processesExe] = [PSCustomObject]@{
        ProcessesExe       = $processesExe
        BlockedIPs         = [System.Collections.ArrayList]@()
        AssociatedServices = $null
        Counter            = 0
      }
    }
    # add IP details, if not there yet
    if ($blockedProgramsHashmap[$processesExe].BlockedIps -notcontains $e.DestAddress) {
      [void] $blockedProgramsHashmap[$processesExe].BlockedIps.Add( $e.DestAddress )
    }
    # events counter increment
    $blockedProgramsHashmap[$processesExe].Counter = ($blockedProgramsHashmap[$processesExe].Counter + 1)
    # add service details if available
    $blockedProgramsHashmap[$processesExe].AssociatedServices = $servicesHashmap[$processesExe]

    # check if any services are associated with the exe
    $associatedServices = $servicesHashmap[$processesExe]
    if ($associatedServices) {
      $blockedProgramsHashmap[$processesExe].AssociatedServices = $associatedServices
    }
  }

  # return
  [PSCustomObject]@{
    BlockedProgramsList = $blockedProgramsHashmap.Values
    NextSearchTimestamp = ($eventsCount -gt 0) ? $blockedConnectionsEvents[0].TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") : $EventFilterStartTime
  }
}
