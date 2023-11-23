function Get-FHBlockedEntitiesBasedOnEventlog {
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
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" -and $_.BinaryPathName } | Select-Object -Property Name, DisplayName, BinaryPathName, Description
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

  # get running processes
  $processes = Get-Process -ErrorAction Stop | Select-Object -Property Id, Path, Parent, Company, Product, Name
  $proccessHashmap = @{}
  foreach ($p in $processes) {
    [string]$processId = $p.Id
    $proccessHashmap.Add($processId, $p)
  }

  # init result and helper collection
  $blockedServices = [System.Collections.ArrayList]@()
  $blockedProgramsHashmap = @{}
  $processedPIDs = [System.Collections.ArrayList]@()

  # get blocked connections
  $blockedConnectionsEvents = Get-FHTBlockedConnectionEvents -StartTime $EventFilterStartTime -ErrorAction Stop -Verbose
  $eventsCount = ($blockedConnectionsEvents | Measure-Object).Count
  Write-Verbose -Message "Fetched [$eventsCount] Firewall events from EventLog"

  foreach ($e in $blockedConnectionsEvents) {
    # per-exe report
    $processesExe = $e.Application.ToLower()
    [string] $procId = $e.ProcessId

    #Write-Verbose -Message "`n`nProcessing [$($e.ProcessId)-$processesExe-$($e.DestAddress)]"
    if ($null -eq $blockedProgramsHashmap[$processesExe]) {
      $blockedProgramsHashmap[$processesExe] = [PSCustomObject]@{
        ProcessesExe       = $processesExe
        BlockedIPs         = [System.Collections.ArrayList]@()
        AssociatedServices = $null
        Counter            = 0
      }
    }
    if ($blockedProgramsHashmap[$processesExe].BlockedIps -notcontains $e.DestAddress) {
      [void] $blockedProgramsHashmap[$processesExe].BlockedIps.Add( $e.DestAddress )
    }
    $blockedProgramsHashmap[$processesExe].Counter = ($blockedProgramsHashmap[$processesExe].Counter + 1)

    $associatedServices = $servicesHashmap[$processesExe]
    if ($associatedServices) {
      $blockedProgramsHashmap[$processesExe].AssociatedServices = $associatedServices

      # if single service has the exe, no need to analyze runtime
      if (($associatedServices | Measure-Object).Count -eq 1) {

        if (($blockedServices.Service) -contains $associatedServices[0] ) {
          continue
        }

        [void] $processedPIDs.Add($procId)
        [void] $blockedServices.Add(
          @{
            Service    = $associatedServices[0]
            BlockedIps = $e.DestAddress
            ExePath    = $processesExe
            PID        = $procId
            ParentPID  = $processDetails.Parent.Id
          }
        )
        continue
      }
      #Write-Verbose -Message "-- Found assocated service(s)"
    }

    # running processes WMI analysis
    # skip processed
    if ($processedPIDs -contains $procId) {
      continue
    }
    [void] $processedPIDs.Add($procId)

    # check if PID is in Running processes hashmap
    $processDetails = $proccessHashmap[$procId]
    if (
      ($processDetails.Name -eq 'svchost' -and $processesExe -eq "c:\windows\system32\svchost.exe") -or `
      ($processDetails.Path -and $processesExe -eq $processDetails.Path.ToLower())
    ) {
      Write-Verbose -Message "-- Blocked process is still running and WMI details will be taken to see if it is a service. Details: [$processDetails]"

      # PID is part of Service config, check which service exactly
      if ($associatedServices) {
        Write-Verbose -Message "Fetching WMI details for [$procId] associated with a service."
        $exactService = Get-WmiObject -Class Win32_Service -Filter "ProcessId='$procId'" -ErrorAction Stop | Select-Object -Property Name, DisplayName, Description, PathName
        Write-Verbose -Message "-- Related service details: [$exactService]"
        [void] $blockedServices.Add(
          @{
            Service    = $exactService
            BlockedIps = $e.DestAddress
            ExePath    = $processesExe
            PID        = $procId
            ParentPID  = $processDetails.Parent.Id
          }
        )
        continue
      }

      # if process is not part of a service, check if parent is
      if ($processDetails.Parent.Id -and "services" -ne $processDetails.Parent.Name) {
        $parentProcessDetails = $proccessHashmap[$processDetails.Parent.Id.ToString()]
        if ($parentProcessDetails.Path -and $servicesHashmap[$parentProcessDetails.Path.ToLower()]) {
          Write-Verbose -Message "Fetching WMI details for parent procces [$($processDetails.Parent.Id)] associated with a service."
          $exactService = Get-WmiObject -Class Win32_Service -Filter "ProcessId='$($processDetails.Parent.Id)'" -ErrorAction Stop | Select-Object -Property Name, DisplayName, Description, PathName
          [void] $blockedServices.Add(
            @{
              Service    = $exactService
              BlockedIps = $e.DestAddress
              ExePath    = $processesExe
              PID        = $procId
              ParentPID  = $processDetails.Parent.Id
            }
          )
        }
      }
    }
  }

  # for exes part of a service, add all details and remove from other group
  foreach ($bs in $blockedServices) {
    $bs["ExecutableDetails"] = $blockedProgramsHashmap[$bs.ExePath]
    $blockedProgramsHashmap.Remove($bs.ExePath)
  }

  # return
  [PSCustomObject]@{
    BlockedServicesList = $blockedServices
    BlockedProgramsList = $blockedProgramsHashmap.Values
    NextSearchTimestamp = ($eventsCount -gt 0) ? $blockedConnectionsEvents[0].TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") : $EventFilterStartTime
  }
}
