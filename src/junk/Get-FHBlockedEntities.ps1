function Get-FHBlockedEntities {
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
    # per-exe report, exe is lower case
    $processesExe = $e.Application
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

        # check if already processed
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

      # Windows Firewall does not support filtering svchost provided services by Service name
      # They need to be authorized by svchost.exe and is All or None.
      # If in future that changes, this condition might be moved as -or condition to allow the WMI query
      # which shows exact Service behind PID
      if ($processDetails.Name -eq 'svchost' -and $processesExe -eq "c:\windows\system32\svchost.exe") {
        continue
      }

      # skip processed PIDS for WMI analysis
      if ($processedPIDs -contains $procId) {
        continue
      }
      [void] $processedPIDs.Add($procId)

      # check if PID is in Running processes hashmap, if yes Get-WmiObject can detect which service owns it
      # if there is more than one service configured with same exe
      $processDetails = $proccessHashmap[$procId]
      if (
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
      }
    }
  }

  # for exes part of a service, add all details and remove from other group
  foreach ($bs in $blockedServices) {
    $bs["ExecutableDetails"] = $blockedProgramsHashmap[$bs.ExePath]
  }
  foreach ($bs in $blockedServices) {
    $blockedProgramsHashmap.Remove($bs.ExePath)
  }

  # return
  [PSCustomObject]@{
    BlockedServicesList = $blockedServices
    BlockedProgramsList = $blockedProgramsHashmap.Values
    NextSearchTimestamp = ($eventsCount -gt 0) ? $blockedConnectionsEvents[0].TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") : $EventFilterStartTime
  }
}
