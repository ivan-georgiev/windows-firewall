
function Show-FHActiveConnectionsRulesDetails {
  [CmdletBinding()]
  param(
    [Parameter()]
    [switch] $UseBaselineReportFile
  )

  $activeProfile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile
  Write-Verbose -Message "Active network profile: [$activeProfile]"

  # get running processes
  $processes = Get-Process -ErrorAction Stop | Select-Object -Property Id, Path, Parent, Company, Product
  $proccessHashmap = @{}
  foreach ($p in $processes) {
    [string]$processId = $p.Id
    $proccessHashmap.Add($processId, $p)
  }

  # get running services
  $services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" -and $_.BinaryPathName } | Select-Object -Property Name, DisplayName, BinaryPathName
  $servicesHashmap = @{}
  foreach ($svc in $services) {
    $binaryRaw = $svc.BinaryPathName
    if ($binaryRaw) {
      $binary = (($binaryRaw.Trim('"')) -split ".exe")[0]
      $binary = "$binary.exe".ToLower()

      if ($null -eq $servicesHashmap[$binary]) {
        $servicesHashmap.Add($binary, [System.Collections.ArrayList]@())
      }
      [void] $servicesHashmap[$binary].Add($svc)
    }
  }

  # get firewall details
  $entities = $null
  if ($UseBaselineReportFile.IsPresent) {
    try {
      $entities = Get-Content -Path "Baseline-$activeProfile-latest.json" -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
      Write-Warning -Message "Error getting baseline file content [$($_.Exception.Message)]. Generate new baseline report."
      $null = Create-FHBaselineReport -NetworkProfileName $activeProfile -ErrorAction Stop
      # get baseline content
      $entities = Get-Content -Path "Baseline-$activeProfile-latest.json" -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
    }
  }
  if ($null -eq $entities) {
    Write-Verbose -Message "Baseline file not detected. Get enitities dynamically"
    $entities = Get-FHFirewallAuthorizedEntities -NetworkProfileName $activeProfile -ErrorAction Stop -Verbose
  }

  # review active connections and provide details
  $activeConnectionsV4 = Get-NetTCPConnection -AppliedSetting "Internet" -ErrorAction Stop | Where-Object -FilterScript {
    $_.LocalAddress -notlike '*:*' -and
    $_.RemoteAddress -notlike "0.0.0.0" -and
    $_.RemoteAddress -notlike "127.0.0.1"
  } | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State -ErrorAction Stop

  foreach ($conn in  $activeConnectionsV4) {
    try {
      # get process Id of the network connection
      [string] $processId = $conn.OwningProcess
      # get process details from process hashmap
      $processDetails = $proccessHashmap[$processId]
      Write-Verbose -Message "Target [$($conn.RemoteAddress)] in State [$($conn.State)] open by [$processDetails]"

      if (-not $processDetails.Path) {
        Write-Warning -Message "Process does not have Path property and cannot be analyzed. Continue."
        continue
      }

      # print parent details if availalbe
      if ($processDetails.Parent -and "services" -ne $processDetails.Parent.Name) {
        $parentProcessId = $processDetails.Parent.Id.ToString()
        Write-Verbose -Message "-- Parent details: [$($proccessHashmap[$parentProcessId])]"
      }

      # check if exe is part of a service, use service hashmap to improve speed
      $relatedService = $servicesHashmap[$processDetails.Path]
      if ($relatedService) {
        $exactService = Get-WmiObject -Class Win32_Service -Filter "ProcessId='$processId'" -ErrorAction Stop | Select-Object -Property Name, DisplayName, Description, PathName
        Write-Verbose -Message "-- Related service details: [$exactService]"
        # lookup rules related to this service
        $rules = $entities.AuthorizedServices[$exactService.Name].Rules
        if ($rules) {
          Write-Verbose -Message "-- Related service rules details: [$rules]"
        } else {
          Write-Verbose -Message "-- No firewall rules found for service [$($exactService.Name)]."
        }
      }

      # lookup for rules for the exe
      $exePath = $processDetails.Path
      $rules = $entities.AuthorizedExes[$exePath].Rules
      if ($rules) {
        Write-Verbose -Message "-- Related exe rules for [$exePath] details: [$rules]"
      } else {
        Write-Verbose -Message "-- No exe rules found for exe [$exePath]"
      }

      Write-Verbose -Message "`n`n"
    } catch {
      Write-Error -Message "Exception [$($_.Message)] during processing connection [$conn]" -ErrorAction Continue
    }
  }
}
