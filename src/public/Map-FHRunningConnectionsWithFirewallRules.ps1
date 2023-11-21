
function Map-FHRunningConnectionsWithFirewallRules {
  [CmdletBinding()]
  param()

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
      $binary = "$binary.exe"

      if ($null -eq $servicesHashmap[$binary]) {
        $servicesHashmap.Add($binary, [System.Collections.ArrayList]@())
      }
      [void] $servicesHashmap[$binary].Add($svc)
    }
  }

  # process log file if present
  try {
    #Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid
    # 2023-11-20 17:53:54 DROP TCP 192.168.10.30 34.120.208.123 61005 443 0 - 0 0 0 - - - SEND 11188
    # 2023-11-20 17:53:54 DROP TCP 192.168.10.30 34.120.208.123 61147 443 0 - 0 0 0 - - - SEND 11188

    $today = Get-Date -Format 'yyyy-MM-dd' -ErrorAction Stop
    $firewallLog = Get-Content -Path "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -ErrorAction Stop
    Write-Verbose -Message "Firewall log has [$(($firewallLog | Measure-Object).Count)] lines"
    $blockedProgramsHashmap = @{}
    foreach ($line in $firewallLog) {
      # skip old rows
      if (-not $line.Contains("$today ")) {
        continue
      }
      # skip inbound
      if (-not $line.Contains(" SEND ")) {
        continue
        # skip not DROP events if any
      }
      if (-not $line.Contains(" DROP ")) {
        continue
      }

      # parse line
      $lineSplit = $line -split " "
      $protocol = $lineSplit[3]
      $dstIp = $lineSplit[5]
      $procId = $lineSplit[-1]

      # resolve exe from pid
      $process = $proccessHashmap[$procId]
      if ($process) {
        $processesExe = $process.Path
      } else {
        Write-Warning -Message "Cannot resolve PID from firewall log"
      }

      if ($null -eq $blockedProgramsHashmap[$processesExe]) {
        $blockedProgramsHashmap[$processesExe] = [PSCustomObject]@{
          FullProcessDetails = $process
          BlockedIps         = [System.Collections.ArrayList] @()
        }
      }

      [void] $blockedProgramsHashmap[$processesExe].BlockedIps.Add( [PSCustomObject]@{
          BlockedDestinationIp = $dstIp
          Protocol             = $protocol
        })
    }

  } catch {
    Write-Warning -Message "Cannot get firewall log file content"
  }
  Write-Verbose -Message "Blocked exes based on Firewall log: [$($blockedProgramsHashmap | ConvertTo-Json -Depth 5)]"


  # get firewall details
  try {
    $entities = Get-Content -Path "Baseline-$activeProfile-latest.json" -ErrorAction Stop | ConvertFrom-Json -Depth 5 -AsHashtable -ErrorAction Stop
  } catch {
    $entities = Get-FHFirewallAuthorizedEntities -NetworkProfileName $activeProfile -ErrorAction Stop -Verbose
  }

  # review active connections and provide details
  $activeConnectionsV4 = Get-NetTCPConnection -AppliedSetting "Internet" -ErrorAction Stop | Where-Object -FilterScript {
    $_.LocalAddress -notlike '*:*' -and
    $_.RemoteAddress -notlike "0.0.0.0" -and
    $_.RemoteAddress -notlike "127.0.0.1"
  } | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State -ErrorAction Stop

  foreach ($conn in  $activeConnectionsV4) {
    [string]$processId = $conn.OwningProcess
    $processDetails = $proccessHashmap[$processId]
    Write-Verbose -Message "Target [$($conn.RemoteAddress)] in State [$($conn.State)] open by [$processDetails]"
    if ($processDetails.Parent -and "services" -ne $processDetails.Parent.Name ) {
      Write-Verbose -Message "-- Parent details: [$($proccessHashmap[$processDetails.Parent.Id.ToString()])]"
    }

    #
    $relatedService = $servicesHashmap[$processDetails.Path]
    if ($relatedService) {
      $exactService = Get-WmiObject -Class Win32_Service -Filter "ProcessId='$processId'" -ErrorAction Stop | Select-Object -Property Name, DisplayName, Description, PathName
      Write-Verbose -Message "-- Related service details: [$exactService]"

      $rules = $entities.AuthorizedServices[$exactService.Name].Rules
      if ($rules) {
        Write-Verbose -Message "-- Related service rules details: [$rules]"
      } else {
        Write-Verbose -Message "-- No firewall rules found for service [$($exactService.Name)]."
      }
    }
    $exePath = $processDetails.Path
    $rules = $entities.AuthorizedExes[$exePath].Rules
    if ($rules) {
      Write-Verbose -Message "-- Related exe rules for [$exePath] details: [$rules]"
    } else {
      Write-Verbose -Message "-- No exe rules found for exe [$exePath]"
    }

    Write-Verbose -Message "`n`n"
  }

}
