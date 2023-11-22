
function Get-FHFirewallTodayLogDetails {
  [CmdletBinding()]
  param()



  # result
  $blockedProgramsHashmap = @{}
  $exeResolutionErrors = $false

  # process log file if present
  try {
    #Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid
    # 2023-11-20 17:53:54 DROP TCP 192.168.10.30 34.120.208.123 61005 443 0 - 0 0 0 - - - SEND 11188
    # 2023-11-20 17:53:54 DROP TCP 192.168.10.30 34.120.208.123 61147 443 0 - 0 0 0 - - - SEND 11188

    $today = Get-Date -Format 'yyyy-MM-dd' -ErrorAction Stop
    $firewallLog = Get-Content -Path "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -ErrorAction Stop
    Write-Verbose -Message "Firewall log has [$(($firewallLog | Measure-Object).Count)] lines"

    # get running processes
    $processes = Get-Process -ErrorAction Stop | Select-Object -Property Id, Path, Parent, Company, Product
    $proccessHashmap = @{}
    foreach ($p in $processes) {
      [string]$processId = $p.Id
      $proccessHashmap.Add($processId, $p)
    }

    $lineNumber = -1
    foreach ($line in $firewallLog) {
      $lineNumber += 1
      # skip old rows, not from today
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
      if ($process -and $process.Path) {
        $processesExe = $process.Path
      } else {
        $exeResolutionErrors = $true
        $processesExe = $procId
      }

      # init hashmap item if not there
      if ($null -eq $blockedProgramsHashmap[$processesExe]) {
        $blockedProgramsHashmap[$processesExe] = [PSCustomObject]@{
          FullProcessDetails = $process
          BlockedIps         = [System.Collections.ArrayList] @()
        }
      }

      # add IP details
      $details = [PSCustomObject]@{
        BlockedDestinationIp = $dstIp
        Protocol             = $protocol
      }
      if ($blockedProgramsHashmap[$processesExe].BlockedIps.BlockedDestinationIp -notcontains $details.BlockedDestinationIp) {
        [void] $blockedProgramsHashmap[$processesExe].BlockedIps.Add( $details )
      }
    }

  } catch [System.Management.Automation.ItemNotFoundException] {
    Write-Warning -Message "Cannot get firewall log file content"
  } catch {
    Write-Error -Message "Error on line [$lineNumber]: [$line]" -ErrorAction Continue
    throw
  }

  if ($exeResolutionErrors) {
    Write-Warning -Message "Cannot resolve PID from firewall log for some exes, so PID is used instead"
  }
  # return
  $blockedProgramsHashmap
}
