function Show-FHRealtimeBlockedConnectionEvents {
  [CmdletBinding()]
  param(
    [Parameter()]
    [Int16] $MaxIterations = 10,

    [Parameter()]
    [Int16] $TimeoutInSeconds = 15
  )

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

  $EventFilterStartTime = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

  foreach ($_ in (0..$MaxIterations)) {
    $result = Get-FHBlockedExes -ServicesHashtable $servicesHashmap -EventFilterStartTime $EventFilterStartTime -ErrorAction Stop -Verbose
    if (($result.BlockedProgramsList | Measure-Object).Count -gt 0) {
      Write-Verbose -Message "$($result.BlockedProgramsList | Select-Object -Property ProcessesExe, BlockedIPs, Counter  | ConvertTo-Json -Depth 2)"
      $EventFilterStartTime = $result.NextSearchTimestamp
    }
    Start-Sleep -Seconds $TimeoutInSeconds
  }
}
