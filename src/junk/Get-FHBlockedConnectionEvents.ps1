function Get-FHTBlockedConnectionEvents {
  [CmdletBinding()]
  param(
    [Parameter()]
    [string] $StartTime = (Get-Date -Format 'yyyy-MM-dd')
  )

  # get \device\harddiskvolume to drive letter mapping
  $volumeDetailsRaw = & fltmc volumes
  if ($LASTEXITCODE -ne 0 -or -not $?) {
    throw "Error getting drive mapping"
  }
  $drivesMap = @{}
  foreach ($line in $volumeDetailsRaw) {
    if ($line -match '^([A-Z]:)\s+([\\A-Za-z0-9]+).*') {
      $drivesMap.Add($Matches[2].ToLower(), $Matches[1].ToUpper())
    }
  }

  # object to extract Event properties
  $selector = [System.Collections.Generic.List[string]]@(
    "Event/EventData/Data[@Name='ProcessID']",
    "Event/EventData/Data[@Name='Application']",
    "Event/EventData/Data[@Name='Direction']",
    "Event/EventData/Data[@Name='DestAddress']",
    "Event/EventData/Data[@Name='DestPort']",
    "Event/EventData/Data[@Name='Protocol']"
  )

  try {
    # get 5157 The Windows Filtering Platform has blocked a connection. events
    # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn311466(v=ws.11)
    $events = Get-WinEvent -FilterHashtable @{
      LogName   = 'Security'
      StartTime = "$StartTime"
      ID        = @(5157)
    } -ErrorAction Stop -Verbose:$false | Sort-Object -Property TimeCreated -Descending

  } catch {
    # if there are no events return $null
    if ($_.Exception.Message -eq "No events were found that match the specified selection criteria.") {
      Write-Verbose -Message "No Filtering Platform Connection events found."
      return
    } else {
      # raise other errors
      throw
    }
  }
  # result list
  $eventsList = [System.Collections.ArrayList]@()

  # get details from events
  foreach ($e in $events) {
    # extract properties as list
    $messageDetails = $e.GetPropertyValues($selector)

    # Get exe path and fix format: \device\harddiskvolume3\windows\system32\svchost.exe to C:\windows\system32\svchost.exe
    if ($messageDetails[1] -imatch '^(\\device\\harddiskvolume[0-9])(\\.+)$') {
      $exePath = $drivesMap[$Matches[1].ToLower()] + $Matches[2]
    } else {
      Write-Warning -Message "Cannot prase Application property of event [$($messageDetails[1])]. Skip."
      continue
    }

    # add to result
    [void] $eventsList.Add(
      [PSCustomObject]@{
        ProcessID   = $messageDetails[0]
        Application = $exePath
        # "%%14593" is Outbound
        Direction   = ($messageDetails[2] -eq "%%14593") ? "Outbound" : "Inbound"
        DestAddress = $messageDetails[3]
        DestPort    = $messageDetails[4]
        Protocol    = $messageDetails[5]
        TimeCreated = $e.TimeCreated
      })
  }

  # return, filter to contain only Outbound
  $eventsList | Where-Object -FilterScript { $_.Direction -eq "Outbound" }
}
