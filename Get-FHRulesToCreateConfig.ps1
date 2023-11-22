function Get-FHRulesToCreateConfig {
  [CmdletBinding()]
  param ()

  # return
  [PSCustomObject]@{
    CommonParams = @{
      Enabled      = "True"
      PolicyStore  = "PersistentStore"
      Direction    = "Outbound"
      Action       = "Allow"
      Group        = "FirewallHelper"
      Profile      = "Any"
      LocalAddress = "Any"
      LocalPort    = "Any"
      Protocol     = "Any"
    }

    Rules        = @(
      @{
        DisplayName   = "FH-LocalNetwork"
        Description   = "Enabled LocalNetwork Traffic"
        RemoteAddress = @(
          "LocalSubnet4", "DNS4", "DHCP4", "WINS4", "DefaultGateway4", "Intranet4", "PlayToDevice4"
        )
        RemotePort    = "Any"
        # Service       = $null
        # Program       = $null
        # Package       = $null
      },
      @{
        DisplayName   = "FH-Firefox"
        Description   = "Allow Firefox browser"
        RemoteAddress = "Any"
        RemotePort    = "Any"
        Program       = "C:\Program Files\Mozilla Firefox\firefox.exe"
      },
      @{
        DisplayName   = "FH-Chrome"
        Description   = "Allow Chrome browser"
        RemoteAddress = "Any"
        RemotePort    = "Any"
        Program       = "C:\Program Files\Google\Chrome\Application\chrome.exe"
      },
      @{
        DisplayName   = "FH-uTorrent"
        Description   = "Allow uTorrent browser"
        RemoteAddress = "Any"
        RemotePort    = "Any"
        Program       = "C:\Program Files (x86)\uTorrent\uTorrent.exe"
      },
      @{
        DisplayName   = "FH-VSCode"
        Description   = "Allow VSCode"
        RemoteAddress = "Any"
        RemotePort    = "Any"
        Program       = "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe"
      },
      @{
        DisplayName   = "FH-BingWallpaper"
        Description   = "Allow VSCode"
        RemoteAddress = "Any"
        RemotePort    = "Any"
        Program       = "$env:LOCALAPPDATA\Microsoft\BingWallpaperApp\BingWallpaperApp.exe"
      },
      @{
        DisplayName   = "FH-pwsh-7"
        Description   = "Allow VSCode"
        RemoteAddress = "Any"
        RemotePort    = "Any"
        Program       = "C:\Program Files\PowerShell\7\pwsh.exe"
      }
    )
  }
}
