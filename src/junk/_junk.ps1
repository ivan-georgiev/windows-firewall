function Get-RulesToCreate {
  [CmdletBinding()]
  param ()

  # return
  @(
    {
      DisplayGroup = "Core Networking Diagnostics"
    },
    {
      DisplayGroup = "File and Printer Sharing"
    }
  )
}




