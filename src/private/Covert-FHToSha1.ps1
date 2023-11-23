function Covert-FHStringToSha1 {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [string] $InputString
  )

  $stringAsStream = [System.IO.MemoryStream]::new()
  $writer = [System.IO.StreamWriter]::new($stringAsStream)
  $writer.write($InputString)
  $writer.Flush()
  $stringAsStream.Position = 0
  Get-FileHash -InputStream $stringAsStream -Algorithm SHA1 | Select-Object -ExpandProperty Hash
}
