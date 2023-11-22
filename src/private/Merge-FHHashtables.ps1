function Merge-FHHashtables {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [hashtable] $HashtableA,

    [Parameter(Mandatory)]
    [hashtable] $HashtableB
  )

  $result = @{}

  foreach ($item in $HashtableA.GetEnumerator()) {
    $result[$item.key] = $item.Value
  }
  foreach ($item in $HashtableB.GetEnumerator()) {
    $result[$item.key] = $item.Value
  }

  $result
}
