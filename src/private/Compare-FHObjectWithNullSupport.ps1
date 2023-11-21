function Compare-FHObjectWithNullSupport {
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [AllowEmptyCollection()]
    [string[]] $ReferenceObject,

    [Parameter()]
    [AllowNull()]
    [AllowEmptyCollection()]
    [string[]] $DifferenceObject
  )

  if ($null -eq $ReferenceObject) {
    return [PSCustomObject]@{
      New     = $DifferenceObject
      Deleted = $null
    }
  }

  if ($null -eq $DifferenceObject) {
    return [PSCustomObject]@{
      New     = $null
      Deleted = $ReferenceObject
    }
  }

  # Compare-Object impementation, not working
  #$diff = Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject -ErrorAction Stop
  #$new = $diff | Where-Object -Property SideIndicator -EQ ">=" | Select-Object -ExpandProperty InputObject -ErrorAction Stop
  #$deleted = $diff | Where-Object -Property SideIndicator -EQ "<=" | Select-Object -ExpandProperty InputObject -ErrorAction Stop

  $deleted = [System.Collections.ArrayList]@()
  $new = [System.Collections.ArrayList]@()
  foreach ($i in $ReferenceObject) {
    if ($DifferenceObject -notcontains $i) {
      [void] $deleted.Add($i)
    }
  }
  foreach ($i in $DifferenceObject) {
    if ($ReferenceObject -notcontains $i) {
      [void] $new.Add($i)
    }
  }


  return [PSCustomObject]@{
    New     = $new
    Deleted = $deleted
  }
}
