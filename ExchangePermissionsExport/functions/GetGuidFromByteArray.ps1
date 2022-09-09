Function GetGuidFromByteArray
{
    
    [CmdletBinding()]
    param
    (
        [byte[]]$GuidByteArray
    )
    New-Object -TypeName guid -ArgumentList (, $GuidByteArray)

}

