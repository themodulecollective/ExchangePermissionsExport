Function GetArrayIndexForIdentity
{
    
    [cmdletbinding()]
    param(
        [parameter(mandatory = $true)]
        $array #The array for which you want to find a value's index
        ,
        [parameter(mandatory = $true)]
        $value #The Value for which you want to find an index
        ,
        [parameter(Mandatory)]
        $property #The property name for the value for which you want to find an index
    )
    Write-Verbose -Message 'Using Property Match for Index'
    [array]::indexof(($array.$property).guid, $value)

}

