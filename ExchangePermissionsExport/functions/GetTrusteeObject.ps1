Function GetTrusteeObject
{

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$TrusteeIdentity
        ,
        [string[]]$HRPropertySet
        ,
        [hashtable]$ObjectGUIDHash
        ,
        [hashtable]$DomainPrincipalHash
        ,
        [hashtable]$SIDHistoryHash
        ,
        [hashtable]$UnfoundIdentitiesHash
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        $ExchangeOrganizationIsInExchangeOnline
    )
    $trusteeObject = $(
        $AddToLookup = $null
        #Write-Verbose -Message "Getting Object for TrusteeIdentity $TrusteeIdentity"
        switch ($TrusteeIdentity)
        {
            { $UnfoundIdentitiesHash.ContainsKey($_) }
            {
                $null
                break
            }
            { $ObjectGUIDHash.ContainsKey($_) }
            {
                $ObjectGUIDHash.$($_)
                #Write-Verbose -Message 'Found Trustee in ObjectGUIDHash'
                break
            }
            { $DomainPrincipalHash.ContainsKey($_) }
            {
                $DomainPrincipalHash.$($_)
                #Write-Verbose -Message 'Found Trustee in DomainPrincipalHash'
                break
            }
            { $SIDHistoryHash.ContainsKey($_) }
            {
                $SIDHistoryHash.$($_)
                #Write-Verbose -Message 'Found Trustee in SIDHistoryHash'
                break
            }
            { $null -eq $TrusteeIdentity -or [string]::IsNullOrEmpty($TrusteeIdentity) }
            {
                $null
                break
            }
            Default
            {
                if ($ExchangeOrganizationIsInExchangeOnline -and $TrusteeIdentity -like '*\*')
                {
                    $null
                }
                else
                {
                    $splat = @{
                        Identity    = $TrusteeIdentity
                        ErrorAction = 'SilentlyContinue'
                    }
                    Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-Recipient @using:splat } -ErrorAction SilentlyContinue -OutVariable AddToLookup
                    if ($null -eq $AddToLookup)
                    {
                        Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-Group @using:splat } -ErrorAction SilentlyContinue -OutVariable AddToLookup
                    }
                    if ($null -eq $AddToLookup)
                    {
                        Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-User @using:splat } -ErrorAction SilentlyContinue -OutVariable AddToLookup
                    }
                }
            }
        }
    )
    #if we found a 'new' object add it to the lookup hashtables
    if ($null -ne $AddToLookup -and $AddToLookup.count -gt 0)
    {
        #Write-Verbose -Message "Found Trustee $TrusteeIdentity via new lookup"
        $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process { $ObjectGUIDHash.$($_.ExchangeGuid.Guid) = $_ } -ErrorAction SilentlyContinue
        #Write-Verbose -Message "ObjectGUIDHash Count is $($ObjectGUIDHash.count)"
        $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process { $ObjectGUIDHash.$($_.Guid.Guid) = $_ } -ErrorAction SilentlyContinue
        if ($TrusteeIdentity -like '*\*' -or $TrusteeIdentity -like '*@*')
        {
            $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process { $DomainPrincipalHash.$($TrusteeIdentity) = $_ } -ErrorAction SilentlyContinue
            #Write-Verbose -Message "DomainPrincipalHash Count is $($DomainPrincipalHash.count)"
        }
    }
    #if we found nothing, add the Identity to the UnfoundIdentitiesHash
    if ($null -eq $trusteeObject -and $null -ne $TrusteeIdentity -and -not [string]::IsNullOrEmpty($TrusteeIdentity) -and -not $UnfoundIdentitiesHash.ContainsKey($TrusteeIdentity))
    {
        $UnfoundIdentitiesHash.$TrusteeIdentity = $null
    }
    if ($null -ne $trusteeObject -and $trusteeObject.Count -ge 2)
    {
        #TrusteeIdentity is ambiguous.  Need to implement and AmbiguousIdentitiesHash for testing/reporting
        $trusteeObject = $null
    }
    $trusteeObject

}
