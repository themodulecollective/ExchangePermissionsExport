Function GetGroupMemberExpandedViaLocalLDAP
{

    [CmdletBinding()]
    param
    (
        [string]$Identity #distinguishedName
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        $hrPropertySet
        ,
        $ObjectGUIDHash
        ,
        $DomainPrincipalHash
        ,
        $SIDHistoryRecipientHash
        ,
        [hashtable]$UnfoundIdentitiesHash
        ,
        $ExchangeOrganizationIsInExchangeOnline
    )
    if (-not (Test-Path -Path variable:script:dsLookFor))
    {
        #enumerate groups: http://stackoverflow.com/questions/8055338/listing-users-in-ad-group-recursively-with-powershell-script-without-cmdlets/8055996#8055996
        $script:dse = [ADSI]'LDAP://Rootdse'
        $script:dn = [ADSI]"LDAP://$($script:dse.DefaultNamingContext)"
        $script:dsLookFor = New-Object System.DirectoryServices.DirectorySearcher($script:dn)
        $script:dsLookFor.SearchScope = 'subtree'
    }
    $script:dsLookFor.Filter = "(&(memberof:1.2.840.113556.1.4.1941:=$($Identity))(objectCategory=user))"
    Try
    {
        $OriginalErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        $TrusteeUserObjects = @($dsLookFor.findall())
        $ErrorActionPreference = $OriginalErrorActionPreference
    }
    Catch
    {
        $myError = $_
        $ErrorActionPreference = $OriginalErrorActionPreference
        $TrusteeUserObjects = @()
        WriteLog -Message $myError.tostring() -ErrorLog -EntryType Failed -Verbose
    }

    foreach ($u in $TrusteeUserObjects)
    {
        $TrusteeIdentity = $(GetGuidFromByteArray -GuidByteArray $($u.Properties.objectguid)).guid
        $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $TrusteeIdentity -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
        if ($null -ne $trusteeRecipient)
        { $trusteeRecipient }
    }

}
