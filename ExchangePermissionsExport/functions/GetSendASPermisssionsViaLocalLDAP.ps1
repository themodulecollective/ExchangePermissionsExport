Function GetSendASPermisssionsViaLocalLDAP
{

    [cmdletbinding()]
    param
    (
        $TargetMailbox
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        [hashtable]$ObjectGUIDHash
        ,
        [hashtable]$excludedTrusteeGUIDHash
        ,
        [bool]$dropInheritedPermissions
        ,
        [hashtable]$DomainPrincipalHash
        ,
        [hashtable]$UnfoundIdentitiesHash
        ,
        $ExchangeOrganization
        ,
        $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    #Well-known GUID for Send As Permissions, see function Get-SendASRightGUID
    $SendASRight = [GUID]'ab721a54-1e2f-11d0-9819-00aa0040529b'
    $userDN = [ADSI]("LDAP://$($TargetMailbox.DistinguishedName)")
    $saRawPermissions = @(
        $userDN.psbase.ObjectSecurity.Access | Where-Object -FilterScript { (($_.ObjectType -eq $SendASRight) -or ($_.ActiveDirectoryRights -eq 'GenericAll')) -and ($_.AccessControlType -eq 'Allow') } | Where-Object -FilterScript { $_.IdentityReference -notlike 'NT AUTHORITY\SELF' } | Select-Object identityreference, IsInherited
        # Where-Object -FilterScript {($_.identityreference.ToString().split('\')[0]) -notin $ExcludedTrusteeDomains}
        # Where-Object -FilterScript {$_.identityreference -notin $ExcludedTrustees}|
    )
    if ($dropInheritedPermissions -eq $true)
    {
        $saRawPermissions = @($saRawPermissions | Where-Object -FilterScript { $_.IsInherited -eq $false })
    }
    #Drop Self Permissions
    $saRawPermissions = @($saRawPermissions | Where-Object -FilterScript { $_.IdentityReference -ne 'NT AUTHORITY\SELF' })
    #Lookup Trustee Recipients and export permission if found
    foreach ($sa in $saRawPermissions)
    {
        $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $sa.IdentityReference -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -UnfoundIdentitiesHash $UnFoundIdentitiesHash
        switch ($null -eq $trusteeRecipient)
        {
            $true
            {
                $npeoParams = @{
                    TargetMailbox              = $TargetMailbox
                    TrusteeIdentity            = $sa.IdentityReference
                    TrusteeRecipientObject     = $null
                    PermissionType             = 'SendAs'
                    AssignmentType             = 'Undetermined'
                    IsInherited                = $sa.IsInherited
                    SourceExchangeOrganization = $ExchangeOrganization
                }
                NewPermissionExportObject @npeoParams
            }#end $true
            $false
            {
                if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                {
                    $npeoParams = @{
                        TargetMailbox              = $TargetMailbox
                        TrusteeIdentity            = $sa.IdentityReference
                        TrusteeRecipientObject     = $trusteeRecipient
                        PermissionType             = 'SendAs'
                        AssignmentType             = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) { $null { 'Undetermined' } '*group*' { 'GroupMembership' } Default { 'Direct' } }
                        IsInherited                = $sa.IsInherited
                        SourceExchangeOrganization = $ExchangeOrganization
                    }
                    NewPermissionExportObject @npeoParams
                }
            }#end $false
        }#end switch
    }#end foreach

}
