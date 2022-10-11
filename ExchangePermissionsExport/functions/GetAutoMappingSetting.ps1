Function GetAutoMappingSetting
{

    [cmdletbinding()]
    param
    (
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
        [hashtable]$AutoMappingHash
        ,
        $ExchangeOrganization
        ,
        $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference

    $rawAutoMapping = @(
        foreach ($amu in $AutoMappingHash.getenumerator())
        {

            $targetRecipient = GetTrusteeObject -TrusteeIdentity $amu.name  -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -UnfoundIdentitiesHash $UnFoundIdentitiesHash
            foreach ($v in $amu.value)
            {
                [PSCustomObject]@{
                    TargetMailbox = $targetRecipient
                    User = $v
                }
            }
        }
    )
    

    foreach ($am in $rawAutoMapping)
    {
        $user = $am.User
        $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $user -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -UnfoundIdentitiesHash $UnFoundIdentitiesHash
        switch ($null -eq $trusteeRecipient)
        {
            $true
            {
                $npeoParams = @{
                    TargetMailbox              = $am.TargetMailbox
                    TrusteeIdentity            = $User
                    TrusteeRecipientObject     = $null
                    PermissionType             = 'AutoMapping'
                    AssignmentType             = 'Undetermined'
                    IsInherited                = $null
                    IsAutoMapped               = $true
                    SourceExchangeOrganization = $ExchangeOrganization
                }
                NewPermissionExportObject @npeoParams
            }#end $true
            $false
            {
                if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                {
                    $npeoParams = @{
                        TargetMailbox              = $am.TargetMailbox
                        TrusteeIdentity            = $user
                        TrusteeRecipientObject     = $trusteeRecipient
                        PermissionType             = 'AutoMapping'
                        AssignmentType             = 'Direct'
                        IsInherited                = $null
                        IsAutoMapped               = $true
                        SourceExchangeOrganization = $ExchangeOrganization
                    }
                    NewPermissionExportObject @npeoParams
                }
            }#end $false
        }#end switch
    }#end foreach am

}
