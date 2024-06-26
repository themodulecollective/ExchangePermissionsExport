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

    $PxPParams = @{
        ArrayToProcess             = @(1,2)
        CalculatedProgressInterval = 'Each'
        Activity                   = 'Get AutoMapping "Permissions" Process'
        Status                     = 'Step 1 of 2'
    }
    $PxPID = New-xProgress @PxPParams
    $CxPParams = @{
        ArrayToProcess             = @($AutoMappingHash.GetEnumerator())
        CalculatedProgressInterval = '1Percent'
        Activity                   = 'Get Recipient Object(s) for the Mapped Mailboxes'
        xParentIdentity            = $PxPID
    }
    $CxPID = New-xProgress @CxPParams
    Write-xProgress -Identity $PxPID
    $rawAutoMapping = @(
        foreach ($amu in $AutoMappingHash.getenumerator())
        {
            Write-xProgress -Identity $CxPID
            $targetRecipient = GetTrusteeObject -TrusteeIdentity $amu.name -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -UnfoundIdentitiesHash $UnFoundIdentitiesHash
            foreach ($v in $amu.value)
            {
                [PSCustomObject]@{
                    TargetMailbox = $targetRecipient
                    User          = $v
                }
            }
        }
    )
    Complete-xProgress -Identity $CxPID
    $CxPParams = @{
        ArrayToProcess             = @($rawAutoMapping)
        CalculatedProgressInterval = '1Percent'
        Activity                   = 'Get Recipient Object for the Mapping User and Get Permission Output Object'
        xParentIdentity            = $PxPID
    }
    $CxPID = New-xProgress @CxPParams
    Set-xProgress -Identity $PxPID -Status 'Step 2 of 2'
    Write-xProgress -Identity $PxPID
    foreach ($am in $rawAutoMapping)
    {
        Write-xProgress -Identity $CxPID
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
    Complete-xProgress -Identity $CxPID
    Complete-xProgress -Identity $PxPID
}
