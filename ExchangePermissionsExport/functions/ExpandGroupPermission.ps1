Function ExpandGroupPermission
{
    [CmdletBinding()]
    param
    (
        [psobject[]]$Permission
        ,
        $TargetMailbox
        ,
        [hashtable]$ObjectGUIDHash
        ,
        [hashtable]$SIDHistoryHash
        ,
        $excludedTrusteeGUIDHash
        ,
        [hashtable]$UnfoundIdentitiesHash
        ,
        $HRPropertySet
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        $dropExpandedParentGroupPermissions
        ,
        [switch]$UseExchangeCommandsInsteadOfADOrLDAP
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    $gPermissions = @($Permission | Where-Object -FilterScript { $_.TrusteeRecipientTypeDetails -like '*Group*' })
    $ngPermissions = @($Permission | Where-Object -FilterScript { $_.TrusteeRecipientTypeDetails -notlike '*Group*' -or $null -eq $_.TrusteeRecipientTypeDetails })
    if ($gPermissions.Count -ge 1)
    {
        $expandedPermissions = @(
            foreach ($gp in $gPermissions)
            {
                Write-Verbose -Message "Expanding Group $($gp.TrusteeObjectGUID)"
                #check if we have already expanded this group . . .
                switch ($script:ExpandedGroupsNonGroupMembershipHash.ContainsKey($gp.TrusteeObjectGUID))
                {
                    $true
                    {
                        #if so, get the terminal trustee objects from the expansion hashtable
                        $UserTrustees = $script:ExpandedGroupsNonGroupMembershipHash.$($gp.TrusteeObjectGUID)
                        Write-Verbose -Message "Previously Expanded Group $($gp.TrusteeObjectGUID) Members Count: $($userTrustees.count)"
                    }
                    $false
                    {
                        #if not, get the terminal trustee objects now
                        if ($UseExchangeCommandsInsteadOfADOrLDAP -eq $true)
                        {
                            $UserTrustees = @(GetGroupMemberExpandedViaExchange -Identity $gp.TrusteeObjectGUID -ExchangeSession $exchangeSession -hrPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryRecipientHash $SIDHistoryRecipientHash -UnFoundIdentitiesHash $UnfoundIdentitiesHash)
                        }
                        else
                        {
                            $UserTrustees = @(GetGroupMemberExpandedViaLocalLDAP -Identity $gp.TrusteeDistinguishedName -ExchangeSession $exchangeSession -hrPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryRecipientHash $SIDHistoryRecipientHash -UnfoundIdentitiesHash $UnfoundIdentitiesHash)
                        }
                        #and add them to the expansion hashtable
                        $script:ExpandedGroupsNonGroupMembershipHash.$($gp.TrusteeObjectGUID) = $UserTrustees
                        Write-Verbose -Message "Newly Expanded Group $($gp.TrusteeObjectGUID) Members Count: $($userTrustees.count)"
                    }
                }
                foreach ($u in $UserTrustees)
                {
                    $trusteeRecipient = $u
                    switch ($null -eq $trusteeRecipient)
                    {
                        $true
                        {
                            #no point in doing anything here
                        }#end $true
                        $false
                        {
                            if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                            {
                                $npeoParams = @{
                                    TargetMailbox              = $TargetMailbox
                                    TrusteeIdentity            = $trusteeRecipient.guid.guid
                                    TrusteeRecipientObject     = $trusteeRecipient
                                    TrusteeGroupObjectGUID     = $gp.TrusteeObjectGUID
                                    PermissionType             = $gp.PermissionType
                                    AssignmentType             = 'GroupMembership'
                                    SourceExchangeOrganization = $ExchangeOrganization
                                    IsInherited                = $gp.IsInherited
                                    ParentPermissionIdentity   = $gp.PermissionIdentity
                                }
                                NewPermissionExportObject @npeoParams
                            }
                        }#end $false
                    }#end switch
                }#end foreach (user)
            }#end foreach (permission)
        )#expandedPermissions
        if ($expandedPermissions.Count -ge 1)
        {
            #remove any self permissions that came in through expansion
            $expandedPermissions = @($expandedPermissions | Where-Object -FilterScript { $_.TargetObjectGUID -ne $_.TrusteeObjectGUID })
        }
        if ($dropExpandedParentGroupPermissions)
        {
            @($ngPermissions; $expandedPermissions)
        }
        else
        {
            @($ngPermissions; $gPermissions; $expandedPermissions)
        }
    }
    else
    {
        $permission
    }

}
