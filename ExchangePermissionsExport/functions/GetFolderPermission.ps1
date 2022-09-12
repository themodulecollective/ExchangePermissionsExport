Function GetFolderPermission
{

    [cmdletbinding()]
    param
    (
        $TargetMailbox
        ,
        $TargetFolderIdentity
        ,
        $TargetFolderPath
        ,
        $TargetFolderType
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        [hashtable]$ObjectGUIDHash
        ,
        [hashtable]$excludedTrusteeGUIDHash
        ,
        [hashtable]$DomainPrincipalHash
        ,
        [hashtable]$UnfoundIdentitiesHash
        ,
        $ExchangeOrganization
        ,
        $ExchangeOrganizationIsInExchangeOnline
        ,
        $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    $splat = @{Identity = $TargetFolderIdentity}
    $RawFolderPermissions = @(
        try
        {
            Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-MailboxFolderPermission @using:splat } -ErrorAction Stop
        }
        catch
        {
            Write-Verbose -Message "Get-MailboxFolderPermission threw an error with Identity $Identity."
        }
    )
    #filter anon and default permissions
    $RawFolderPermissions = @($RawFolderPermissions | Where-Object -FilterScript { $_.User -notlike 'Anonymous' -and $_.User -notlike 'Default' })
    #process the permissions for export
    foreach ($rfp in $RawFolderPermissions)
    {
        switch ($ExchangeOrganizationIsInExchangeOnline)
        {
            $true
            {
                switch ($rfp.user.usertype.value)
                {
                    'Internal'
                    {
                        $user = $rfp.user.ADRecipient.guid.guid
                    }
                    'External'
                    {
                        $user = $rfp.user.DisplayName
                    }
                }
            }
            $false
            {
                $user = $rfp.user
            }
        }
        $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $user -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
        $FolderAccessRights = $rfp.AccessRights -join '|'
        switch ($null -eq $trusteeRecipient)
        {
            $true
            {
                $npeoParams = @{
                    TargetMailbox              = $TargetMailbox
                    TrusteeIdentity            = $User
                    TrusteeRecipientObject     = $null
                    TargetFolderPath           = $TargetFolderPath
                    TargetFolderType           = $TargetFolderType
                    FolderAccessRights         = $FolderAccessRights
                    PermissionType             = 'Folder'
                    AssignmentType             = 'Undetermined'
                    IsInherited                = $false
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
                        TrusteeIdentity            = $user
                        TrusteeRecipientObject     = $trusteeRecipient
                        TargetFolderPath           = $TargetFolderPath
                        TargetFolderType           = $TargetFolderType
                        FolderAccessRights         = $FolderAccessRights
                        PermissionType             = 'Folder'
                        AssignmentType             = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) { '*group*' { 'GroupMembership' } $null { 'Undetermined' } Default { 'Direct' } }
                        IsInherited                = $false
                        SourceExchangeOrganization = $ExchangeOrganization
                    }
                    NewPermissionExportObject @npeoParams
                }
            }#end $false
        }#end switch
    }#end foreach rfp

}
