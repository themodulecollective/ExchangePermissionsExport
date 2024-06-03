Function GetCalendarPermission
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
        [hashtable]$DomainPrincipalHash
        ,
        [hashtable]$UnfoundIdentitiesHash
        ,
        $ExchangeOrganization
        ,
        $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    $Identity = $TargetMailbox.guid.guid
    $TargetFolderPath = '\Calendar'
    $splat = @{Identity = $Identity + ':' + $TargetFolderPath }
    $RawCalendarPermissions = @(
        try
        {
            Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-MailboxFolderPermission @using:splat } -ErrorAction Stop
        }
        catch
        {
            Write-Verbose -Message "Get-MailboxPermission threw an error with Identity $Identity.  Attempting to find localized folder name instead."
            try
            {
                $CalendarFolderName = Invoke-Command -ErrorAction Stop -Session $ExchangeSession -ScriptBlock {
                    Get-MailboxFolderStatistics -Identity $using:Identity
                } | Where-Object -FilterScript { $_.FolderType -eq 'Calendar' } | Select-Object -First 1 | Select-Object -ExpandProperty Name
                if ([string]::IsNullOrWhiteSpace($CalendarFolderName))
                {
                    Write-Verbose -Message "No Calendar Folder found for Identity $Identity"
                }
                else
                {
                    $TargetFolderPath = '/' + $CalendarFolderName
                    #try again with the localized folder name
                    $splat.Identity = $($Identity + ':' + $TargetFolderPath)
                    Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-MailboxFolderPermission @using:splat } -ErrorAction Stop
                }
            }
            catch
            {
                Write-Verbose -Message "Unresolved Error Retrieving Calendar Permissions for Identity $Identity"
            }
        }
    )
    #filter anon and default permissions
    $RawCalendarPermissions = @($RawCalendarPermissions.where({$_.User.UserType.Value -notin @('Default','Anonymous')}))
    #process the permissions for export
    foreach ($rcp in $RawCalendarPermissions)
    {
        switch ($script:OrganizationType)
        {
            'ExchangeOnline'
            {
                switch ($rcp.user.usertype.value)
                {
                    'Internal'
                    {
                        $user = $rcp.user.RecipientPrincipal # 2024-06-03 Micrsosoft changed the output of Get-MailboxFolderPermission!
                    }
                    'Unknown'
                    {
                        $user = $rcp.user.DisplayName
                    }
                    'External'
                    {
                        $user = $rcp.user.DisplayName
                    }
                }
            }
            'ExchangeOnPremises'
            {
                $user = $rfp.user
            }
        }
        $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $user -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -UnfoundIdentitiesHash $UnFoundIdentitiesHash
        $FolderAccessRights = $rcp.AccessRights -join '|'
        switch ($null -eq $trusteeRecipient)
        {
            $true
            {
                $npeoParams = @{
                    TargetMailbox              = $TargetMailbox
                    TrusteeIdentity            = $User
                    TrusteeRecipientObject     = $null
                    TargetFolderPath           = $TargetFolderPath
                    TargetFolderType           = 'Calendar'
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
                        TargetFolderType           = 'Calendar'
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
    }#end foreach rcp

}
