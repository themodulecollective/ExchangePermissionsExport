Function GetFullAccessPermission
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
    $splat = @{Identity = $TargetMailbox.guid.guid; ErrorAction = 'Stop' }
    $FilterScriptString = '($_.AccessRights -like "*FullAccess*") -and -not ($_.User -like "NT AUTHORITY\SELF") -and -not ($_.Deny -eq $True) -and -not ($_.User -like "S-1-5*")'
    $filterscript = [scriptblock]::Create($FilterScriptString)
    #doing this in try/catch b/c we might find the recipient is no longer a mailbox . . .
    try
    {
        $faRawPermissions = @(Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-MailboxPermission @using:splat } -ErrorAction Stop) | Where-Object -FilterScript $filterscript
    }
    catch
    {
        $myerror = $_
        #if ($myerror.tostring() -like "*isn't a mailbox user.")
        #{$faRawPermissions = @()}
        #else
        #{
        #throw($myerror)
        WriteLog -Message $myerror.tostring() -ErrorLog -Verbose -EntryType Failed
        $faRawPermissions = @()
        #}
    }

    #drop InheritedPermissions if requested
    if ($dropInheritedPermissions -eq $true)
    {
        $faRawPermissions = @($faRawPermissions | Where-Object -FilterScript { $_.IsInherited -eq $false })
    }
    foreach ($fa in $faRawPermissions)
    {
        $user = $fa.User
        $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $user -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
        switch ($null -eq $trusteeRecipient)
        {
            $true
            {
                $npeoParams = @{
                    TargetMailbox              = $TargetMailbox
                    TrusteeIdentity            = $User
                    TrusteeRecipientObject     = $null
                    PermissionType             = 'FullAccess'
                    AssignmentType             = 'Undetermined'
                    IsInherited                = $fa.IsInherited
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
                        PermissionType             = 'FullAccess'
                        AssignmentType             = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) { '*group*' { 'GroupMembership' } $null { 'Undetermined' } Default { 'Direct' } }
                        IsInherited                = $fa.IsInherited
                        SourceExchangeOrganization = $ExchangeOrganization
                    }
                    NewPermissionExportObject @npeoParams
                }
            }#end $false
        }#end switch
    }#end foreach fa

}

