Function GetSendOnBehalfPermission
{
    
    #Get Delegate Users (NOTE: actual permissions are stored in the mailbox . . . so these are not true delegates just a likely correlation to delegates)
    [cmdletbinding()]
    param
    (
        $TargetMailbox
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        [hashtable]$ObjectGUIDHash
        ,
        [hashtable]$DomainPrincipalHash
        ,
        [hashtable]$excludedTrusteeGUIDHash
        ,
        [hashtable]$UnfoundIdentitiesHash
        ,
        $ExchangeOrganization
        ,
        $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    if ($null -ne $TargetMailbox.GrantSendOnBehalfTo -and $TargetMailbox.GrantSendOnBehalfTo.ToArray().count -ne 0)
    {
        #Write-Verbose -message "Target Mailbox has entries in GrantSendOnBehalfTo"
        $splat = @{
            Identity    = $TargetMailbox.guid.guid
            ErrorAction = 'Stop'
        }
        #Write-Verbose -Message "Getting Trustee Objects from GrantSendOnBehalfTo"
        #doing this in try/catch b/c we might find the recipient is no longer a mailbox . . .
        try
        {
            $sbTrustees = Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-Mailbox @using:splat | Select-Object -ExpandProperty GrantSendOnBehalfTo } -ErrorAction Stop
        }
        catch
        {
            $myerror = $_
            #if ($myerror.tostring() -like "*isn't a mailbox user.")
            #{$sbTrustees = @()}
            #else
            #{
            #throw($myerror)
            WriteLog -Message $myerror.tostring() -ErrorLog -Verbose -EntryType Failed
            $sbTrustees = @()
            #}
        }
        foreach ($sb in $sbTrustees)
        {
            $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $sb.objectguid.guid -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
            switch ($null -eq $trusteeRecipient)
            {
                $true
                {
                    $npeoParams = @{
                        TargetMailbox              = $TargetMailbox
                        TrusteeIdentity            = $sb.objectguid.guid
                        TrusteeRecipientObject     = $null
                        PermissionType             = 'SendOnBehalf'
                        AssignmentType             = 'Undetermined'
                        SourceExchangeOrganization = $ExchangeOrganization
                        IsInherited                = $false
                    }
                    NewPermissionExportObject @npeoParams
                }#end $true
                $false
                {
                    if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                    {
                        $npeoParams = @{
                            TargetMailbox              = $TargetMailbox
                            TrusteeIdentity            = $sb.objectguid.guid
                            TrusteeRecipientObject     = $trusteeRecipient
                            PermissionType             = 'SendOnBehalf'
                            AssignmentType             = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) { $null { 'Undetermined' } '*group*' { 'GroupMembership' } Default { 'Direct' } }
                            SourceExchangeOrganization = $ExchangeOrganization
                            IsInherited                = $false
                        }
                        NewPermissionExportObject @npeoParams
                    }
                }#end $false
            }#end switch
        }#end foreach
    }

}

