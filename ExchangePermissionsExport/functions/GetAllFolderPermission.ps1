Function GetAllFolderPermission
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
        $ExchangeOrganizationIsInExchangeOnline
        ,
        $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    $Identity = $TargetMailbox.guid.guid
    $splat = @{Identity = $Identity; FolderScope = 'All' }
    $AllFolders = @(
        try
        {
            Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-MailboxFolderStatistics @using:splat } -ErrorAction Stop
        }
        catch
        {
            Write-Verbose -Message "Get-MailboxFolderStatistics threw an error with Identity $Identity."

        }
    )
    foreach ($f in $AllFolders)
    {
        $gfpParams = @{
            TargetMailbox                          = $TargetMailbox
            TargetFolderIdentity                   = $Identity + ':' + $($f.FolderID)
            TargetFolderPath                       = $f.FolderPath
            TargetFolderType                       = $f.FolderType
            ExchangeSession                        = $ExchangeSession
            ObjectGUIDHash                         = $ObjectGUIDHash
            excludedTrusteeGUIDHash                = $excludedTrusteeGUIDHash
            DomainPrincipalHash                    = $DomainPrincipalHash
            UnFoundIdentitiesHash                  = $UnfoundIdentitiesHash
            ExchangeOrganization                   = $ExchangeOrganization
            ExchangeOrganizationIsInExchangeOnline = $ExchangeOrganizationIsInExchangeOnline
            HRPropertySet                          = $HRPropertySet
        }
        GetFolderPermission @gfpParams
    }
}