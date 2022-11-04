Function GetAutoMappingHash
{
    [outputtype([hashtable])]
    [cmdletbinding()]
    param
    (
        [parameter()]
        $ActiveDirectoryDrive
        ,
        [psobject[]]$InScopeRecipients
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
    )#End param

    Try
    {

        switch ($script:OrganizationType)
        {
            'ExchangeOnPremises'
            {
                Push-Location
                WriteLog -Message 'Operation: Retrieve Mapping for all user objects with msExchDelegateListLink.'
                #Region Get user object with msExchdelegateListLink
                Set-Location $($ActiveDirectoryDrive.Name + ':\') -ErrorAction Stop
                $message = "Get AD Users with msExchDelegateListLink from AD Drive $($activeDirectoryDrive.Name)"
                WriteLog -Message $message -EntryType Attempting
                $AutoMappedUsers = @(Get-Aduser -ldapfilter '(&(legacyExchangeDN=*)(msExchDelegateListLink=*))' -Properties msExchMailboxGuid,msExchDelegateListLink -ErrorAction Stop)
                Pop-Location
                #EndRegion msExchdelegateListLink
            }
            'ExchangeOnline'
            {
                $message = 'Get Mailbox AutoMapped Users with Get-MailboxPermission -Owner -ReadFromDomainController'
                WriteLog -Message $message -EntryType Attempting
                #Set up progress bar
                $iXPParams = @{
                    ArrayToProcess             = $InScopeRecipients
                    CalculatedProgressInterval = '1Percent'
                    Activity                   = 'Collect Automapping for In Scope Recipients'
                }
                $xProgressID = New-xProgress @iXPParams
                $AutoMappedUsers = @(
                    Foreach ($isr in $InScopeRecipients)
                    {
                        Write-xProgress -Identity $xProgressID
                        $splat = @{Identity = $isr.exchangeguid.guid; ReadFromDomainController = $true; Owner = $true ;ErrorAction = 'SilentlyContinue'}
                        $MailboxOwnerObject = $Null
                        $MailboxOwnerObject = Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-MailboxPermission @using:splat } -ErrorAction SilentlyContinue
                        If ($null -ne $MailboxOwnerObject -and $MailboxOwnerObject.DelegateListLink.count -ge 1)
                        {
                            $MailboxOwnerObject | Select-Object -Property ExchangeGUID,@{n='msExchDelegateListLink';e= {$_.DelegateListLink}}
                        }#end If
                    }#End Foreach
                )
                Complete-xProgress -Identity $xProgressID
            }
        }
        WriteLog -Message $message -EntryType Succeeded
        WriteLog -Message "Got $($AutoMappedUsers.count) Users from AD" -EntryType Notification
    }
    Catch
    {
        $myError = $_
        WriteLog -Message $message -EntryType Failed -ErrorLog
        WriteLog -Message $myError.tostring() -ErrorLog
        throw("Failed: $Message")
    }


    $iXPParams = @{
        ArrayToProcess             = $InScopeRecipients
        CalculatedProgressInterval = '1Percent'
        Activity                   = 'Generating hash of Automapped Users and AutoMappers...'
    }
    $xProgressID = New-xProgress @iXPParams

    $AutoMappingHash = @{}
    Foreach ($u in $AutoMappedUsers)
    {
        Write-xProgress -Identity $xProgressID
        switch ($script:OrganizationType)
        {
            'ExchangeOnPremises'
            {$AutoMappingHash.$([guid]::new($u.msExchMailboxGuid).guid) = $u.msExchDelegateListLink}
            'ExchangeOnline'
            {$AutoMappingHash.$($u.ExchangeGUID.guid) = $u.msExchDelegateListLink}
        }

    }#End Foreach
    Complete-xProgress -Identity $xProgressID
    $AutoMappingHash
}
