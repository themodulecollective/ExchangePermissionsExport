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
                $message = "Get Mailbox AutoMapped Users with Get-MailboxPermission -Owner -ReadFromDomainController"
                WriteLog -Message $message -EntryType Attempting
                $counter = 0
                $AutoMappedUsers = @(
                    Foreach ($isr in $InScopeRecipients)
                    {
                        $counter++
                        $message = 'Getting Mailbox Owner Object From Exchange Online AD'
                        $ProgressInterval = [int]($($InScopeRecipients.Count) * .01)
                        if ($InScopeRecipients.count -ge 100 -and $($counter) % $ProgressInterval -eq 0 )
                        {
                            Write-Progress -Activity $message -Status "Items processed: $($counter) of $($InScopeRecipients.Count)" -PercentComplete (($counter / $($InScopeRecipients.Count)) * 100)
                        }
                        $splat = @{Identity = $isr.exchangeguid.guid; ReadFromDomainController = $true; Owner = $true ;ErrorAction = 'SilentlyContinue'} 
                        $MailboxOwnerObject = $Null
                        $MailboxOwnerObject = Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-MailboxPermission @using:splat } -ErrorAction SilentlyContinue
                        If ($null -ne $MailboxOwnerObject -and $MailboxOwnerObject.DelegateListLink.count -ge 1)
                        {
                            $MailboxOwnerObject | Select-Object -property ExchangeGUID,@{n='msExchDelegateListLink';e={$_.DelegateListLink}}
                        }#end If
                    }#End Foreach
                )
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


    $counter = 0
    $AutoMappingHash = @{}
    Foreach ($u in $AutoMappedUsers)
    {
        $counter++
        $message = 'Generating hash of Automapped Users and AutoMappers...'
        $ProgressInterval = [int]($($AutoMappedUsers.Count) * .01)
        if ($AutoMappedUsers.count -ge 100 -and $($counter) % $ProgressInterval -eq 0)
        {
            Write-Progress -Activity $message -Status "Items processed: $($counter) of $($AutoMappedUsers.Count)" -PercentComplete (($counter / $($AutoMappedUsers.Count)) * 100)
        }
        switch ($script:OrganizationType)
        {
            'ExchangeOnPremises'
            {$AutoMappingHash.$([guid]::new($u.msExchMailboxGuid).guid) = $u.msExchDelegateListLink}
            'ExchangeOnline'
            {$AutoMappingHash.$($u.ExchangeGUID.guid) = $u.msExchDelegateListLink}
        }

    }#End Foreach
    $AutoMappingHash

}
