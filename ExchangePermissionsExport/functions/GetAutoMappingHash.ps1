Function GetAutoMappingHash
{
    [outputtype([hashtable])]
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $ActiveDirectoryDrive
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
    )#End param

    Push-Location
    WriteLog -Message 'Operation: Retrieve Mapping for all user objects with msExchDelegateListLink.'

    #Region Get user object with msExchdelegateListLink
    Set-Location $($ActiveDirectoryDrive.Name + ':\') -ErrorAction Stop
    Try
    {
        $message = "Get AD Users with msExchDelegateListLink from AD Drive $($activeDirectoryDrive.Name)"
        WriteLog -Message $message -EntryType Attempting
        $AutoMappedUsers = @(Get-Aduser -ldapfilter '(&(legacyExchangeDN=*)(msExchDelegateListLink=*))' -Properties msExchMailboxGuid,msExchDelegateListLink -ErrorAction Stop)
        WriteLog -Message $message -EntryType Succeeded
    }
    Catch
    {
        $myError = $_
        WriteLog -Message $message -EntryType Failed -ErrorLog
        WriteLog -Message $myError.tostring() -ErrorLog
        throw("Failed: $Message")
    }
    Pop-Location
    WriteLog -Message "Got $($msExchDelegateListLinkUsers.count) Users with msExchDelegateListLink from AD $($ActiveDirectoryDrive.name)" -EntryType Notification
    #EndRegion msExchdelegateListLink

    $counter = 0
    $AutoMappingHash = @{}
    Foreach ($u in $AutoMappedUsers)
    {
        $counter++
        $message = 'Generating hash of Automapped Users and AutoMappers...'
        $ProgressInterval = [int]($($AutoMappedUsers.Count) * .01)
        if ($($counter) % $ProgressInterval -eq 0)
        {
            Write-Progress -Activity $message -Status "Items processed: $($counter) of $($AutoMappedUsers.Count)" -PercentComplete (($counter / $($AutoMappedUsers.Count)) * 100)
        }
        $AutoMappingHash.$([guid]::new($u.msExchMailboxGuid).guid) = $u.msExchDelegateListLink

    }#End Foreach
    $AutoMappingHash

}
