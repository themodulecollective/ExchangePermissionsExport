Function GetSIDHistoryRecipientHash
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
    WriteLog -Message 'Operation: Retrieve Mapping for all User Recipients with SIDHistory.'

    #Region GetSIDHistoryUsers
    Set-Location $($ActiveDirectoryDrive.Name + ':\') -ErrorAction Stop
    Try
    {
        $message = "Get AD Users with SIDHistory from AD Drive $($activeDirectoryDrive.Name)"
        WriteLog -Message $message -EntryType Attempting
        $sidHistoryUsers = @(Get-Aduser -ldapfilter '(&(legacyExchangeDN=*)(sidhistory=*))' -Properties sidhistory, legacyExchangeDN -ErrorAction Stop)
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
    WriteLog -Message "Got $($sidHistoryUsers.count) Users with SID History from AD $($ActiveDirectoryDrive.name)" -EntryType Notification
    #EndRegion GetSIDHistoryUsers

    $sidhistoryusercounter = 0
    $SIDHistoryRecipientHash = @{}
    Foreach ($shu in $sidhistoryusers)
    {
        $sidhistoryusercounter++
        $message = 'Generating hash of SIDHistory SIDs and Recipient objects...'
        $ProgressInterval = [int]($($sidhistoryusers.Count) * .01)
        if ($($sidhistoryusercounter) % $ProgressInterval -eq 0)
        {
            Write-Progress -Activity $message -Status "Items processed: $($sidhistoryusercounter) of $($sidhistoryusers.Count)" -PercentComplete (($sidhistoryusercounter / $($sidhistoryusers.Count)) * 100)
        }
        $splat = @{Identity = $shu.ObjectGuid.guid; ErrorAction = 'SilentlyContinue' } #is this a good assumption?
        $sidhistoryuserrecipient = $Null
        $sidhistoryuserrecipient = Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-Recipient @using:splat } -ErrorAction SilentlyContinue
        If ($null -ne $sidhistoryuserrecipient)
        {
            Foreach ($sidhistorysid in $shu.sidhistory)
            {
                $SIDHistoryRecipientHash.$($sidhistorysid.value) = $sidhistoryuserrecipient
            }#End Foreach
        }#end If
    }#End Foreach
    $SIDHistoryRecipientHash

}
