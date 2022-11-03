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
    WriteLog -Message 'Operation: Generate Mapping for all User Recipients with SIDHistory.'

    #Region GetSIDHistoryUsers
    Set-Location $($ActiveDirectoryDrive.Name + ':\') -ErrorAction Stop

    $PiXPParams = @{
        ArrayToProcess             = @(1,2)
        CalculatedProgressInterval = 'Each'
        Activity                   = 'Generate Mapping for all User Recipients with SIDHistory.'
        Status                     = 'Step 1 of 2'
    }
    $PxProgressID = Initialize-xProgress @PiXPParams
    $iXPParams = @{
        ArrayToProcess             = @(1)
        CalculatedProgressInterval = 'Each'
        Activity                   = "Get AD Users with SIDHistory from AD Drive $($activeDirectoryDrive.Name)"
        xParentIdentity            = $PxProgressID
    }
    $xProgressID = Initialize-xProgress @iXPParams
    Write-xProgress -Identity $PxProgressID
    Try
    {
        Write-xProgress -Identity $xProgressID
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
    Complete-xProgress -Identity $xProgressID
    #EndRegion GetSIDHistoryUsers

    $iXPParams = @{
        ArrayToProcess             = $sidHistoryUsers
        CalculatedProgressInterval = 'Each'
        Activity                   = 'Generating hashtable of SIDHistory SIDs and Recipient objects...'
        xParentIdentity            = $PxProgressID
    }
    $xProgressID = Initialize-xProgress @iXPParams
    Set-xProgress -Identity $PxProgressID -Status 'Step 2 of 2'
    Write-xProgress -Identity $PxProgressID

    $SIDHistoryRecipientHash = @{}
    Foreach ($shu in $sidhistoryusers)
    {
        Write-xProgress -Identity $xProgressID
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
    Complete-xProgress -Identity $xProgressID
    $SIDHistoryRecipientHash
}
