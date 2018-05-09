#developing
function Get-ForwardingMailbox
{}

function GetCalendarPermission
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
        $splat = @{Identity = $Identity + ':\Calendar'}
        $RawCalendarPermissions = @(
            try
            {
                Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-MailboxFolderPermission @using:splat} -ErrorAction Stop
            }
            catch
            {
                Write-Verbose -Message "Get-MailboxPermission threw an error with Identity $Identity.  Attempting to find localized folder name instead."
                try
                {
                    $CalendarFolderName = Invoke-Command -errorAction Stop -session $ExchangeSession -ScriptBlock {
                        Get-MailboxFolderStatistics -Identity $using:Identity
                    } | Where-Object -FilterScript {$_.FolderType -eq "Calendar"} | Select-Object -First 1 | Select-Object -ExpandProperty Name
                    if ([string]::IsNullOrWhiteSpace($CalendarFolderName))
                    {
                        Write-Verbose -Message "No Calendar Folder found for Identity $Identity"
                    }
                    else
                    {
                        #try again with the localized folder name
                        $splat.Identity = $($Identity + ':\' + $CalendarFolderName)
                        Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-MailboxFolderPermission @using:splat} -ErrorAction Stop
                    }
                }
                catch
                {
                    Write-Verbose -Message "Unresolved Error Retrieving Calendar Permissions for Identity $Identity"
                }
            }
        )
        #filter anon and default permissions
        $$RawCalendarPermissions | Where-Object -FilterScript {$_.User -notlike "Anonymous" -and $_.User -notlike "Default"}
    }
#end Get-CalendarPermission