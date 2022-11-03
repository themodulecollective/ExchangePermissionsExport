Function Export-ExchangePermission
{
    <#
.SYNOPSIS
    Exports Exchange Permissions (Full, SendAs, SendOnBehalf, Calendar, Folder) to a CSV file using a standard format for all permission types.
.DESCRIPTION
    Exports Exchange Permissions (Full, SendAs, SendOnBehalf, Calendar, Folder) to a CSV file using a standard format for all permission types. Expands group permissions. Identified permisisons based on SIDHistory. Identifies inherited Permissions. Resolves permisison holders (Trustees) to unique identifiers (such as MailboxGUID).
.NOTES

.LINK

.EXAMPLE
    Get Full Access, SendAS, and SendOnBehalf Permissions for all mailboxes, expand group membership for group assinged permissions, and include permissions based on SIDHistory.  Use an AD connection for better performance for SendAS permissions and group expansion.
    Import-Module ActiveDirectory
    $AD = Get-psdrive -Provider ActiveDirectory
    Export-ExchangePermission -Outputfolderpath c:\PermOutput -AllMailboxes -IncludeSendOnBehalf -IncludeFullAccess -IncludeSendAs -ExpandGroups -ActiveDirectoryDrive $AD -IncludeSIDHistory

    Get Permissions for a specified set of mailboxes
    Export-ExchangePermission -outputfolderpath c:\PermOutput -Identity ben@contoso.com,mike@contoso.com -IncludeSendOnBehalf -IncludeSendAS -IncludeFullAccess

    Get mailbox folder level permission for all mailboxes.  Note: This may be a very long running operation. See WIPFunctions\FanOutFolderPermissions.ps1
    Export-ExchangePermission -outputfolderpath c:\PermOutput -AllMailboxes -IncludeAllFolder
#>

    [cmdletbinding(DefaultParameterSetName = 'AllMailboxes')]
    param
    (

        #specifies the folder where output files (csv and logs) will be placed.  User must be able to write to this location.
        [Parameter(ParameterSetName = 'AllMailboxes', Mandatory)]
        [parameter(ParameterSetName = 'Scoped', Mandatory)]
        [parameter(ParameterSetName = 'GlobalSendAs', Mandatory)]
        [ValidateScript( { TestIsWriteableDirectory -Path $_ })]
        $OutputFolderPath
        ,
        #specifies a permissions export based on the named identities in the connected organization
        [parameter(ParameterSetName = 'Scoped', Mandatory)]
        [string[]]$Identity
        ,
        #specifies a permissions export for all mailboxes in the connected organization
        [Parameter(ParameterSetName = 'AllMailboxes', Mandatory)]
        [switch]$AllMailboxes
        ,
        #specify permission target mailboxes to exclude (when using -AllMailboxes)
        [parameter()]#These will be resolved to target recipient objects
        [string[]]$ExcludedIdentities
        ,
        #specify permission holders to exclude from Permissions output
        [parameter()]#These will be resolved to trustee objects
        [string[]]$ExcludedTrusteeIdentities
        ,
        #Include SendOnBehalf permissions in the output
        [parameter(ParameterSetName = 'Scoped')]
        [Parameter(ParameterSetName = 'AllMailboxes')]
        [switch]$IncludeSendOnBehalf
        ,
        #Include FullAccess permissions in the output
        [parameter(ParameterSetName = 'Scoped')]
        [Parameter(ParameterSetName = 'AllMailboxes')]
        [switch]$IncludeFullAccess
        ,
        #Include SendAs permissions in the output (retrieved from AD rather than Exchange if -ActiveDirectoryDrive is provided).
        [parameter(ParameterSetName = 'Scoped')]
        [Parameter(ParameterSetName = 'AllMailboxes')]
        [switch]$IncludeSendAs
        ,
        #Include Calendar permissions for each included mailbox's first calendar folder
        [parameter(ParameterSetName = 'Scoped')]
        [Parameter(ParameterSetName = 'AllMailboxes')]
        [switch]$IncludeCalendar
        ,
        #Include permissions for all folders in the included mailboxes.  Includes calendar
        [parameter(ParameterSetName = 'Scoped')]
        [Parameter(ParameterSetName = 'AllMailboxes')]
        [switch]$IncludeAllFolder
        ,
        #Includes AD Based SendAS permission (an inherited form of SendAS). Requires -ActiveDirectoryDrive
        [parameter(ParameterSetName = 'GlobalSendAs', Mandatory)]
        [switch]$GlobalSendAs
        ,
        #Include permissions that result from SIDHistory in AD (SendAS)
        [switch]$IncludeSIDHistory
        ,
        #Include Automapping Details for Full Access Permissions. Requres -ActiveDirectoryDrive for Exchange On Premises.
        [switch]$IncludeAutoMapping
        ,
        #Include Automapping settings independently from Full Access Permissions in output.  Requres -ActiveDirectoryDrive for Exchange On Premises.
        [switch]$IncludeAutoMappingSetting
        ,
        #Expands permissions assigned to a group out to the group members in the output.
        [bool]$expandGroups = $true
        ,
        #Drops the original group permission when group permissions are expanded (rarely used)
        [switch]$dropExpandedParentGroupPermissions
        ,
        #Drops permissions inherited in AD.  Usually effective at removing administrative only permissions that are not relevant to most exchange migrations
        [bool]$dropInheritedPermissions = $true
        ,
        #Used for AD connectivity for better performance of SendAs permission retrieval and also for group expansion and SIDHistory
        [parameter()]
        [ValidateScript( { $_.gettype().name -eq 'ADDriveInfo' })]#doing this as a validatescript instead of a type declaration so that this will run on a system that lacks the ActiveDirectory module if the user doesn't need this parameter.
        $ActiveDirectoryDrive
        ,
        #Forces use of Exchange commands rather than AD connectionfor Group expansion and SendAs permission retrieval
        [switch]$UseExchangeCommandsInsteadOfADOrLDAP
        ,
        #Excludes a record output for mailboxes where no permissions are found
        [switch]$ExcludeNonePermissionOutput
        ,
        #Stores all permission output in a global scope variable for review at the command line after export has completed.
        [switch]$KeepExportedPermissionsInGlobalVariable
    )#End Param
    Begin
    {
        #$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        # Add Parameter Validation (for complex validations that would require many parameter sets otherwise)
        switch ($script:ConnectExchangeOrganizationCompleted)
        {
            $true
            {
                switch (TestExchangePSSession -PSSession $script:PSSession)
                {
                    $true
                    {
                        WriteLog -Message 'Using Existing Exchange Connection' -EntryType Notification
                    }
                    $false
                    {
                        WriteLog -Message 'Removing Existing Failed PSSession' -EntryType Notification
                        Remove-PSSession -Session $script:PsSession -ErrorAction SilentlyContinue
                        WriteLog -Message 'Establishing New PSSession to Exchange Organization' -EntryType Notification
                        $GetExchangePSSessionParams = GetGetExchangePSSessionParams
                        $script:PsSession = GetExchangePSSession @GetExchangePSSessionParams
                    }
                }
            }
            $false
            {
                WriteUserInstructionError
            }
        }
        $BeginTimeStamp = Get-Date -Format yyyyMMdd-HHmmss
        $random = [System.IO.Path]::GetRandomFileName().split('.')[0]
        $ExchangeOrganization = Invoke-Command -Session $Script:PSSession -ScriptBlock { Get-OrganizationConfig | Select-Object -ExpandProperty Identity}
        $script:LogPath = Join-Path -Path $OutputFolderPath -ChildPath $($BeginTimeStamp + '-' + $random + '-ExchangePermissionsExportOperations.log')
        $script:ErrorLogPath = Join-Path -Path $OutputFolderPath -ChildPath $($BeginTimeStamp + '-' + $random + '-ExchangePermissionsExportOperations-ERRORS.log')


        WriteLog -Message "Calling Invocation = $($MyInvocation.Line)" -EntryType Notification
        WriteLog -Message "Provided Exchange Session is Running in Exchange Organzation $ExchangeOrganization" -EntryType Notification
        $ExportedExchangePermissionsFile = Join-Path -Path $OutputFolderPath -ChildPath $($BeginTimeStamp + '-' + $random + '-ExportedExchangePermissions.csv')
        $ResumeIndex = 0
        if (($true -eq $IncludeSIDHistory -or $true -eq $IncludeAutoMapping) -and $Script:OrganizationType -eq 'ExchangeOnPremises' )
        {
            if ($null -eq $ActiveDirectoryDrive)
            { throw('If IncludeSIDHistory or IncludeAutoMapping is required an Active Directory PS Drive connection to the appropriate domain or forest must be provided') }
        }

        #Region GetExcludedRecipients
        if ($PSBoundParameters.ContainsKey('ExcludedIdentities'))
        {
            try
            {
                $message = "Get recipent object(s) from Exchange Organization $ExchangeOrganization for the $($ExcludedIdentities.Count) ExcludedIdentities provided."
                WriteLog -Message $message -EntryType Attempting
                $excludedRecipients = @(
                    $ExcludedIdentities | ForEach-Object {
                        $splat = @{
                            Identity    = $_
                            ErrorAction = 'Stop'
                        }
                        Invoke-Command -Session $Script:PSSession -ScriptBlock { Get-Recipient @Using:splat | Select-Object -Property $using:HRPropertySet } -ErrorAction 'Stop'
                    }
                )
                WriteLog -Message $message -EntryType Succeeded
            }
            Catch
            {
                $myError = $_
                WriteLog -Message $message -EntryType Failed -ErrorLog
                WriteLog -Message $myError.tostring() -ErrorLog
                throw("Failed: $Message")
            }
            WriteLog -Message "Got $($excludedRecipients.count) Excluded Objects" -EntryType Notification
            $excludedRecipientGUIDHash = $excludedRecipients | Group-Object -Property GUID -AsString -AsHashTable -ErrorAction Stop
        }
        else
        {
            $excludedRecipientGUIDHash = @{}
        }
        #EndRegion GetExcludedRecipients

        #Region GetExcludedTrustees
        if ($PSBoundParameters.ContainsKey('ExcludedTrusteeIdentities'))
        {
            try
            {
                $message = "Get recipent object(s) from Exchange Organization $ExchangeOrganization for the $($ExcludedTrusteeIdentities.Count) ExcludedTrusteeIdentities provided."
                WriteLog -Message $message -EntryType Attempting
                $excludedTrusteeRecipients = @(
                    $ExcludedTrusteeIdentities | ForEach-Object {
                        $splat = @{
                            Identity    = $_
                            ErrorAction = 'Stop'
                        }
                        Invoke-Command -Session $Script:PSSession -ScriptBlock { Get-Recipient @Using:splat | Select-Object -Property $using:HRPropertySet } -ErrorAction 'Stop'
                    }
                )
                WriteLog -Message $message -EntryType Succeeded
            }
            Catch
            {
                $myError = $_
                WriteLog -Message $message -EntryType Failed -ErrorLog
                WriteLog -Message $myError.tostring() -ErrorLog
                throw("Failed: $Message")
            }
            WriteLog -Message "Got $($excludedTrusteeRecipients.count) Excluded Trustee Objects" -EntryType Notification
            $excludedTrusteeGUIDHash = $excludedTrusteeRecipients | Group-Object -Property GUID -AsString -AsHashTable -ErrorAction Stop
        }
        else
        {
            $excludedTrusteeGUIDHash = @{}
        }
        #EndRegion GetExcludedTrustees

        #Region GetInScopeRecipients
        Try
        {
            switch ($PSCmdlet.ParameterSetName)
            {
                'Scoped'
                {
                    WriteLog -Message "Operation: Scoped Permission retrieval with $($Identity.Count) Identities provided."
                    $message = "Get mailbox object for each provided Identity in Exchange Organization $ExchangeOrganization."
                    WriteLog -Message $message -EntryType Attempting
                    $InScopeRecipients = @(
                        $Identity | ForEach-Object {
                            $splat = @{
                                Identity    = $_
                                ErrorAction = 'Stop'
                            }
                            Invoke-Command -Session $Script:PSSession -ScriptBlock { Get-Mailbox @Using:splat | Select-Object -Property $Using:HRPropertySet } -ErrorAction Stop
                        }
                    )
                    WriteLog -Message $message -EntryType Succeeded
                }#end Scoped
                'AllMailboxes'
                {
                    WriteLog -Message 'Operation: Permission retrieval for all mailboxes.'
                    $message = "Get all available mailbox objects in Exchange Organization $ExchangeOrganization."
                    WriteLog -Message $message -EntryType Attempting
                    $splat = @{
                        ResultSize  = 'Unlimited'
                        ErrorAction = 'Stop'
                    }
                    $InScopeRecipients = @(Invoke-Command -Session $Script:PSSession -ScriptBlock { Get-Mailbox @Using:splat | Select-Object -Property $Using:HRPropertySet } -ErrorAction Stop)
                    WriteLog -Message $message -EntryType Succeeded
                }#end AllMailboxes
                'GlobalSendAs'
                {
                    WriteLog -Message 'Operation: Send As Permission retrieval for all recipients.'
                    $message = "Get all available recipient objects in Exchange Organization $ExchangeOrganization."
                    WriteLog -Message $message -EntryType Attempting
                    $splat = @{
                        ResultSize  = 'Unlimited'
                        ErrorAction = 'Stop'
                    }
                    $InScopeRecipients = @(Invoke-Command -Session $Script:PSSession -ScriptBlock { Get-Recipient @Using:splat | Select-Object -Property $Using:HRPropertySet } -ErrorAction Stop)
                    WriteLog -Message $message -EntryType Succeeded
                }#end GlobalSendAS
            }#end Switch
        }#end try
        Catch
        {
            $myError = $_
            WriteLog -Message $message -EntryType Failed -ErrorLog
            WriteLog -Message $myError.tostring() -ErrorLog
            throw("Failed: $Message")
        }
        $InScopeRecipientCount = $InScopeRecipients.count
        WriteLog -Message "Got $InScopeRecipientCount In Scope Recipient Objects" -EntryType Notification
        #EndRegion GetInScopeRecipients

        #Region GetSIDHistoryData
        if ($true -eq $IncludeSIDHistory)
        {
            $SIDHistoryRecipientHash = GetSIDHistoryRecipientHash -ActiveDirectoryDrive $ActiveDirectoryDrive -ExchangeSession $Script:PSSession -ErrorAction Stop
        }
        else
        {
            $SIDHistoryRecipientHash = @{}
        }
        #EndRegion GetSIDHistoryData

        #Region GetAutoMappingData
        if ($true -eq $IncludeAutoMapping)
        {
            $GAMHParams = @{
                ExchangeSession   = $Script:PSSession
                ErrorAction       = 'Stop'
                InScopeRecipients = $InScopeRecipients
            }
            if ($script:OrganizationType -eq 'ExchangeOnPremises')
            {
                $GAMHParams.ActiveDirectoryDrive = $activeDirectoryDrive
            }
            $AutoMappingHash = GetAutoMappingHash @GAMHParams
        }
        else
        {
            $AutoMappingHash = @{}
        }
        #EndRegion GetAutoMappingData

        #Region BuildLookupHashTables
        WriteLog -Message 'Building Recipient Lookup HashTables' -EntryType Notification
        $ObjectGUIDHash = $InScopeRecipients | Select-Object -Property $HRPropertySet | Group-Object -AsHashTable -Property Guid -AsString
        #Also Add the Exchange GUIDs to this lookup if we are dealing with Exchange Online
        if ($Script:OrganizationType -eq 'ExchangeOnline')
        {
            $InScopeRecipients | ForEach-Object -Process { $ObjectGUIDHash.$($_.ExchangeGuid.Guid) = $_ }
        }

    }

    End
    {
        #these have to be populated as we go
        $DomainPrincipalHash = @{}
        $UnfoundIdentitiesHash = @{}
        if ($expandGroups -eq $true)
        {
            $script:ExpandedGroupsNonGroupMembershipHash = @{}
        }

        #Set Up to Loop through Mailboxes/Recipients
        WriteLog -message $message -EntryType Notification
        $ExportedPermissions = @(
            If (($IncludeAutoMapping) -and ($IncludeAutoMappingSetting) -and (!($GlobalSendAs)))
            {
                Write-Verbose -Message 'Getting AutoMapping Settings As Permissions for All Automappings'
                GetAutoMappingSetting -AutoMappingHash $AutoMappingHash -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $Script:PSSession -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization -DomainPrincipalHash $DomainPrincipalHash -HRPropertySet $HRPropertySet -dropInheritedPermissions $dropInheritedPermissions -UnfoundIdentitiesHash $UnfoundIdentitiesHash
            }
            #Set up progress bar
            $iXPParams = @{
                ArrayToProcess             = $InScopeRecipients
                CalculatedProgressInterval = '1Percent'
                Activity                   = 'Collect Permissions for In Scope Recipients'
            }
            $ISRxProgress = Initialize-xProgress @iXPParams

            #Set up permissions collection loop
            :nextISR for
            (
                $i = $ResumeIndex
                $i -le $InScopeRecipientCount - 1
                $(if ($Recovering) { $i = $ResumeIndex } else { $i++ })
                #$ISR in $InScopeRecipients[$ResumeIndex..$()]
            )

            {
                $Recovering = $false
                Write-xProgress -Identity $ISRxProgress
                $ISR = $InScopeRecipients[$i]
                $ID = $ISR.guid.guid

                if ($excludedRecipientGUIDHash.ContainsKey($ISR.guid.Guid))
                {
                    WriteLog -Message "Excluding Excluded Recipient $ID"
                    continue nextISR
                }

                $message = "Collect permissions for $($ID)"
                Try
                {
                    WriteLog -Message $message -EntryType Attempting
                    $PermissionExportObjects = @(
                        If (($IncludeSendOnBehalf) -and (!($GlobalSendAs)))
                        {
                            Write-Verbose -Message "Getting SendOnBehalf Permissions for Target $ID"
                            GetSendOnBehalfPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $Script:PSSession -ExcludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization -HRPropertySet $HRPropertySet -DomainPrincipalHash $DomainPrincipalHash -UnfoundIdentitiesHash $UnfoundIdentitiesHash
                        }
                        If (($IncludeFullAccess) -and (!($GlobalSendAs)))
                        {
                            Write-Verbose -Message "Getting FullAccess Permissions for Target $ID"
                            GetFullAccessPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $Script:PSSession -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization -DomainPrincipalHash $DomainPrincipalHash -HRPropertySet $HRPropertySet -dropInheritedPermissions $dropInheritedPermissions -UnfoundIdentitiesHash $UnfoundIdentitiesHash
                        }
                        If (($IncludeCalendar) -and (!($GlobalSendAs)))
                        {
                            Write-Verbose -Message "Getting Calendar Permissions for Target $ID"
                            GetCalendarPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $Script:PSSession -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization -DomainPrincipalHash $DomainPrincipalHash -HRPropertySet $HRPropertySet -UnfoundIdentitiesHash $UnfoundIdentitiesHash
                        }
                        If (($IncludeAllFolder) -and (!($GlobalSendAs)))
                        {
                            Write-Verbose -Message "Getting Folder Permissions for Target $ID"
                            GetAllFolderPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $Script:PSSession -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization -DomainPrincipalHash $DomainPrincipalHash -HRPropertySet $HRPropertySet -UnfoundIdentitiesHash $UnfoundIdentitiesHash
                        }
                        #Get Send As Users
                        If (($IncludeSendAs) -or ($GlobalSendAs))
                        {
                            Write-Verbose -Message "Getting SendAS Permissions for Target $ID"
                            if ($script:OrganizationType -eq 'ExchangeOnline' -or $UseExchangeCommandsInsteadOfADOrLDAP)
                            {
                                Write-Verbose -Message "Getting SendAS Permissions for Target $ID Via Exchange Commands"
                                GetSendASPermissionsViaExchange -TargetMailbox $ISR -ExchangeSession $Script:PSSession -ObjectGUIDHash $ObjectGUIDHash -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -dropInheritedPermissions $dropInheritedPermissions -DomainPrincipalHash $DomainPrincipalHash -ExchangeOrganization $ExchangeOrganization -HRPropertySet $HRPropertySet -UnfoundIdentitiesHash $UnfoundIdentitiesHash
                            }
                            else
                            {
                                Write-Verbose -Message "Getting SendAS Permissions for Target $ID Via LDAP Commands"
                                GetSendASPermisssionsViaLocalLDAP -TargetMailbox $ISR -ExchangeSession $Script:PSSession -ObjectGUIDHash $ObjectGUIDHash -excludedTrusteeGUIDHash $excludedRecipientGUIDHash -dropInheritedPermissions $dropInheritedPermissions -DomainPrincipalHash $DomainPrincipalHash -ExchangeOrganization $ExchangeOrganization -HRPropertySet $HRPropertySet -UnfoundIdentitiesHash $UnfoundIdentitiesHash
                            }
                        }
                    )
                    if ($expandGroups -eq $true)
                    {
                        Write-Verbose -Message "Expanding Group Based Permissions for Target $ID"
                        $splat = @{
                            Permission              = $PermissionExportObjects
                            ObjectGUIDHash          = $ObjectGUIDHash
                            SIDHistoryHash          = $SIDHistoryRecipientHash
                            excludedTrusteeGUIDHash = $excludedTrusteeGUIDHash
                            UnfoundIdentitiesHash   = $UnfoundIdentitiesHash
                            HRPropertySet           = $HRPropertySet
                            exchangeSession         = $Script:PSSession
                            TargetMailbox           = $ISR
                        }
                        if ($dropExpandedParentGroupPermissions -eq $true)
                        { $splat.dropExpandedParentGroupPermissions = $true }
                        if ($Script:OrganizationType -eq 'ExchangeOnline' -or $UseExchangeCommandsInsteadOfADOrLDAP)
                        { $splat.UseExchangeCommandsInsteadOfADOrLDAP = $true }
                        $PermissionExportObjects = @(ExpandGroupPermission @splat)
                    }
                    if ($script:OrganizationType -eq 'ExchangeOnline' -or ($Script:OrganizationType -eq 'ExchangeOnPremises' -and $(TestExchangePSSession -PSSession $Script:PSSession)))
                    {
                        if ($PermissionExportObjects.Count -eq 0 -and -not $ExcludeNonePermissionOutput -eq $true)
                        {
                            $GPEOParams = @{
                                TargetMailbox              = $ISR
                                TrusteeIdentity            = 'Not Applicable'
                                TrusteeRecipientObject     = $null
                                PermissionType             = 'None'
                                AssignmentType             = 'None'
                                SourceExchangeOrganization = $ExchangeOrganization
                                None                       = $true
                            }
                            $NonPerm = NewPermissionExportObject @GPEOParams
                            $NonPerm
                        }
                        elseif ($PermissionExportObjects.Count -gt 0)
                        {
                            $PermissionExportObjects
                        }
                        WriteLog -Message $message -EntryType Succeeded
                    }
                    else
                    {
                        WriteLog -Message 'Removing Existing Failed PSSession' -EntryType Notification
                        Remove-PSSession -Session $script:PsSession -ErrorAction SilentlyContinue
                        WriteLog -Message 'Establish New PSSession to Exchange Organization' -EntryType Attempting
                        $GetExchangePSSessionParams = GetGetExchangePSSessionParams
                        try
                        {
                            Start-Sleep -Seconds 10
                            $script:PsSession = GetExchangePSSession @GetExchangePSSessionParams
                            WriteLog -Message 'Establish New PSSession to Exchange Organization' -EntryType Succeeded
                            $ResumeIndex = getarrayIndexForIdentity -array $InScopeRecipients -property 'guid' -Value $ID -ErrorAction Stop
                            Set-xProgress -Identity $ISRxProgress -DecrementCounter
                            $Recovering = $true
                            continue nextISR
                        }
                        catch
                        {
                            $myerror = $_
                            WriteLog -Message 'Establish New PSSession to Exchange Organization' -EntryType Failed
                            WriteLog -Message $myerror.tostring() -ErrorLog -Verbose
                            WriteLog -Message $message -EntryType Failed -ErrorLog -Verbose
                            $exitmessage = "Testing Showed that Exchange Session Failed/Disconnected during permission processing for ID $ID."
                            WriteLog -Message $exitmessage -EntryType Notification -ErrorLog -Verbose
                            #$exitmessage = "Exchange Session Failed/Disconnected during permission processing for ID $ID. The next Log entry is the error from the Exchange Session."
                            #WriteLog -Message $exitmessage -EntryType Notification -ErrorLog -Verbose
                            Break nextISR
                        }
                    }
                }
                Catch
                {
                    $myerror = $_
                    WriteLog -Message $message -EntryType Failed -ErrorLog -Verbose
                    WriteLog -Message $myError.tostring() -ErrorLog -Verbose
                    $ResumeIndex = getarrayIndexForIdentity -array $InScopeRecipients -property 'guid' -Value $ID -ErrorAction Stop
                    Set-xProgress -Identity $ISRxProgress -DecrementCounter
                    $Recovering = $true
                    continue nextISR
                }
            }#Foreach recipient in set
        )# end ExportedPermissions

        Complete-xProgress -Identity $ISRxProgress

        if ($ExportedPermissions.Count -ge 1)
        {
            Try
            {
                $message = "Export $($ExportedPermissions.Count) Exported Permissions to File $ExportedExchangePermissionsFile."
                WriteLog -Message $message -EntryType Attempting
                switch ($PSCmdlet.ParameterSetName -eq 'Resume')
                {
                    $true
                    {
                        $ExportedPermissions | Export-Csv -Path $ExportedExchangePermissionsFile -Append -Encoding UTF8 -ErrorAction Stop -NoTypeInformation #-Force
                    }
                    $false
                    {
                        $ExportedPermissions | Export-Csv -Path $ExportedExchangePermissionsFile -NoClobber -Encoding UTF8 -ErrorAction Stop -NoTypeInformation
                    }
                }
                WriteLog -Message $message -EntryType Succeeded
                if ($KeepExportedPermissionsInGlobalVariable -eq $true)
                {
                    WriteLog -Message "Saving Exported Permissions to Global Variable $($BeginTimeStamp + 'ExportedExchangePermissions') for recovery/manual export."
                    Set-Variable -Name $($BeginTimeStamp + 'ExportedExchangePermissions') -Value $ExportedPermissions -Scope Global
                }
            }
            Catch
            {
                $myerror = $_
                WriteLog -Message $message -EntryType Failed -ErrorLog -Verbose
                WriteLog -Message $myError.tostring() -ErrorLog
                WriteLog -Message "Saving Exported Permissions to Global Variable $($BeginTimeStamp + 'ExportedExchangePermissions') for recovery/manual export if desired/required.  This is separate from performing a Resume with a Resume file." -verbose
                Set-Variable -Name $($BeginTimeStamp + 'ExportedExchangePermissions') -Value $ExportedPermissions -Scope Global
            }
        }
        else
        {
            WriteLog -Message 'No Permissions were generated for export by this operation.  Check the logs for errors if this is unexpected.' -EntryType Notification -Verbose
        }
    }#end End

}
