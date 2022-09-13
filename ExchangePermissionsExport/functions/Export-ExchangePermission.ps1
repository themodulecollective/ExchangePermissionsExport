Function Export-ExchangePermission
{

    [cmdletbinding(DefaultParameterSetName = 'AllMailboxes')]
    param
    (
        [Parameter(ParameterSetName = 'AllMailboxes', Mandatory)]
        [parameter(ParameterSetName = 'Scoped', Mandatory)]
        [parameter(ParameterSetName = 'GlobalSendAs', Mandatory)]
        [ValidateScript( { TestIsWriteableDirectory -Path $_ })]
        $OutputFolderPath
        ,
        [parameter(ParameterSetName = 'GlobalSendAs', Mandatory)]
        [switch]$GlobalSendAs
        ,
        [parameter(ParameterSetName = 'Scoped', Mandatory)]
        [string[]]$Identity
        ,
        [Parameter(ParameterSetName = 'AllMailboxes', Mandatory)]
        [switch]$AllMailboxes
        ,
        [parameter()]#These will be resolved to target recipient objects
        [string[]]$ExcludedIdentities
        ,
        [parameter()]#These will be resolved to trustee objects
        [string[]]$ExcludedTrusteeIdentities
        ,
        [parameter(ParameterSetName = 'Scoped')]
        [Parameter(ParameterSetName = 'AllMailboxes')]
        [switch]$IncludeSendOnBehalf
        ,
        [parameter(ParameterSetName = 'Scoped')]
        [Parameter(ParameterSetName = 'AllMailboxes')]
        [switch]$IncludeFullAccess
        ,
        [parameter(ParameterSetName = 'Scoped')]
        [Parameter(ParameterSetName = 'AllMailboxes')]
        [switch]$IncludeSendAs
        ,
        [parameter(ParameterSetName = 'Scoped')]
        [Parameter(ParameterSetName = 'AllMailboxes')]
        [switch]$IncludeCalendar
        ,
        [parameter(ParameterSetName = 'Scoped')]
        [Parameter(ParameterSetName = 'AllMailboxes')]
        [switch]$IncludeAllFolder
        ,
        [switch]$IncludeSIDHistory
        ,
        [bool]$expandGroups = $true
        ,
        [switch]$dropExpandedParentGroupPermissions
        ,
        [bool]$dropInheritedPermissions = $true
        ,
        [parameter()]
        [ValidateScript( { $_.gettype().name -eq 'ADDriveInfo' })]#doing this as a validatescript instead of a type declaration so that this will run on a system that lacks the ActiveDirectory module if the user doesn't need this parameter.
        $ActiveDirectoryDrive
        ,
        [switch]$UseExchangeCommandsInsteadOfADOrLDAP
        ,
        [switch]$ExcludeNonePermissionOutput
        ,
        [switch]$EnableResume
        ,
        [switch]$KeepExportedPermissionsInGlobalVariable
        ,
        [Parameter(ParameterSetName = 'Resume', Mandatory)]
        [ValidateScript( { Test-Path -Path $_ })]
        [string]$ResumeFile
    )#End Param
    Begin
    {
        #$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        switch ($script:ConnectExchangeOrganizationCompleted)
        {
            $true
            {
                switch (TestExchangePSSession -PSSession $script:PSSession)
                {
                    $true
                    {
                        WriteLog -Message 'Using Existing PSSession' -EntryType Notification
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
        $ExchangeOrganization = Invoke-Command -Session $Script:PSSession -ScriptBlock { Get-OrganizationConfig | Select-Object -ExpandProperty Identity | Select-Object -ExpandProperty Name }
        $ExchangeOrganizationIsInExchangeOnline = $ExchangeOrganization -like '*.onmicrosoft.com'
        $script:LogPath = Join-Path -Path $OutputFolderPath -ChildPath $($BeginTimeStamp + '-' + $random + '-ExchangePermissionsExportOperations.log')
        $script:ErrorLogPath = Join-Path -Path $OutputFolderPath -ChildPath $($BeginTimeStamp + '-' + $random + '-ExchangePermissionsExportOperations-ERRORS.log')

        switch ($PSCmdlet.ParameterSetName -eq 'Resume')
        {
            $true
            {
                $ImportedExchangePermissionsExportResumeData = ImportExchangePermissionExportResumeData -Path $ResumeFile
                $ExcludedRecipientGuidHash = $ImportedExchangePermissionsExportResumeData.ExcludedRecipientGuidHash
                $ExcludedTrusteeGuidHash = $ImportedExchangePermissionsExportResumeData.ExcludedTrusteeGuidHash
                $SIDHistoryRecipientHash = $ImportedExchangePermissionsExportResumeData.SIDHistoryRecipientHash
                $InScopeRecipients = $ImportedExchangePermissionsExportResumeData.InScopeRecipients
                $InScopeRecipientCount = $InScopeRecipients.count
                $ObjectGUIDHash = $ImportedExchangePermissionsExportResumeData.ObjectGUIDHash
                $ResumeIdentity = $ImportedExchangePermissionsExportResumeData.ResumeID
                [uint32]$Script:PermissionIdentity = $ImportedExchangePermissionsExportResumeData.NextPermissionIdentity
                $ExportedExchangePermissionsFile = $ImportedExchangePermissionsExportResumeData.ExportedExchangePermissionsFile
                foreach ($v in $ImportedExchangePermissionsExportResumeData.ExchangePermissionsExportParameters)
                {
                    Set-Variable -Name $v.name -Value $v.value -Force
                }
                WriteLog -Message "Calling Invocation = $($MyInvocation.Line)" -EntryType Notification
                WriteLog -Message "Exchange Session is Running in Exchange Organzation $ExchangeOrganization" -EntryType Notification
                $ResumeIndex = getarrayIndexForIdentity -array $InScopeRecipients -property 'guid' -Value $ResumeIdentity -ErrorAction Stop
                if ($null -eq $ResumeIndex -or $ResumeIndex.gettype().name -notlike '*int*')
                {
                    $message = 'ResumeIndex is invalid.  Check/Edit the *ResumeID.xml file for a valid ResumeIdentity GUID.'
                    WriteLog -Message $message -ErrorLog -EntryType Failed
                    Throw($message)
                }
                WriteLog -Message "Resume index set to $ResumeIndex based on ResumeIdentity $resumeIdentity" -EntryType Notification
            }
            $false
            {
                WriteLog -Message "Calling Invocation = $($MyInvocation.Line)" -EntryType Notification
                WriteLog -Message "Provided Exchange Session is Running in Exchange Organzation $ExchangeOrganization" -EntryType Notification
                $ExportedExchangePermissionsFile = Join-Path -Path $OutputFolderPath -ChildPath $($BeginTimeStamp + '-' + $random + '-ExportedExchangePermissions.csv')
                $ResumeIndex = 0
                [uint32]$Script:PermissionIdentity = 0
                if ($IncludeSIDHistory -eq $true)
                {
                    if ($null -eq $ActiveDirectoryDrive)
                    { throw('If IncludeSIDHistory is required an Active Directory PS Drive connection to the appropriate domain or forest must be provided') }
                }
                #create a property set for storing of recipient data during processing.  We don't need all attributes in memory/storage.
                $HRPropertySet = @('*name*', '*addr*', 'RecipientType*', '*Id', 'Identity', 'GrantSendOnBehalfTo')

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
                if ($IncludeSIDHistory -eq $true)
                {
                    $SIDHistoryRecipientHash = GetSIDHistoryRecipientHash -ActiveDirectoryDrive $ActiveDirectoryDrive -ExchangeSession $Script:PSSession -ErrorAction Stop
                }
                else
                {
                    $SIDHistoryRecipientHash = @{}
                }
                #EndRegion GetSIDHistoryData

                #Region BuildLookupHashTables
                WriteLog -Message 'Building Recipient Lookup HashTables' -EntryType Notification
                $ObjectGUIDHash = $InScopeRecipients | Select-Object -Property $HRPropertySet | Group-Object -AsHashTable -Property Guid -AsString
                #Also Add the Exchange GUIDs to this lookup if we are dealing with Exchange Online
                if ($ExchangeOrganizationIsInExchangeOnline)
                {
                    $InScopeRecipients | ForEach-Object -Process { $ObjectGUIDHash.$($_.ExchangeGuid.Guid) = $_ }
                }
            }
        }
        # Setup for Possible Resume if requested by the user
        if ($EnableResume -eq $true)
        {
            $ExportExchangePermissionsExportResumeData = @{
                ExcludedRecipientGuidHash       = $ExcludedRecipientGuidHash
                ExcludedTrusteeGuidHash         = $ExcludedTrusteeGuidHash
                SIDHistoryRecipientHash         = $SIDHistoryRecipientHash
                InScopeRecipients               = $InScopeRecipients
                ObjectGUIDHash                  = $ObjectGUIDHash
                outputFolderPath                = $outputFolderPath
                ExportedExchangePermissionsFile = $ExportedExchangePermissionsFile
                TimeStamp                       = $BeginTimeStamp
                ErrorAction                     = 'Stop'
            }
            switch ($PSCmdlet.ParameterSetName -eq 'Resume')
            {
                $true
                {
                    $ExportExchangePermissionsExportResumeData.ExchangePermissionsExportParameters = $ImportedExchangePermissionsExportResumeData.ExchangePermissionsExportParameters
                }
                $false
                {
                    $ExportExchangePermissionsExportResumeData.ExchangePermissionsExportParameters = @(GetAllParametersWithAValue -boundparameters $PSBoundParameters -allparameters $MyInvocation.MyCommand.Parameters)
                }
            }
            $message = 'Enable Resume and Export Resume Data'
            WriteLog -Message $message -EntryType Attempting
            $ResumeFile = ExportExchangePermissionExportResumeData @ExportExchangePermissionsExportResumeData
            $message = $message + " to file $ResumeFile"
            WriteLog -Message $message -EntryType Succeeded
        }
        #these have to be populated as we go
        $DomainPrincipalHash = @{}
        $UnfoundIdentitiesHash = @{}
        if ($expandGroups -eq $true)
        {
            $script:ExpandedGroupsNonGroupMembershipHash = @{}
        }
    }
    End
    {
        #Set Up to Loop through Mailboxes/Recipients
        $message = "First Permission Identity will be $($Script:PermissionIdentity)"
        WriteLog -message $message -EntryType Notification
        $ISRCounter = $ResumeIndex
        $ExportedPermissions = @(
            :nextISR for
            (
                $i = $ResumeIndex
                $i -le $InScopeRecipientCount - 1
                $(if ($Recovering) { $i = $ResumeIndex } else { $i++ })
                #$ISR in $InScopeRecipients[$ResumeIndex..$()]
            )
            {
                $Recovering = $false
                $ISRCounter++
                $ISR = $InScopeRecipients[$i]
                $ID = $ISR.guid.guid
                if ($excludedRecipientGUIDHash.ContainsKey($ISR.guid.Guid))
                {
                    WriteLog -Message "Excluding Excluded Recipient $ID"
                    continue nextISR
                }
                $message = "Collect permissions for $($ID)"
                Write-Progress -Activity $message -Status "Items processed: $($ISRCounter) of $($InScopeRecipientCount)" -PercentComplete (($ISRCounter / $InScopeRecipientCount) * 100)
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
                            GetCalendarPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $Script:PSSession -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization -DomainPrincipalHash $DomainPrincipalHash -HRPropertySet $HRPropertySet -UnfoundIdentitiesHash $UnfoundIdentitiesHash -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline
                        }
                        If (($IncludeAllFolder) -and (!($GlobalSendAs)))
                        {
                            Write-Verbose -Message "Getting Folder Permissions for Target $ID"
                            GetAllFolderPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $Script:PSSession -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization -DomainPrincipalHash $DomainPrincipalHash -HRPropertySet $HRPropertySet -UnfoundIdentitiesHash $UnfoundIdentitiesHash -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline
                        }
                        #Get Send As Users
                        If (($IncludeSendAs) -or ($GlobalSendAs))
                        {
                            Write-Verbose -Message "Getting SendAS Permissions for Target $ID"
                            if ($ExchangeOrganizationIsInExchangeOnline -or $UseExchangeCommandsInsteadOfADOrLDAP)
                            {
                                Write-Verbose -Message "Getting SendAS Permissions for Target $ID Via Exchange Commands"
                                GetSendASPermissionsViaExchange -TargetMailbox $ISR -ExchangeSession $Script:PSSession -ObjectGUIDHash $ObjectGUIDHash -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -dropInheritedPermissions $dropInheritedPermissions -DomainPrincipalHash $DomainPrincipalHash -ExchangeOrganization $ExchangeOrganization -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -HRPropertySet $HRPropertySet -UnfoundIdentitiesHash $UnfoundIdentitiesHash
                            }
                            else
                            {
                                Write-Verbose -Message "Getting SendAS Permissions for Target $ID Via LDAP Commands"
                                GetSendASPermisssionsViaLocalLDAP -TargetMailbox $ISR -ExchangeSession $Script:PSSession -ObjectGUIDHash $ObjectGUIDHash -excludedTrusteeGUIDHash $excludedRecipientGUIDHash -dropInheritedPermissions $dropInheritedPermissions -DomainPrincipalHash $DomainPrincipalHash -ExchangeOrganization $ExchangeOrganization -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -HRPropertySet $HRPropertySet -UnfoundIdentitiesHash $UnfoundIdentitiesHash
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
                        if ($ExchangeOrganizationIsInExchangeOnline -or $UseExchangeCommandsInsteadOfADOrLDAP)
                        { $splat.UseExchangeCommandsInsteadOfADOrLDAP = $true }
                        $PermissionExportObjects = @(ExpandGroupPermission @splat)
                    }
                    if (TestExchangePSSession -PSSession $Script:PSSession)
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
                            $ISRCounter--
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
                            if ($EnableResume -eq $true)
                            {
                                WriteLog -Message "Resume File $ResumeFile is available to resume this operation after you have re-connected the Exchange Session" -Verbose
                                WriteLog -Message "Resume Recipient ID is $ID" -Verbose
                                $ResumeIDFile = ExportResumeID -ID $ID -outputFolderPath $OutputFolderPath -TimeStamp $BeginTimeStamp -NextPermissionID $Script:PermissionIdentity
                                WriteLog -Message "Resume ID $ID exported to file $resumeIDFile" -Verbose
                                WriteLog -Message "Next Permission Identity $($Script:PermissionIdentity) exported to file $resumeIDFile" -Verbose
                                $message = "Run `'Get-ExchangePermission -ResumeFile $ResumeFile`' and also specify any common parameters desired (such as -verbose) since common parameters are not included in the Resume Data File."
                                WriteLog -Message $message -EntryType Notification -verbose
                            }
                            Break nextISR
                        }
                    }
                }
                Catch
                {
                    $myerror = $_
                    WriteLog -Message $message -EntryType Failed -ErrorLog -Verbose
                    $exitmessage = "Exchange Session Failed/Disconnected during permission processing for ID $ID. The next Log entry is the error from the Exchange Session."
                    WriteLog -Message $exitmessage -EntryType Notification -ErrorLog -Verbose
                    WriteLog -Message $myError.tostring() -ErrorLog -Verbose
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
                        $ISRCounter--
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
                        if ($EnableResume -eq $true)
                        {
                            WriteLog -Message "Resume File $ResumeFile is available to resume this operation after you have re-connected the Exchange Session" -Verbose
                            WriteLog -Message "Resume Recipient ID is $ID" -Verbose
                            $ResumeIDFile = ExportResumeID -ID $ID -outputFolderPath $OutputFolderPath -TimeStamp $BeginTimeStamp -NextPermissionID $Script:PermissionIdentity
                            WriteLog -Message "Resume ID $ID exported to file $resumeIDFile" -Verbose
                            WriteLog -Message "Next Permission Identity $($Script:PermissionIdentity) exported to file $resumeIDFile" -Verbose
                            $message = "Run `'Get-ExchangePermission -ResumeFile $ResumeFile`' and also specify any common parameters desired (such as -verbose) since common parameters are not included in the Resume Data File."
                            WriteLog -Message $message -EntryType Notification -verbose
                        }
                        Break nextISR
                    }
                }
            }#Foreach recipient in set
        )# end ExportedPermissions
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
