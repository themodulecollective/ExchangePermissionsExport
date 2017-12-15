
function New-PermissionExportObject
    {
        [cmdletbinding()]
        param(
        [parameter(Mandatory)]
        $TargetMailbox
        ,
        [parameter(Mandatory)]
        [string]$TrusteeIdentity
        ,
        [parameter(Mandatory)]
        [ValidateSet('FullAccess','SendOnBehalf','SendAs','None')]
        $PermissionType
        ,
        [parameter()]
        [ValidateSet('Direct','GroupMembership','None')]
        [string]$AssignmentType = 'Direct'
        ,
        $TrusteeGroupObjectGUID
        ,
        $ParentPermissionIdentity
        ,
        [string]$SourceExchangeOrganization = $ExchangeOrganization
        ,
        [boolean]$IsInherited = $False #Export-Permissions currently does not export inherited permissions for FullAccess, and they are not possible for SendOnBehalf, so this will get set to $true only for certain Send As permissions
        )#End Param
        $Script:PermissionIdentity++
        [pscustomobject]@{
            PermissionIdentity = $Script:PermissionIdentity
            ParentPermissionIdentity = $ParentPermissionIdentity
            SourceExchangeOrganization = $SourceExchangeOrganization
            TargetObjectGUID = $TargetMailbox.Guid.Guid
            TargetObjectExchangeGUID = $TargetMailbox.ExchangeGuid.Guid
            TargetDistinguishedName = $TargetMailbox.DistinguishedName
            TargetPrimarySMTPAddress = $TargetMailbox.PrimarySmtpAddress.ToString()
            TargetRecipientType = $TargetMailbox.RecipientType
            TargetRecipientTypeDetails = $TargetMailbox.RecipientTypeDetails
            PermissionType = $PermissionType
            AssignmentType = $AssignmentType
            TrusteeGroupObjectGUID = $TrusteeGroupObjectGUID
            TrusteeIdentity = $TrusteeIdentity
            IsInherited = $IsInherited
        }
    }
#end function New-PermissionExportObject

function Add-TrusteeAttributesToPermissionExportObject
{
    [cmdletbinding()]
    param
    (
    [parameter(Mandatory)]
    [Alias('rpeo')]
    $rawPermissionExportObject
    ,
    [parameter(Mandatory)]
    [Alias('Recipient','Mailbox')]
    [AllowNull()]
    $TrusteeRecipientObject
    ,
    [switch]$None
    )#End Param
    if ($TrusteeRecipientObject -ne $null)
    {
        $MorePermissionExportProperties = @{
            TrusteeObjectGUID = $TrusteeRecipientObject.guid.Guid
            TrusteeExchangeGUID = $TrusteeRecipientObject.ExchangeGuid.Guid
            TrusteeDistinguishedName = $TrusteeRecipientObject.DistinguishedName
            TrusteePrimarySMTPAddress = $TrusteeRecipientObject.PrimarySmtpAddress.ToString()
            TrusteeRecipientType = $TrusteeRecipientObject.RecipientType
            TrusteeRecipientTypeDetails = $TrusteeRecipientObject.RecipientTypeDetails
            
        }
    }
    else
    {
        $MorePermissionExportProperties = @{
            TrusteeObjectGUID = $null
            TrusteeExchangeGUID = $TrusteeRecipientObject.ExchangeGuid.Guid
            TrusteeDistinguishedName = if ($None) {'none'} else {$null}
            TrusteePrimarySMTPAddress = if ($None) {'none'} else {$null}
            TrusteeRecipientType = $null
            TrusteeRecipientTypeDetails = $null
        }
    }
    Add-Member -InputObject $rawPermissionExportObject -NotePropertyMembers $MorePermissionExportProperties
}
#end function Add-TrusteeAttributesToPermissionExportObject

Function Get-SIDHistoryRecipientHash 
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            $ActiveDirectoryDrive
            ,
            $ExchangeSession
        )#End param

        Push-Location
        Write-Log -Message "Operation: Retrieve Mapping for all User Recipients with SIDHistory."

        #Region GetSIDHistoryUsers
        Set-Location $($ActiveDirectoryDrive.Name + ':\') -ErrorAction Stop
        Try
        {
            $message = "Get AD Users with SIDHistory from AD Drive $($activeDirectoryDrive.Name)"
            Write-Log -Message $message -EntryType Attempting
            $sidHistoryUsers = @(Get-Aduser -ldapfilter "(&(legacyExchangeDN=*)(sidhistory=*))" -Properties sidhistory,legacyExchangeDN -ErrorAction Stop)
            Write-Log -Message $message -EntryType Succeeded
        }
        Catch
        {
            $myError = $_
            Write-Log -Message $message -EntryType Failed -ErrorLog
            Write-Log -Message $myError.tostring() -ErrorLog
            throw("Failed: $Message")
        }
        Pop-Location
        Write-Log -Message "Got $($sidHistoryUsers.count) Users with SID History from AD $($ActiveDirectoryDrive.name)" -EntryType Notification
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
                Write-Progress -Activity $message -status "Items processed: $($sidhistoryusercounter) of $($sidhistoryusers.Count)" -percentComplete (($sidhistoryusercounter / $($sidhistoryusers.Count))*100)
            }
            $splat = @{Identity = $shu.ObjectGuid.guid; ErrorAction = 'SilentlyContinue'} #is this a good assumption?
            $sidhistoryuserrecipient = $Null
            $sidhistoryuserrecipient = Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @using:splat} -ErrorAction SilentlyContinue
            If ($null -ne $sidhistoryuserrecipient)
            {
                Foreach ($sidhistorysid in $shu.sidhistory)
                {
                    $SIDHistoryRecipientHash.$($sidhistorysid.value) = $sidhistoryuserrecipient
                }#End Foreach
            }#end If
        }#End Foreach
        Write-Output $SIDHistoryRecipientHash
    }
#End Get-SIDHistoryRecipientHash

Function Get-SendOnBehalfPermission
{#Get Delegate Users (NOTE: actual permissions are stored in the mailbox . . . so these are not true delegates just a likely correlation to delegates)
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
        $ExchangeOrganization
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    if ($Mailbox.GrantSendOnBehalfTo.ToArray().count -ne 0)
    {
        Write-Verbose -message "Target Mailbox has entries in GrantSendOnBehalfTo"
        $splat = @{
            Identity = $Mailbox.guid.guid
            ErrorAction = 'Stop'
        }
        Write-Verbose -Message "Getting Trustee Objects from GrantSendOnBehalfTo"
        $sbTrustees = Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Mailbox @using:splat | Select-Object -ExpandProperty GrantSendOnBehalfTo}
        foreach ($sb in $sbTrustees)
        {
            $trusteeRecipient = $(
                switch ($ObjectGUIDHash.ContainsKey($sb.ObjectGUID.guid))
                {
                    $true
                    {
                        $ObjectGUIDHash.$($sb.ObjectGUID.guid)
                    }
                    $false
                    {
                        $splat = @{
                            Identity = $sb.ObjectGuid.guid
                            ErrorAction = 'SilentlyContinue'
                        }
                        Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @using:splat} -ErrorAction SilentlyContinue -OutVariable AddToLookup
                        if ($null -ne $AddToLookup)
                        {
                            $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$ObjectGUIDHash.$($_.ExchangeGuid.Guid) = $_} -ErrorAction SilentlyContinue
                            $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$ObjectGUIDHash.$($_.Guid.Guid) = $_} -ErrorAction SilentlyContinue
                        }
                    }
                }
            )
            if ($null -ne $trusteeRecipient -and -not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
            {
                $npeoParams = @{
                    TargetMailbox = $TargetMailbox
                    TrusteeIdentity = $trusteeRecipient.Guid.Guid
                    PermissionType = 'SendOnBehalf'
                    AssignmentType = if ($trusteeRecipient.RecipientTypeDetails -like '*group*') {'GroupMembership'} else {'Direct'}
                    SourceExchangeOrganization = $ExchangeOrganization
                }
                New-PermissionExportObject @npeoParams
            }
        }#end foreach
    }
}
#end function Get-SendOnBehalfPermission

function Get-FullAccessPermission
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
        [bool]$dropInheritedPermissions
        ,
        [hashtable]$DomainPrincipalHash
        ,
        $ExchangeOrganization
    )
    $splat = @{Identity = $TargetMailbox.guid.guid; ErrorAction = 'Stop'}
    $FilterScriptString = '($_.AccessRights -like "*FullAccess*") -and -not ($_.User -like "NT AUTHORITY\SELF") -and -not ($_.Deny -eq $True) -and -not ($_.User -like "S-1-5*")'
    if ($dropInheritedPermissions -eq $true)
    {
        $FilterScriptString = $FilterScriptString + ' -and ($_.IsInherited -eq $false)'
    }
    $filterscript = [scriptblock]::Create($FilterScriptString)
    #add code to check session
    $faRawPermissions = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-MailboxPermission @using:splat} -ErrorAction Stop) | Where-Object -FilterScript $filterscript
    Write-Verbose -Message "$($farawPermissions.Count) Full Access Permissions Found for Target Mailbox"
    foreach ($fa in $faRawPermissions)
    {
        $user = $fa.User
        $trusteeRecipient = $(
            switch ($DomainPrincipalHash.ContainsKey($user))
            {
                $true
                {
                    $DomainPrincipalHash.$($user)
                }
                $false
                {
                    $splat = @{
                        Identity = $user
                        ErrorAction = 'SilentlyContinue'
                    }
                    Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @using:splat} -ErrorAction SilentlyContinue -OutVariable AddToLookup
                    if ($null -ne $AddToLookup)
                    {
                        $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$ObjectGUIDHash.$($_.ExchangeGuid.Guid) = $_} -ErrorAction SilentlyContinue
                        $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$ObjectGUIDHash.$($_.Guid.Guid) = $_} -ErrorAction SilentlyContinue
                        $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$DomainPrincipalHash.$($user) = $_} -ErrorAction SilentlyContinue
                    }
                }
            }#end Switch
        )
        if ($null -ne $trusteeRecipient -and -not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
        {
            $npeoParams = @{
                TargetMailbox = $TargetMailbox
                TrusteeIdentity = $trusteeRecipient.Guid.Guid
                PermissionType = 'FullAccess'
                AssignmentType = if ($trusteeRecipient.RecipientTypeDetails -like '*group*') {'GroupMembership'} else {'Direct'}
                SourceExchangeOrganization = $ExchangeOrganization
            }
            New-PermissionExportObject @npeoParams
        }
    }#end foreach fa
}

Function Export-Permissions
{
    #ToDo
    #Add an attribute to the permission object which indicates if the target/permholder were in the mailboxes scope
    #use get-group and/or get-user when get-recipient fails to get an object
    #Fix Fullaccess to leverage SID History and Inheritance options
    #Make inheritance work for expanded group perms, too. right now will say false for all which isn't correct.
    #add excluded prefixes with split on \
    #add scoping by OU? integrate EXO recipients as a filter of some sort?
    #implement explicit garbage collection. 

    #fix ugly out-file hack -- done
    #fix denies --done
    #globalsendas -- done
    ##parameterset -- done
    ##recip instead of mailbox -- done just for globalsendas
    #sid stuff -- done
    #AD connection -- done
    #inheritance switch and output -- done
    #hard-code sendas guid -- done
    #add genericall -- done
    #add group detection for SendOnBehalf -- done
    [cmdletbinding(DefaultParameterSetName = 'AllMailboxes')]
    param
    (
        [parameter(Mandatory)]
        [ValidateScript({$_.state -eq 'Opened' -and $_.Availability -eq 'Available'})]
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        [parameter(Mandatory)]
        [ValidateScript({Test-isWriteAbleDirectory -Path $_})]
        $OutputFolderPath
        ,
        [parameter(ParameterSetName = 'GlobalSendAs',Mandatory)]
        [switch]$GlobalSendAs
        ,
        [parameter(ParameterSetName = 'Scoped',Mandatory)]
        [string[]]$Identity
        ,
        [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
        [switch]$AllMailboxes
        ,
        [parameter()]#These will be resolved to recipient objects
        [string[]]$ExcludedIdentities
        ,
        [string[]]$ExcludedTrusteeIdentities
        ,
        [parameter(ParameterSetName = 'Scoped',Mandatory)]
        [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
        [bool]$IncludeSendOnBehalf = $true
        ,
        [parameter(ParameterSetName = 'Scoped',Mandatory)]
        [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
        [bool]$IncludeFullAccess = $true
        ,
        [parameter(ParameterSetName = 'Scoped',Mandatory)]
        [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
        [bool]$IncludeSendAs = $true
        ,
        [bool]$expandGroups = $true
        ,
        [bool]$dropExpandedGroups = $false
        ,
        [bool]$dropInheritedPermissions = $false #Currently Functional Only For Send-As, though this function is hard-coded to ignore inherited FMB and inherited SendOnBehalf is not possible.
        ,
        [bool]$IncludeSIDHistory = $false
        ,
        [parameter()]
        [ValidateScript({$_.gettype().name -eq 'ADDriveInfo'})]#doing this as a validatescript instead of a type declaration so that this will run on a system that lacks the ActiveDirectory module if the user doesn't need this parameter.
        $ActiveDirectoryDrive
    )#End Param
    Begin
    {
        $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $BeginTimeStamp = Get-Date -Format yyyyMMdd-HHmmss
        $script:LogPath = Join-Path -path $OutputFolderPath -ChildPath $($BeginTimeStamp + 'ExchangePermissionsExportOperations.log')
        $script:ErrorLogPath = Join-Path -path $OutputFolderPath -ChildPath $($BeginTimeStamp + 'ExchangePermissionsExportOperations-ERRORS.log')
        Write-Log -Message "Calling Invocation = $($MyInvocation.Line)" -EntryType Notification
        $ExchangeOrganization = Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-OrganizationConfig | Select-Object -ExpandProperty Identity | Select-Object -ExpandProperty Name}
        $ExchangeOrganizationIsInExchangeOnline = $ExchangeOrganization -like '*.onmicrosoft.com'
        Write-Log -Message "Provided Exchange Session is Running in Exchange Organzation $ExchangeOrganization" -EntryType Notification
        if ($IncludeSIDHistory -eq $true)
        {
            if ($null -eq $ActiveDirectoryDrive)
            {throw("If IncludeSIDHistory is required an Active Directory PS Drive connection to the appropriate domain or forest must be provided")}
        }
        if ($IncludeSendAs -eq $true -or $GlobalSendAs -eq $true)
        {
            #Well-known GUID for Send As Permissions, see function Get-SendASRightGUID
            $SendASRight = [GUID]'ab721a54-1e2f-11d0-9819-00aa0040529b' 
        }
    }
    End
    {
        #Region GetExcludedRecipients
        if ($PSBoundParameters.ContainsKey('ExcludedIdentities'))
        {
            try
            {
                $message = "Get recipent object(s) from Exchange Organization $ExchangeOrganization for the $($ExcludedIdentities.Count) ExcludedIdentities provided."
                Write-Log -Message $message -EntryType Attempting
                $excludedRecipients = @(
                    $ExcludedIdentities | ForEach-Object {
                        $splat = @{
                            Identity = $_
                            ErrorAction = 'Stop'
                        }
                        Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @Using:splat} -ErrorAction 'Stop'
                    }
                )
                Write-Log -Message $message -EntryType Succeeded
            }
            Catch
            {
                $myError = $_
                Write-Log -Message $message -EntryType Failed -ErrorLog
                Write-Log -Message $myError.tostring() -ErrorLog
                throw("Failed: $Message")
            }
            Write-Log -Message "Got $($excludedRecipients.count) Excluded Objects" -EntryType Notification
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
                Write-Log -Message $message -EntryType Attempting
                $excludedTrusteeRecipients = @(
                    $ExcludedTrusteeIdentities | ForEach-Object {
                        $splat = @{
                            Identity = $_
                            ErrorAction = 'Stop'
                        }
                        Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @Using:splat} -ErrorAction 'Stop'
                    }
                )
                Write-Log -Message $message -EntryType Succeeded
            }
            Catch
            {
                $myError = $_
                Write-Log -Message $message -EntryType Failed -ErrorLog
                Write-Log -Message $myError.tostring() -ErrorLog
                throw("Failed: $Message")
            }
            Write-Log -Message "Got $($excludedTrusteeRecipients.count) Excluded Trustee Objects" -EntryType Notification
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
                    Write-Log -Message "Operation: Scoped Permission retrieval with $($Identity.Count) Identities provided."
                    $message = "Get mailbox object for each provided Identity in Exchange Organization $ExchangeOrganization."
                    Write-Log -Message $message -EntryType Attempting
                    $InScopeRecipients = @(
                        $Identity | ForEach-Object {
                            $splat = @{
                                Identity = $_
                                ErrorAction = 'Stop'
                            }
                            Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @Using:splat} -ErrorAction Stop
                        }
                    )
                    Write-Log -Message $message -EntryType Succeeded
                }#end Scoped
                'AllMailboxes'
                {
                    Write-Log -Message "Operation: Permission retrieval for all mailboxes."
                    $message = "Get all available mailbox objects in Exchange Organization $ExchangeOrganization."
                    Write-Log -Message $message -EntryType Attempting
                    $splat = @{
                        ResultSize = 'Unlimited'
                        ErrorAction = 'Stop'
                    }
                    $InScopeRecipients = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Mailbox @Using:splat} -ErrorAction Stop)
                    Write-Log -Message $message -EntryType Succeeded
                }#end AllMailboxes
                'GlobalSendAs'
                {
                    Write-Log -Message "Operation: Send As Permission retrieval for all recipients."
                    $message = "Get all available recipient objects in Exchange Organization $ExchangeOrganization."
                    Write-Log -Message $message -EntryType Attempting
                    $splat = @{
                        ResultSize = 'Unlimited'
                        ErrorAction = 'Stop'
                    }
                    $InScopeRecipients = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @Using:splat} -ErrorAction Stop)
                    Write-Log -Message $message -EntryType Succeeded
                }#end GlobalSendAS
            }#end Switch
        }#end try
        Catch
        {
            $myError = $_
            Write-Log -Message $message -EntryType Failed -ErrorLog
            Write-Log -Message $myError.tostring() -ErrorLog
            throw("Failed: $Message")
        }
        $InScopeRecipientCount = $InScopeRecipients.count
        Write-Log -Message "Got $InScopeRecipientCount In Scope Objects" -EntryType Notification
        #EndRegion GetInScopeRecipients

        #Region GetSIDHistoryData
        if ($IncludeSIDHistory -eq $true)
        {
            $SIDHistoryRecipientHash = Get-SIDHistoryRecipientHash -ActiveDirectoryDrive $ActiveDirectoryDrive -ExchangeSession $ExchangeSession -ErrorAction Stop
        }
        #EndRegion GetSIDHistoryData

        #Region BuildLookupHashTables
        Write-Log -Message "Building Recipient Lookup HashTables" -EntryType Notification
        $HRPropertySet = @('*name*','*addr*','RecipientType*','*Id','Identity')
        $ObjectGUIDHash = $InScopeRecipients | Select-object -property $HRPropertySet | Group-Object -AsHashTable -Property Guid -AsString
        #Also Add the Exchange GUIDs to this lookup if we are dealing with Exchange Online
        if ($ExchangeOrganizationIsInExchangeOnline)
        {
            $InScopeRecipients | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$ObjectGUIDHash.$($_.ExchangeGuid.Guid) = $_}
        }
        if ($expandGroups -eq $true)
        {
            $DistinguishedNameHash = $InScopeRecipients | Select-object -property $HRPropertySet | Group-Object -AsHashTable -Property DistinguishedName -AsString
        }
        $DomainPrincipalHash = @{}
        #EndRegion BuildLookupHashtables

        #Set Up to Loop through Mailboxes/Recipients
        $ISRCounter = 0
        [uint32]$Script:PermissionIdentity = 0
        :nextISR Foreach ($ISR in $InScopeRecipients) #$mailbox
        {
            $ISRCounter++
            $ID = $ISR.guid.guid
            if ($excludedRecipientGUIDHash.ContainsKey($ISR.guid.Guid))
            {
                Write-Log -Message "Excluding Excluded Recipient $ID"
                continue nextISR
            }
            $message = "Collect permissions for $($ID)"
            Write-Progress -Activity $message -status "Items processed: $($ISRCounter) of $($InScopeRecipientCount)" -percentComplete (($ISRCounter / $InScopeRecipientCount)*100)
            Write-Log -Message $message -EntryType Attempting
            $rawPermissions = @(
                If (($IncludeSendOnBehalf) -and (!($GlobalSendAs)))
                {
                    Get-SendOnBehalfPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $ExchangeSession -ExcludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization
                }
                If (($IncludeFullAccess) -and (!($GlobalSendAs)))
                {
                    Get-FullAccessPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $ExchangeSession -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization
                }
                #Get Send As Users
                If (($IncludeSendAs) -or ($GlobalSendAs))
                {
                    #add code to check session
                    if ($ExchangeOrganizationIsInExchangeOnline)
                    {
                        $splat = @{
                            ErrorAction = 'Stop'
                            ResultSize = 'Unlimited'
                            Identity = $ID
                            AccessRights = 'SendAs'
                        }
                        $saRawPermissions = Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-RecipientPermission @using:splat} -ErrorAction Stop
                        if ($dropInheritedPermissions)
                        {$saRawPermissions = $saRawPermissions | Where-Object -FilterScript {$_.IsInherited -eq $false}}
                        $saRawPermissions |
                        ForEach-Object {
                            New-PermissionExportObject -TargetMailbox $ISR -TrusteeIdentity $_.Trustee -PermissionType SendAs -AssignmentType Direct -SourceExchangeOrganization $ExchangeOrganization -IsInherited $_.IsInherited
                        }
                    }
                    else
                    {
                        $userDN = [ADSI]("LDAP://$($ISR.DistinguishedName)")
                        $saTrustees = @(
                            $userDN.psbase.ObjectSecurity.Access | Where-Object -FilterScript { (($_.ObjectType -eq $SendASRight) -or ($_.ActiveDirectoryRights -eq 'GenericAll')) -and ($_.AccessControlType -eq 'Allow')} | Where-Object -FilterScript {$_.IdentityReference -notlike "NT AUTHORITY\SELF"}| Select-Object identityreference,IsInherited 
                            #
                            # Where-Object -FilterScript {($_.identityreference.ToString().split('\')[0]) -notin $ExcludedTrusteeDomains}|
                            # Where-Object -FilterScript {$_.identityreference -notin $ExcludedTrustees}|
                        )
                        foreach ($sa in $saTrustees)
                        {	
                            If ($sa.IsInherited -eq $true -and $dropInheritedPermissions -eq $true)
                            {
                                #drop this perm
                            }#End If
                            else
                            {
                                New-PermissionExportObject -TargetMailbox $ISR -TrusteeIdentity $sa.identityreference -PermissionType SendAs -AssignmentType Direct -SourceExchangeOrganization $ExchangeOrganization -IsInherited $sa.IsInherited
                            }
                        }
                    }
                }
            )
            #compile permissions information and permission holders identity details
            $MissingOrAmbiguousRecipients = @()
            foreach ($rp in $rawPermissions)
            {
                $Recipient = @()
                switch ($rp.PermissionType)
                {
                    'SendOnBehalf' #uses CanonicalName format!?! (on premises) or DisplayName (Exchange Online) !?! Silliness.
                    {
                        if ($ObjectGUIDHash.ContainsKey($rp.TrusteeIdentity))
                        {
                            $Recipient = @($ObjectGUIDHash.$($rp.TrusteeIdentity))
                        }
                    }
                    Default #both SendAs and FullAccess use Domain\SecurityPrincipal format
                    {
                        if ($DomainPrincipalHash.ContainsKey($rp.TrusteeIdentity))
                        {
                            $Recipient = @($DomainPrincipalHash.$($rp.TrusteeIdentity))
                        }
                        elseif ($IncludeSIDHistory -eq $true -and $SIDHistoryRecipientHash.ContainsKey($rp.TrusteeIdentity))
                        {
                            $Recipient = @($SIDHistoryRecipientHash.$($rp.TrusteeIdentity))
                        }#End elseif
                    }
                }
                if ($Recipient.Count -eq 0)
                {
                    $splat = @{Identity = $rp.TrusteeIdentity; ErrorAction = 'SilentlyContinue'}
                    #add code to check session
                    $Recipient = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @using:splat} -ErrorAction SilentlyContinue)
                }
                switch ($Recipient.Count) 
                {
                    1
                    {#not sure at this point why we are doing this here . . . 
                        $Recipient = $Recipient[0]
                        Add-TrusteeAttributesToPermissionExportObject -rawPermissionExportObject $rp -TrusteeRecipientObject $Recipient
                        switch ($rp.permissionType) {
                            'SendOnBehalf' {$ObjectGUIDHash.$($rp.TrusteeIdentity) = $Recipient}
                            Default {$DomainPrincipalHash.$($rp.TrusteeIdentity) = $Recipient}
                        }
                    }#1
                    Default
                    {
                        $MissingOrAmbiguousRecipients += $rp.TrusteeIdentity
                        Add-TrusteeAttributesToPermissionExportObject -rawPermissionExportObject $rp -TrusteeRecipientObject $null
                    }#Default
                }#switch Recipient.Count
            }#foreach Rp in RawPermissions

            if ($expandGroups)
            {
                #enumerate groups: http://stackoverflow.com/questions/8055338/listing-users-in-ad-group-recursively-with-powershell-script-without-cmdlets/8055996#8055996
                $dse = [ADSI]"LDAP://Rootdse"
                $dn = [ADSI]"LDAP://$($dse.DefaultNamingContext)"
                $dsLookFor = New-Object System.DirectoryServices.DirectorySearcher($dn)
                $expandedPermissions = @(
                    $groupPerms = @($rawPermissions | Where-Object -FilterScript {$_.TrusteeRecipientTypeDetails -like '*Group*'})
                    foreach ($gp in $groupPerms)
                    {
                        $dsLookFor.Filter = "(&(memberof:1.2.840.113556.1.4.1941:=$($gp.TrusteeDistinguishedName))(objectCategory=user))" 
                        $dsLookFor.SearchScope = "subtree" 
                        $lstUsr = $dsLookFor.findall()
                        foreach ($u in $lstUsr)
                        {
                            $uDN = $u.Properties.distinguishedname
                            if ($DistinguishedNameHash.ContainsKey("$uDN"))
                            {$Recipient = @($DistinguishedNameHash."$uDN")}
                            else
                            {
                                $splat = @{Identity = "$uDN"; ErrorAction = 'SilentlyContinue'}
                                $Recipient = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @using:splat} -ErrorAction SilentlyContinue)
                            }
                            switch ($Recipient.count)
                            {
                                1
                                {
                                    $Recipient = $Recipient[0]
                                    $GPEOParams = @{
                                        TargetMailbox = $ISR
                                        TrusteeIdentity = $Recipient.DistinguishedName
                                        PermissionType = $gp.PermissionType
                                        AssignmentType = 'GroupMembership'
                                        TrusteeGroupObjectGUID = $gp.TrusteeObjectGUID
                                        SourceExchangeOrganization = $ExchangeOrganization
                                        ParentPermissionIdentity = $gp.PermissionIdentity
                                    }
                                    $rawEP = New-PermissionExportObject @GPEOParams
                                    Add-TrusteeAttributesToPermissionExportObject -rawPermissionExportObject $rawEP -TrusteeRecipientObject $Recipient
                                    Write-Output $rawEP
                                    $DistinguishedNameHash.$uDN = $Recipient
                                }#1
                                Default
                                {
                                    $GPEOParams = @{
                                        TargetMailbox = $ISR
                                        TrusteeIdentity = "$uDN"
                                        PermissionType = $gp.PermissionType
                                        AssignmentType = 'GroupMembership'
                                        TrusteeGroupObjectGUID = $gp.TrusteeObjectGUID
                                        SourceExchangeOrganization = $ExchangeOrganization
                                        ParentPermissionIdentity = $gp.PermissionIdentity
                                    }
                                    $rawEP = New-PermissionExportObject @GPEOParams
                                    Add-TrusteeAttributesToPermissionExportObject -rawPermissionExportObject $rawEP -TrusteeRecipientObject $null
                                    $MissingOrAmbiguousRecipients += $rp.TrusteeIdentity
                                }#Default
                            }#switch Recipient.Count
                        }#foreach u in lstusr
                    }#foreach gp in groupPerms
                )#expandedPermissions
                if ($dropExpandedGroups)
                {
                    $rawPermissions = $rawPermissions | Where-Object -FilterScript {$_.TrusteeRecipientTypeDetails -notlike '*group*'}
                }
            }
            #combine and remove and self permissions that came in through expansion or otherwise
            if ($expandedPermissions.Count -ge 1)
            {$AllPermissionsOutput = $expandedPermissions + $rawPermissions | Where-Object -FilterScript {$_.TargetObjectGUID -ne $_.TrusteeObjectGUID}}
            else
            {$AllPermissionsOutput = $rawPermissions | Where-Object -FilterScript {$_.TargetObjectGUID -ne $_.TrusteeObjectGUID}}
            #remove permissions from excludedPermissionHolders if needed
            if ($PSBoundParameters.ContainsKey('ExcludedIdentities'))
            {
                $AllPermissionsOutput = @(
                    $AllPermissionsOutput | Where-Object -FilterScript {
                        ($_.TrusteeObjectGUID -eq $null) -or
                        (-not $excludedRecipientGUIDHash.ContainsKey($_.TrusteeObjectGUID)) #this is wrong now that we've separated exclusion between recipient and trustee
                    }
                )
            }
            if ($AllPermissionsOutput.Count -eq 0)
            {
                $GPEOParams = @{
                    TargetMailbox = $ISR
                    TrusteeIdentity = 'Not Applicable'
                    PermissionType = 'None'
                    AssignmentType = 'None'
                    SourceExchangeOrganization = $ExchangeOrganization
                }
                $NonPerm = New-PermissionExportObject @GPEOParams
                Add-TrusteeAttributesToPermissionExportObject -rawPermissionExportObject $NonPerm -TrusteeRecipientObject $null -None
                Write-Output $NonPerm
            }
            else
            {
                Write-Output $AllPermissionsOutput
            }
            Write-Log -Message $message -EntryType Succeeded
        }#Foreach recipient in set

        if ($MissingOrAmbiguousRecipients.count -ge 1)
        {
            $MissingOrAmbiguousRecipients = $MissingOrAmbiguousRecipients | Sort-Object | Select-Object -Unique
            $joinedIDs = $MissingOrAmbiguousRecipients -join '|'
            Write-Log -Message "The following identities are missing (as recipient objects) or ambiguous: $joinedIDs" -EntryType Notification -ErrorLog
            $ExportFilePath = join-path $OutputFolderPath  $($BeginTimeStamp + '-MissingOrAmbiguousRecipients' + '.txt')
            $MissingOrAmbiguousRecipients | out-file $exportFilePath
        }
    }#end End
}
#End Function Export-Permissions
###################################################################
#Import Additional Files
###################################################################
. $(Join-Path $PSScriptRoot 'SupportAndThirdPartyFunctions.ps1')