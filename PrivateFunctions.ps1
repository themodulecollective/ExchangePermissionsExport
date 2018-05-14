###################################################################
#Get/Expand Permission Functions
###################################################################
Function GetSIDHistoryRecipientHash
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $ActiveDirectoryDrive
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
    )#End param

    Push-Location
    WriteLog -Message "Operation: Retrieve Mapping for all User Recipients with SIDHistory."

    #Region GetSIDHistoryUsers
    Set-Location $($ActiveDirectoryDrive.Name + ':\') -ErrorAction Stop
    Try
    {
        $message = "Get AD Users with SIDHistory from AD Drive $($activeDirectoryDrive.Name)"
        WriteLog -Message $message -EntryType Attempting
        $sidHistoryUsers = @(Get-Aduser -ldapfilter "(&(legacyExchangeDN=*)(sidhistory=*))" -Properties sidhistory, legacyExchangeDN -ErrorAction Stop)
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
            Write-Progress -Activity $message -status "Items processed: $($sidhistoryusercounter) of $($sidhistoryusers.Count)" -percentComplete (($sidhistoryusercounter / $($sidhistoryusers.Count)) * 100)
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
    $SIDHistoryRecipientHash
}
#End GetSIDHistoryRecipientHash
function GetTrusteeObject
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory)]
        [AllowNull()]
        [string]$TrusteeIdentity
        ,
        [string[]]$HRPropertySet
        ,
        [hashtable]$ObjectGUIDHash
        ,
        [hashtable]$DomainPrincipalHash
        ,
        [hashtable]$SIDHistoryHash
        ,
        [hashtable]$UnfoundIdentitiesHash
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        $ExchangeOrganizationIsInExchangeOnline
    )
    $trusteeObject = $(
        $AddToLookup = $null
        #Write-Verbose -Message "Getting Object for TrusteeIdentity $TrusteeIdentity"
        switch ($TrusteeIdentity)
        {
            {$UnfoundIdentitiesHash.ContainsKey($_)}
            {
                $null
                break
            }
            {$ObjectGUIDHash.ContainsKey($_)}
            {
                $ObjectGUIDHash.$($_)
                #Write-Verbose -Message 'Found Trustee in ObjectGUIDHash'
                break
            }
            {$DomainPrincipalHash.ContainsKey($_)}
            {
                $DomainPrincipalHash.$($_)
                #Write-Verbose -Message 'Found Trustee in DomainPrincipalHash'
                break
            }
            {$SIDHistoryHash.ContainsKey($_)}
            {
                $SIDHistoryHash.$($_)
                #Write-Verbose -Message 'Found Trustee in SIDHistoryHash'
                break
            }
            {$null -eq $TrusteeIdentity}
            {
                $null
                break
            }
            Default
            {
                if ($ExchangeOrganizationIsInExchangeOnline -and $TrusteeIdentity -like '*\*')
                {
                    $null
                }
                else
                {
                    $splat = @{
                        Identity    = $TrusteeIdentity
                        ErrorAction = 'SilentlyContinue'
                    }
                    Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @using:splat} -ErrorAction SilentlyContinue -OutVariable AddToLookup
                    if ($null -eq $AddToLookup)
                    {
                        Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Group @using:splat} -ErrorAction SilentlyContinue -OutVariable AddToLookup
                    }
                    if ($null -eq $AddToLookup)
                    {
                        Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-User @using:splat} -ErrorAction SilentlyContinue -OutVariable AddToLookup
                    }
                }
            }
        }
    )
    #if we found a 'new' object add it to the lookup hashtables
    if ($null -ne $AddToLookup -and $AddToLookup.count -gt 0)
    {
        #Write-Verbose -Message "Found Trustee $TrusteeIdentity via new lookup"
        $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$ObjectGUIDHash.$($_.ExchangeGuid.Guid) = $_} -ErrorAction SilentlyContinue
        #Write-Verbose -Message "ObjectGUIDHash Count is $($ObjectGUIDHash.count)"
        $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$ObjectGUIDHash.$($_.Guid.Guid) = $_} -ErrorAction SilentlyContinue
        if ($TrusteeIdentity -like '*\*' -or $TrusteeIdentity -like '*@*')
        {
            $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$DomainPrincipalHash.$($TrusteeIdentity) = $_} -ErrorAction SilentlyContinue
            #Write-Verbose -Message "DomainPrincipalHash Count is $($DomainPrincipalHash.count)"
        }
    }
    #if we found nothing, add the Identity to the UnfoundIdentitiesHash
    if ($null -eq $trusteeObject -and $null -ne $TrusteeIdentity -and -not [string]::IsNullOrEmpty($TrusteeIdentity) -and -not $UnfoundIdentitiesHash.ContainsKey($TrusteeIdentity))
    {
        $UnfoundIdentitiesHash.$TrusteeIdentity = $null
    }
    if ($null -ne $trusteeObject -and $trusteeObject.Count -ge 2)
    {
        #TrusteeIdentity is ambiguous.  Need to implement and AmbiguousIdentitiesHash for testing/reporting
        $trusteeObject = $null
    }
    $trusteeObject
}
#end function GetTrusteeObject
Function GetSendOnBehalfPermission
{
    #Get Delegate Users (NOTE: actual permissions are stored in the mailbox . . . so these are not true delegates just a likely correlation to delegates)
    [cmdletbinding()]
    param
    (
        $TargetMailbox
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        [hashtable]$ObjectGUIDHash
        ,
        [hashtable]$DomainPrincipalHash
        ,
        [hashtable]$excludedTrusteeGUIDHash
        ,
        [hashtable]$UnfoundIdentitiesHash
        ,
        $ExchangeOrganization
        ,
        $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    if ($null -ne $TargetMailbox.GrantSendOnBehalfTo -and $TargetMailbox.GrantSendOnBehalfTo.ToArray().count -ne 0)
    {
        #Write-Verbose -message "Target Mailbox has entries in GrantSendOnBehalfTo"
        $splat = @{
            Identity    = $TargetMailbox.guid.guid
            ErrorAction = 'Stop'
        }
        #Write-Verbose -Message "Getting Trustee Objects from GrantSendOnBehalfTo"
        #doing this in try/catch b/c we might find the recipient is no longer a mailbox . . .
        try
        {
            $sbTrustees = Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Mailbox @using:splat | Select-Object -ExpandProperty GrantSendOnBehalfTo} -ErrorAction Stop
        }
        catch
        {
            $myerror = $_
            #if ($myerror.tostring() -like "*isn't a mailbox user.")
            #{$sbTrustees = @()}
            #else
            #{
            #throw($myerror)
            WriteLog -Message $myerror.tostring() -ErrorLog -Verbose -EntryType Failed
            $sbTrustees = @()
            #}
        }
        foreach ($sb in $sbTrustees)
        {
            $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $sb.objectguid.guid -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
            switch ($null -eq $trusteeRecipient)
            {
                $true
                {
                    $npeoParams = @{
                        TargetMailbox              = $TargetMailbox
                        TrusteeIdentity            = $sb.objectguid.guid
                        TrusteeRecipientObject     = $null
                        PermissionType             = 'SendOnBehalf'
                        AssignmentType             = 'Undetermined'
                        SourceExchangeOrganization = $ExchangeOrganization
                        IsInherited                = $false
                    }
                    NewPermissionExportObject @npeoParams
                }#end $true
                $false
                {
                    if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                    {
                        $npeoParams = @{
                            TargetMailbox              = $TargetMailbox
                            TrusteeIdentity            = $sb.objectguid.guid
                            TrusteeRecipientObject     = $trusteeRecipient
                            PermissionType             = 'SendOnBehalf'
                            AssignmentType             = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) {$null {'Undetermined'} '*group*' {'GroupMembership'} Default {'Direct'}}
                            SourceExchangeOrganization = $ExchangeOrganization
                            IsInherited                = $false
                        }
                        NewPermissionExportObject @npeoParams
                    }
                }#end $false
            }#end switch
        }#end foreach
    }
}
#end function GetSendOnBehalfPermission
function GetFullAccessPermission
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
        [hashtable]$UnfoundIdentitiesHash
        ,
        $ExchangeOrganization
        ,
        $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    $splat = @{Identity = $TargetMailbox.guid.guid; ErrorAction = 'Stop'}
    $FilterScriptString = '($_.AccessRights -like "*FullAccess*") -and -not ($_.User -like "NT AUTHORITY\SELF") -and -not ($_.Deny -eq $True) -and -not ($_.User -like "S-1-5*")'
    $filterscript = [scriptblock]::Create($FilterScriptString)
    #doing this in try/catch b/c we might find the recipient is no longer a mailbox . . .
    try
    {
        $faRawPermissions = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-MailboxPermission @using:splat} -ErrorAction Stop) | Where-Object -FilterScript $filterscript
    }
    catch
    {
        $myerror = $_
        #if ($myerror.tostring() -like "*isn't a mailbox user.")
        #{$faRawPermissions = @()}
        #else
        #{
        #throw($myerror)
        WriteLog -Message $myerror.tostring() -ErrorLog -Verbose -EntryType Failed
        $faRawPermissions = @()
        #}
    }

    #drop InheritedPermissions if requested
    if ($dropInheritedPermissions -eq $true)
    {
        $faRawPermissions = @($faRawPermissions | where-object -filterscript {$_.IsInherited -eq $false})
    }
    foreach ($fa in $faRawPermissions)
    {
        $user = $fa.User
        $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $user -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
        switch ($null -eq $trusteeRecipient)
        {
            $true
            {
                $npeoParams = @{
                    TargetMailbox              = $TargetMailbox
                    TrusteeIdentity            = $User
                    TrusteeRecipientObject     = $null
                    PermissionType             = 'FullAccess'
                    AssignmentType             = 'Undetermined'
                    IsInherited                = $fa.IsInherited
                    SourceExchangeOrganization = $ExchangeOrganization
                }
                NewPermissionExportObject @npeoParams
            }#end $true
            $false
            {
                if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                {
                    $npeoParams = @{
                        TargetMailbox              = $TargetMailbox
                        TrusteeIdentity            = $user
                        TrusteeRecipientObject     = $trusteeRecipient
                        PermissionType             = 'FullAccess'
                        AssignmentType             = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) {'*group*' {'GroupMembership'} $null {'Undetermined'} Default {'Direct'}}
                        IsInherited                = $fa.IsInherited
                        SourceExchangeOrganization = $ExchangeOrganization
                    }
                    NewPermissionExportObject @npeoParams
                }
            }#end $false
        }#end switch
    }#end foreach fa
}
#end function GetFullAccessPermission
function GetSendASPermissionsViaExchange
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
        [hashtable]$UnfoundIdentitiesHash
        ,
        $ExchangeOrganization
        ,
        $ExchangeOrganizationIsInExchangeOnline
        ,
        $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    switch ($ExchangeOrganizationIsInExchangeOnline)
    {
        $true
        {
            $command = 'Get-RecipientPermission'
            $splat = @{
                ErrorAction  = 'Stop'
                ResultSize   = 'Unlimited'
                Identity     = $TargetMailbox.guid.guid
                AccessRights = 'SendAs'
            }
            try
            {
                $saRawPermissions = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {&($using:command) @using:splat} -ErrorAction Stop)
            }
            catch
            {
                $saRawPermissions = @()
                $myerror = $_
                WriteLog -Message $myerror.tostring() -ErrorLog -Verbose -EntryType Failed
            }
        }
        $false
        {
            $command = 'Get-ADPermission'
            $splat = @{
                ErrorAction = 'Stop'
                Identity    = $TargetMailbox.distinguishedname
            }
            #Get All AD Permissions
            try
            {
                $saRawPermissions = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {&($using:command) @using:splat} -ErrorAction Stop)
            }
            catch
            {
                $saRawPermissions = @()
                $myerror = $_
                WriteLog -Message $myerror.tostring() -ErrorLog -Verbose -EntryType Failed
            }
            #Filter out just the Send-AS Permissions
            $saRawPermissions = @($saRawPermissions | Where-Object -FilterScript {$_.ExtendedRights -contains 'Send-As'})
        }
    }
    #Drop Inherited Permissions if Requested
    if ($dropInheritedPermissions)
    {
        $saRawPermissions = @($saRawPermissions | Where-Object -FilterScript {$_.IsInherited -eq $false})
    }
    $IdentityProperty = switch ($ExchangeOrganizationIsInExchangeOnline) {$true {'Trustee'} $false {'User'}}
    #Drop Self Permissions
    $saRawPermissions = @($saRawPermissions | Where-Object -FilterScript {$_.$IdentityProperty -ne 'NT AUTHORITY\SELF'})
    #Lookup Trustee Recipients and export permission if found
    foreach ($sa in $saRawPermissions)
    {
        $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $sa.$IdentityProperty -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
        switch ($null -eq $trusteeRecipient)
        {
            $true
            {
                $npeoParams = @{
                    TargetMailbox              = $TargetMailbox
                    TrusteeIdentity            = $sa.$IdentityProperty
                    TrusteeRecipientObject     = $null
                    PermissionType             = 'SendAs'
                    AssignmentType             = 'Undetermined'
                    IsInherited                = $sa.IsInherited
                    SourceExchangeOrganization = $ExchangeOrganization
                }
                NewPermissionExportObject @npeoParams
            }#end $true
            $false
            {
                if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                {
                    $npeoParams = @{
                        TargetMailbox              = $TargetMailbox
                        TrusteeIdentity            = $sa.$IdentityProperty
                        TrusteeRecipientObject     = $trusteeRecipient
                        PermissionType             = 'SendAs'
                        AssignmentType             = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) {$null {'Undetermined'} '*group*' {'GroupMembership'} Default {'Direct'}}
                        IsInherited                = $sa.IsInherited
                        SourceExchangeOrganization = $ExchangeOrganization
                    }
                    NewPermissionExportObject @npeoParams
                }
            }#end $false
        }#end switch
    }#end foreach
}
#end function Get-SendASPermissionViaExchange
function GetSendASPermisssionsViaLocalLDAP
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
        [hashtable]$UnfoundIdentitiesHash
        ,
        $ExchangeOrganization
        ,
        [bool]$ExchangeOrganizationIsInExchangeOnline = $false
        ,
        $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    #Well-known GUID for Send As Permissions, see function Get-SendASRightGUID
    $SendASRight = [GUID]'ab721a54-1e2f-11d0-9819-00aa0040529b'
    $userDN = [ADSI]("LDAP://$($TargetMailbox.DistinguishedName)")
    $saRawPermissions = @(
        $userDN.psbase.ObjectSecurity.Access | Where-Object -FilterScript { (($_.ObjectType -eq $SendASRight) -or ($_.ActiveDirectoryRights -eq 'GenericAll')) -and ($_.AccessControlType -eq 'Allow')} | Where-Object -FilterScript {$_.IdentityReference -notlike "NT AUTHORITY\SELF"}| Select-Object identityreference, IsInherited
        # Where-Object -FilterScript {($_.identityreference.ToString().split('\')[0]) -notin $ExcludedTrusteeDomains}
        # Where-Object -FilterScript {$_.identityreference -notin $ExcludedTrustees}|
    )
    if ($dropInheritedPermissions -eq $true)
    {
        $saRawPermissions = @($saRawPermissions | Where-Object -FilterScript {$_.IsInherited -eq $false})
    }
    $IdentityProperty = switch ($ExchangeOrganizationIsInExchangeOnline) {$true {'Trustee'} $false {'User'}}
    #Drop Self Permissions
    $saRawPermissions = @($saRawPermissions | Where-Object -FilterScript {$_.$IdentityProperty -ne 'NT AUTHORITY\SELF'})
    #Lookup Trustee Recipients and export permission if found
    foreach ($sa in $saRawPermissions)
    {
        $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $sa.$IdentityProperty -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
        switch ($null -eq $trusteeRecipient)
        {
            $true
            {
                $npeoParams = @{
                    TargetMailbox              = $TargetMailbox
                    TrusteeIdentity            = $sa.$IdentityProperty
                    TrusteeRecipientObject     = $null
                    PermissionType             = 'SendAs'
                    AssignmentType             = 'Undetermined'
                    IsInherited                = $sa.IsInherited
                    SourceExchangeOrganization = $ExchangeOrganization
                }
                NewPermissionExportObject @npeoParams
            }#end $true
            $false
            {
                if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                {
                    $npeoParams = @{
                        TargetMailbox              = $TargetMailbox
                        TrusteeIdentity            = $sa.$IdentityProperty
                        TrusteeRecipientObject     = $trusteeRecipient
                        PermissionType             = 'SendAs'
                        AssignmentType             = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) {$null {'Undetermined'} '*group*' {'GroupMembership'} Default {'Direct'}}
                        IsInherited                = $sa.IsInherited
                        SourceExchangeOrganization = $ExchangeOrganization
                    }
                    NewPermissionExportObject @npeoParams
                }
            }#end $false
        }#end switch
    }#end foreach
}
#end function Get-SendASPermissionsViaLocalLDAP
function GetGroupMemberExpandedViaExchange
{
    [CmdletBinding()]
    param
    (
        [string]$Identity
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        $ExchangeOrganizationIsInExchangeOnline
        ,
        $hrPropertySet
        ,
        $ObjectGUIDHash
        ,
        $DomainPrincipalHash
        ,
        $SIDHistoryRecipientHash
        ,
        $UnFoundIdentitiesHash
        ,
        [int]$iterationLimit = 100
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    $splat = @{
        Identity    = $Identity
        ErrorAction = 'Stop'
    }
    Try
    {
        $BaseGroupMemberIdentities = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Group @using:splat | Select-Object -ExpandProperty Members})
    }
    Catch
    {
        $MyError = $_
        $BaseGroupMemberIdentities = @()
        WriteLog -Message $MyError.tostring() -EntryType Failed -ErrorLog -Verbose
    }
    Write-Verbose -Message "Got $($BaseGroupmemberIdentities.Count) Base Group Members for Group $Identity"
    $BaseGroupMembership = @(foreach ($m in $BaseGroupMemberIdentities) {GetTrusteeObject -TrusteeIdentity $m.objectguid.guid -HRPropertySet $hrPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash})
    $iteration = 0
    $AllResolvedMembers = @(
        do
        {
            $iteration++
            $BaseGroupMembership | Where-Object -FilterScript {$_.RecipientTypeDetails -notlike '*group*'}
            $RemainingGroupMembers = @($BaseGroupMembership | Where-Object -FilterScript {$_.RecipientTypeDetails -like '*group*'})
            Write-Verbose -Message "Got $($RemainingGroupMembers.Count) Remaining Nested Group Members for Group $identity.  Iteration: $iteration"
            $BaseGroupMemberIdentities = @($RemainingGroupMembers | ForEach-Object {$splat = @{Identity = $_.guid.guid; ErrorAction = 'Stop'}; invoke-command -Session $ExchangeSession -ScriptBlock {Get-Group @using:splat | Select-Object -ExpandProperty Members}})
            $BaseGroupMembership = @(foreach ($m in $BaseGroupMemberIdentities) {GetTrusteeObject -TrusteeIdentity $m.objectguid.guid -HRPropertySet $hrPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash})
            Write-Verbose -Message "Got $($baseGroupMembership.count) Newly Explanded Group Members for Group $identity"
        }
        until ($BaseGroupMembership.count -eq 0 -or $iteration -ge $iterationLimit)
    )
    $AllResolvedMembers
}
#end function GetGroupMemberExpandedViaExchange
function GetGroupMemberExpandedViaLocalLDAP
{
    [CmdletBinding()]
    param
    (
        [string]$Identity #distinguishedName
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        $hrPropertySet
        ,
        $ObjectGUIDHash
        ,
        $DomainPrincipalHash
        ,
        $SIDHistoryRecipientHash
        ,
        [hashtable]$UnfoundIdentitiesHash
        ,
        $ExchangeOrganizationIsInExchangeOnline
    )
    if (-not (Test-Path -Path variable:script:dsLookFor))
    {
        #enumerate groups: http://stackoverflow.com/questions/8055338/listing-users-in-ad-group-recursively-with-powershell-script-without-cmdlets/8055996#8055996
        $script:dse = [ADSI]"LDAP://Rootdse"
        $script:dn = [ADSI]"LDAP://$($script:dse.DefaultNamingContext)"
        $script:dsLookFor = New-Object System.DirectoryServices.DirectorySearcher($script:dn)
        $script:dsLookFor.SearchScope = "subtree"
    }
    $script:dsLookFor.Filter = "(&(memberof:1.2.840.113556.1.4.1941:=$($Identity))(objectCategory=user))"
    Try
    {
        $OriginalErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        $TrusteeUserObjects = @($dsLookFor.findall())
        $ErrorActionPreference = $OriginalErrorActionPreference
    }
    Catch
    {
        $myError = $_
        $ErrorActionPreference = $OriginalErrorActionPreference
        $TrusteeUserObjects = @()
        WriteLog -Message $myError.tostring() -ErrorLog -EntryType Failed -Verbose
    }

    foreach ($u in $TrusteeUserObjects)
    {
        $TrusteeIdentity = $(GetGuidFromByteArray -GuidByteArray $($u.Properties.objectguid)).guid
        $trusteeRecipient = GetTrusteeObject -TrusteeIdentity $TrusteeIdentity -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
        if ($null -ne $trusteeRecipient)
        {$trusteeRecipient}
    }
}
#end function GetGroupMemberExpandedViaExchange
function ExpandGroupPermission
{
    [CmdletBinding()]
    param
    (
        [psobject[]]$Permission
        ,
        $TargetMailbox
        ,
        [hashtable]$ObjectGUIDHash
        ,
        [hashtable]$SIDHistoryHash
        ,
        $excludedTrusteeGUIDHash
        ,
        [hashtable]$UnfoundIdentitiesHash
        ,
        $HRPropertySet
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        $dropExpandedParentGroupPermissions
        ,
        [switch]$UseExchangeCommandsInsteadOfADOrLDAP
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    $gPermissions = @($Permission | Where-Object -FilterScript {$_.TrusteeRecipientTypeDetails -like '*Group*'})
    $ngPermissions = @($Permission | Where-Object -FilterScript {$_.TrusteeRecipientTypeDetails -notlike '*Group*' -or $null -eq $_.TrusteeRecipientTypeDetails})
    if ($gPermissions.Count -ge 1)
    {
        $expandedPermissions = @(
            foreach ($gp in $gPermissions)
            {
                Write-Verbose -Message "Expanding Group $($gp.TrusteeObjectGUID)"
                #check if we have already expanded this group . . .
                switch ($script:ExpandedGroupsNonGroupMembershipHash.ContainsKey($gp.TrusteeObjectGUID))
                {
                    $true
                    {
                        #if so, get the terminal trustee objects from the expansion hashtable
                        $UserTrustees = $script:ExpandedGroupsNonGroupMembershipHash.$($gp.TrusteeObjectGUID)
                        Write-Verbose -Message "Previously Expanded Group $($gp.TrusteeObjectGUID) Members Count: $($userTrustees.count)"
                    }
                    $false
                    {
                        #if not, get the terminal trustee objects now
                        if ($UseExchangeCommandsInsteadOfADOrLDAP -eq $true)
                        {
                            $UserTrustees = @(GetGroupMemberExpandedViaExchange -Identity $gp.TrusteeObjectGUID -ExchangeSession $exchangeSession -hrPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryRecipientHash $SIDHistoryRecipientHash -UnFoundIdentitiesHash $UnfoundIdentitiesHash -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline)
                        }
                        else
                        {
                            $UserTrustees = @(GetGroupMemberExpandedViaLocalLDAP -Identity $gp.TrusteeDistinguishedName -ExchangeSession $exchangeSession -hrPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryRecipientHash $SIDHistoryRecipientHash -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnfoundIdentitiesHash)
                        }
                        #and add them to the expansion hashtable
                        $script:ExpandedGroupsNonGroupMembershipHash.$($gp.TrusteeObjectGUID) = $UserTrustees
                        Write-Verbose -Message "Newly Expanded Group $($gp.TrusteeObjectGUID) Members Count: $($userTrustees.count)"
                    }
                }
                foreach ($u in $UserTrustees)
                {
                    $trusteeRecipient = $u
                    switch ($null -eq $trusteeRecipient)
                    {
                        $true
                        {
                            #no point in doing anything here
                        }#end $true
                        $false
                        {
                            if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                            {
                                $npeoParams = @{
                                    TargetMailbox              = $TargetMailbox
                                    TrusteeIdentity            = $trusteeRecipient.guid.guid
                                    TrusteeRecipientObject     = $trusteeRecipient
                                    TrusteeGroupObjectGUID     = $gp.TrusteeObjectGUID
                                    PermissionType             = $gp.PermissionType
                                    AssignmentType             = 'GroupMembership'
                                    SourceExchangeOrganization = $ExchangeOrganization
                                    IsInherited                = $gp.IsInherited
                                    ParentPermissionIdentity   = $gp.PermissionIdentity
                                }
                                NewPermissionExportObject @npeoParams
                            }
                        }#end $false
                    }#end switch
                }#end foreach (user)
            }#end foreach (permission)
        )#expandedPermissions
        if ($expandedPermissions.Count -ge 1)
        {
            #remove any self permissions that came in through expansion
            $expandedPermissions = @($expandedPermissions | Where-Object -FilterScript {$_.TargetObjectGUID -ne $_.TrusteeObjectGUID})
        }
        if ($dropExpandedParentGroupPermissions)
        {
            @($ngPermissions; $expandedPermissions)
        }
        else
        {
            @($ngPermissions; $gPermissions; $expandedPermissions)
        }
    }
    else
    {
        $permission
    }
}
#end Function ExpandGroupPermission
###################################################################
#Permission Export Object Function
###################################################################
function NewPermissionExportObject
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        $TargetMailbox
        ,
        [parameter(Mandatory)]
        [string]$TrusteeIdentity
        ,
        [parameter()]
        [AllowNull()]
        $TrusteeRecipientObject
        ,
        [parameter(Mandatory)]
        [ValidateSet('FullAccess', 'SendOnBehalf', 'SendAs', 'None', 'Folder')]
        $PermissionType
        ,
        [parameter()]
        [ValidateSet('Direct', 'GroupMembership', 'None', 'Undetermined')]
        [string]$AssignmentType = 'Direct'
        ,
        $TrusteeGroupObjectGUID
        ,
        $ParentPermissionIdentity
        ,
        [string]$SourceExchangeOrganization = $ExchangeOrganization
        ,
        [boolean]$IsInherited = $False
        ,
        [switch]$none
        ,
        $TargetFolderPath
        ,
        $TargetFolderType
        ,
        $FolderAccessRights

    )#End Param
    $Script:PermissionIdentity++
    $PermissionExportObject =
    [pscustomobject]@{
        PermissionIdentity          = $Script:PermissionIdentity
        ParentPermissionIdentity    = $ParentPermissionIdentity
        SourceExchangeOrganization  = $SourceExchangeOrganization
        TargetObjectGUID            = $TargetMailbox.Guid.Guid
        TargetObjectExchangeGUID    = $TargetMailbox.ExchangeGuid.Guid
        TargetDistinguishedName     = $TargetMailbox.DistinguishedName
        TargetPrimarySMTPAddress    = $TargetMailbox.PrimarySmtpAddress.ToString()
        TargetRecipientType         = $TargetMailbox.RecipientType
        TargetRecipientTypeDetails  = $TargetMailbox.RecipientTypeDetails
        TargetFolderPath            = $TargetFolderPath
        TargetFolderType            = $TargetFolderType
        FolderAccessRights          = $FolderAccessRights
        PermissionType              = $PermissionType
        AssignmentType              = $AssignmentType
        TrusteeGroupObjectGUID      = $TrusteeGroupObjectGUID
        TrusteeIdentity             = $TrusteeIdentity
        IsInherited                 = $IsInherited
        TrusteeObjectGUID           = $null
        TrusteeExchangeGUID         = $null
        TrusteeDistinguishedName    = if ($None) {'none'} else {$null}
        TrusteePrimarySMTPAddress   = if ($None) {'none'} else {$null}
        TrusteeRecipientType        = $null
        TrusteeRecipientTypeDetails = $null
    }
    if ($null -ne $TrusteeRecipientObject)
    {
        $PermissionExportObject.TrusteeObjectGUID = $TrusteeRecipientObject.guid.Guid
        $PermissionExportObject.TrusteeExchangeGUID = $TrusteeRecipientObject.ExchangeGuid.Guid
        $PermissionExportObject.TrusteeDistinguishedName = $TrusteeRecipientObject.DistinguishedName
        $PermissionExportObject.TrusteePrimarySMTPAddress = $TrusteeRecipientObject.PrimarySmtpAddress.ToString()
        $PermissionExportObject.TrusteeRecipientType = $TrusteeRecipientObject.RecipientType
        $PermissionExportObject.TrusteeRecipientTypeDetails = $TrusteeRecipientObject.RecipientTypeDetails
    }
    $PermissionExportObject
}
#end function NewPermissionExportObject
###################################################################
#Resume Export Operation Functions
###################################################################
Function ExportExchangePermissionExportResumeData
{
    [CmdletBinding()]
    param
    (
        $ExchangePermissionsExportParameters
        ,
        $ExcludedRecipientGuidHash
        ,
        $ExcludedTrusteeGuidHash
        ,
        $SIDHistoryRecipientHash
        ,
        $InScopeRecipients
        ,
        $ObjectGUIDHash
        ,
        $outputFolderPath
        ,
        $ExportedExchangePermissionsFile
        ,
        $TimeStamp
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    $ExchangePermissionExportResumeData = @{
        ExchangePermissionsExportParameters = $ExchangePermissionsExportParameters
        ExcludedRecipientGuidHash           = $ExcludedRecipientGuidHash
        ExcludedTrusteeGuidHash             = $ExcludedTrusteeGuidHash
        SIDHistoryRecipientHash             = $SIDHistoryRecipientHash
        InScopeRecipients                   = $InScopeRecipients
        ObjectGUIDHash                      = $ObjectGUIDHash
        ExportedExchangePermissionsFile     = $ExportedExchangePermissionsFile
        TimeStamp                           = $TimeStamp
    }
    $ExportFilePath = Join-Path -Path $outputFolderPath -ChildPath $($TimeStamp + "ExchangePermissionExportResumeData.xml")
    Export-Clixml -Depth 2 -Path $ExportFilePath -InputObject $ExchangePermissionExportResumeData -Encoding UTF8
    $ExportFilePath
}
Function ImportExchangePermissionExportResumeData
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory)]
        $path
    )
    $ImportedExchangePermissionsExportResumeData = Import-Clixml -Path $path -ErrorAction Stop
    $parentpath = Split-Path -Path $path -Parent
    $ResumeIDFilePath = Join-Path -path $parentpath -ChildPath $($ImportedExchangePermissionsExportResumeData.TimeStamp + 'ExchangePermissionExportResumeID.xml')
    $ResumeIDs = Import-Clixml -Path $ResumeIDFilePath -ErrorAction Stop
    $ImportedExchangePermissionsExportResumeData.ResumeID = $ResumeIDs.ResumeID
    $ImportedExchangePermissionsExportResumeData.NextPermissionIdentity = $ResumeIDs.NextPermissionIdentity
    $ImportedExchangePermissionsExportResumeData
}
Function ExportResumeID
{
    [CmdletBinding()]
    param
    (
        $ID
        ,
        $nextPermissionID
        ,
        $outputFolderPath
        ,
        $TimeStamp
    )
    $ExportFilePath = Join-Path -Path $outputFolderPath -ChildPath $($TimeStamp + "ExchangePermissionExportResumeID.xml")
    $Identities = @{
        NextPermissionIdentity = $nextPermissionID
        ResumeID               = $ID
    }
    Export-Clixml -Depth 1 -Path $ExportFilePath -InputObject $Identities -Encoding UTF8
    $ExportFilePath
}
#end function ExportResumeID