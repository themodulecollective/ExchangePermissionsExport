
###################################################################
#Get/Export Permission Functions
###################################################################
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
        [parameter()]
        [AllowNull()]
        $TrusteeRecipientObject
        ,
        [parameter(Mandatory)]
        [ValidateSet('FullAccess','SendOnBehalf','SendAs','None')]
        $PermissionType
        ,
        [parameter()]
        [ValidateSet('Direct','GroupMembership','None','Undetermined')]
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

        )#End Param
        $Script:PermissionIdentity++
        $PermissionExportObject =
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
                TrusteeObjectGUID = $null
                TrusteeExchangeGUID = $null
                TrusteeDistinguishedName = if ($None) {'none'} else {$null}
                TrusteePrimarySMTPAddress = if ($None) {'none'} else {$null}
                TrusteeRecipientType = $null
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
        Write-Output -InputObject $PermissionExportObject
    }
#end function New-PermissionExportObject
function Get-TrusteeObject
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
            $ExchangeSession
            ,
            $ExchangeOrganizationIsInExchangeOnline
        )
        $trusteeObject = $(
            $AddToLookup = $null
            Write-Verbose -Message "Getting Object for TrusteeIdentity $TrusteeIdentity"
            switch ($TrusteeIdentity)
            {
                {$UnfoundIdentitiesHash.ContainsKey($_)}
                {
                    Write-Output -InputObject $null
                    break
                }
                {$ObjectGUIDHash.ContainsKey($_)}
                {
                    $ObjectGUIDHash.$($_)
                    Write-Verbose -Message 'Found Trustee in ObjectGUIDHash'
                    break
                }
                {$DomainPrincipalHash.ContainsKey($_)}
                {
                    $DomainPrincipalHash.$($_)
                    Write-Verbose -Message 'Found Trustee in DomainPrincipalHash'
                    break
                }
                {$SIDHistoryHash.ContainsKey($_)}
                {
                    $SIDHistoryHash.$($_)
                    Write-Verbose -Message 'Found Trustee in SIDHistoryHash'
                    break
                }
                {$null -eq $TrusteeIdentity}
                {
                    Write-Output -InputObject $null
                    break
                }
                Default
                {
                    if ($ExchangeOrganizationIsInExchangeOnline -and $TrusteeIdentity -like '*\*')
                    {
                        $trusteeObject = $null
                    }
                    else
                    {
                        $splat = @{
                            Identity = $TrusteeIdentity
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
            Write-Verbose -Message "Found Trustee $TrusteeIdentity via new lookup"
            $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$ObjectGUIDHash.$($_.ExchangeGuid.Guid) = $_} -ErrorAction SilentlyContinue
            Write-Verbose -Message "ObjectGUIDHash Count is $($ObjectGUIDHash.count)"
            $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$ObjectGUIDHash.$($_.Guid.Guid) = $_} -ErrorAction SilentlyContinue
            if ($TrusteeIdentity -like '*\*' -or $TrusteeIdentity -like '*@*')
            {
                $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$DomainPrincipalHash.$($TrusteeIdentity) = $_} -ErrorAction SilentlyContinue
                Write-Verbose -Message "DomainPrincipalHash Count is $($DomainPrincipalHash.count)"
            }
        }
        #if we found nothing, add the Identity to the UnfoundIdentitiesHash
        if ($null -eq $trusteeObject -and $null -ne $TrusteeIdentity -and -not [string]::IsNullOrEmpty($TrusteeIdentity) -and -not $UnfoundIdentitiesHash.ContainsKey($TrusteeIdentity))
        {
            $UnfoundIdentitiesHash.$TrusteeIdentity = $null
        }
        Write-Output -InputObject $trusteeObject
    }
#end function Get-TrusteeObject
Function Get-SendOnBehalfPermission
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
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
        if ($null -ne $TargetMailbox.GrantSendOnBehalfTo -and $TargetMailbox.GrantSendOnBehalfTo.ToArray().count -ne 0)
        {
            Write-Verbose -message "Target Mailbox has entries in GrantSendOnBehalfTo"
            $splat = @{
                Identity = $TargetMailbox.guid.guid
                ErrorAction = 'Stop'
            }
            Write-Verbose -Message "Getting Trustee Objects from GrantSendOnBehalfTo"
            $sbTrustees = Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Mailbox @using:splat | Select-Object -ExpandProperty GrantSendOnBehalfTo}
            foreach ($sb in $sbTrustees)
            {
                $trusteeRecipient = Get-TrusteeObject -TrusteeIdentity $sb.objectguid.guid -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
                switch ($null -eq $trusteeRecipient)
                {
                    $true
                    {
                        $npeoParams = @{
                            TargetMailbox = $TargetMailbox
                            TrusteeIdentity = $sb.objectguid.guid
                            TrusteeRecipientObject = $null
                            PermissionType = 'SendOnBehalf'
                            AssignmentType = 'Undetermined'
                            SourceExchangeOrganization = $ExchangeOrganization
                            IsInherited = $false
                        }
                        New-PermissionExportObject @npeoParams
                    }#end $true
                    $false
                    {
                        if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                        {
                            $npeoParams = @{
                                TargetMailbox = $TargetMailbox
                                TrusteeIdentity = $sb.objectguid.guid
                                TrusteeRecipientObject = $trusteeRecipient
                                PermissionType = 'SendOnBehalf'
                                AssignmentType = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) {'*group*' {'GroupMembership'} $null {'Undetermined'} Default {'Direct'}}
                                SourceExchangeOrganization = $ExchangeOrganization
                                IsInherited = $false
                            }
                            New-PermissionExportObject @npeoParams
                        }
                    }#end $false
                }#end switch
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
            [hashtable]$UnfoundIdentitiesHash
            ,
            $ExchangeOrganization
            ,
            $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
        )
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
        $splat = @{Identity = $TargetMailbox.guid.guid; ErrorAction = 'Stop'}
        $FilterScriptString = '($_.AccessRights -like "*FullAccess*") -and -not ($_.User -like "NT AUTHORITY\SELF") -and -not ($_.Deny -eq $True) -and -not ($_.User -like "S-1-5*")'
        $filterscript = [scriptblock]::Create($FilterScriptString)
        #add code to check session
        $faRawPermissions = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-MailboxPermission @using:splat} -ErrorAction Stop) | Where-Object -FilterScript $filterscript
        #drop InheritedPermissions if requested
        if ($dropInheritedPermissions -eq $true)
        {
            $faRawPermissions = @($faRawPermissions | where-object -filterscript {$_.IsInherited -eq $false})
        }
        foreach ($fa in $faRawPermissions)
        {
            $user = $fa.User
            $trusteeRecipient = Get-TrusteeObject -TrusteeIdentity $user -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
            switch ($null -eq $trusteeRecipient)
            {
                $true
                {
                    $npeoParams = @{
                        TargetMailbox = $TargetMailbox
                        TrusteeIdentity = $User
                        TrusteeRecipientObject = $null
                        PermissionType = 'FullAccess'
                        AssignmentType = 'Undetermined'
                        IsInherited = $fa.IsInherited
                        SourceExchangeOrganization = $ExchangeOrganization
                    }
                    New-PermissionExportObject @npeoParams
                }#end $true
                $false
                {
                    if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                    {
                        $npeoParams = @{
                            TargetMailbox = $TargetMailbox
                            TrusteeIdentity = $user
                            TrusteeRecipientObject = $trusteeRecipient
                            PermissionType = 'FullAccess'
                            AssignmentType = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) {'*group*' {'GroupMembership'} $null {'Undetermined'} Default {'Direct'}}
                            IsInherited = $fa.IsInherited
                            SourceExchangeOrganization = $ExchangeOrganization
                        }
                        New-PermissionExportObject @npeoParams
                    }
                }#end $false
            }#end switch
        }#end foreach fa
    }
#end function Get-FullAccessPermission
function Get-SendASPermissionsViaExchange
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
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
        switch ($ExchangeOrganizationIsInExchangeOnline)
        {
            $true
            {
                $command = 'Get-RecipientPermission'
                $splat = @{
                    ErrorAction = 'Stop'
                    ResultSize = 'Unlimited'
                    Identity = $TargetMailbox.guid.guid
                    AccessRights = 'SendAs'
                }
                $saRawPermissions = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {&($using:command) @using:splat} -ErrorAction Stop)
            }
            $false
            {
                $command = 'Get-ADPermission'
                $splat = @{
                    ErrorAction = 'Stop'
                    Identity = $TargetMailbox.distinguishedname
                }
                #Get All AD Permissions
                $saRawPermissions = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {&($using:command) @using:splat} -ErrorAction Stop)
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
            $trusteeRecipient = Get-TrusteeObject -TrusteeIdentity $sa.$IdentityProperty -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
            switch ($null -eq $trusteeRecipient)
            {
                $true
                {
                    $npeoParams = @{
                        TargetMailbox = $TargetMailbox
                        TrusteeIdentity = $sa.$IdentityProperty
                        TrusteeRecipientObject = $null
                        PermissionType = 'SendAs'
                        AssignmentType = 'Undetermined'
                        IsInherited = $sa.IsInherited
                        SourceExchangeOrganization = $ExchangeOrganization
                    }
                    New-PermissionExportObject @npeoParams
                }#end $true
                $false
                {
                    if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                    {
                        $npeoParams = @{
                            TargetMailbox = $TargetMailbox
                            TrusteeIdentity = $sa.$IdentityProperty
                            TrusteeRecipientObject = $trusteeRecipient
                            PermissionType = 'SendAs'
                            AssignmentType = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) {'*group*' {'GroupMembership'} $null {'Undetermined'} Default {'Direct'}}
                            IsInherited = $sa.IsInherited
                            SourceExchangeOrganization = $ExchangeOrganization
                        }
                        New-PermissionExportObject @npeoParams
                    }
                }#end $false
            }#end switch
        }#end foreach
    }
#end function Get-SendASPermissionViaExchange
function Get-SendASPermisssionsViaLocalLDAP
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
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
        #Well-known GUID for Send As Permissions, see function Get-SendASRightGUID
        $SendASRight = [GUID]'ab721a54-1e2f-11d0-9819-00aa0040529b'
        $userDN = [ADSI]("LDAP://$($TargetMailbox.DistinguishedName)")
        $saRawPermissions = @(
            $userDN.psbase.ObjectSecurity.Access | Where-Object -FilterScript { (($_.ObjectType -eq $SendASRight) -or ($_.ActiveDirectoryRights -eq 'GenericAll')) -and ($_.AccessControlType -eq 'Allow')} | Where-Object -FilterScript {$_.IdentityReference -notlike "NT AUTHORITY\SELF"}| Select-Object identityreference,IsInherited 
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
            $trusteeRecipient = Get-TrusteeObject -TrusteeIdentity $sa.$IdentityProperty -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
            switch ($null -eq $trusteeRecipient)
            {
                $true
                {
                    $npeoParams = @{
                        TargetMailbox = $TargetMailbox
                        TrusteeIdentity = $sa.$IdentityProperty
                        TrusteeRecipientObject = $null
                        PermissionType = 'SendAs'
                        AssignmentType = 'Undetermined'
                        IsInherited = $sa.IsInherited
                        SourceExchangeOrganization = $ExchangeOrganization
                    }
                    New-PermissionExportObject @npeoParams
                }#end $true
                $false
                {
                    if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                    {
                        $npeoParams = @{
                            TargetMailbox = $TargetMailbox
                            TrusteeIdentity = $sa.$IdentityProperty
                            TrusteeRecipientObject = $trusteeRecipient
                            PermissionType = 'SendAs'
                            AssignmentType = switch -Wildcard ($trusteeRecipient.RecipientTypeDetails) {'*group*' {'GroupMembership'} $null {'Undetermined'} Default {'Direct'}}
                            IsInherited = $sa.IsInherited
                            SourceExchangeOrganization = $ExchangeOrganization
                        }
                        New-PermissionExportObject @npeoParams
                    }
                }#end $false
            }#end switch
        }#end foreach
    }
#end function Get-SendASPermissionsViaLocalLDAP
function Get-GroupMemberExpandedViaExchange
    {
        [CmdletBinding()]
        param
        (
            [string]$Identity
            ,
            $ExchangeSession
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
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
        $splat = @{
            Identity = $Identity
            ErrorAction = 'Stop'
        }
        $BaseGroupMemberIdentities = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Group @using:splat | Select-Object -ExpandProperty Members})
        Write-Verbose -Message "Got $($BaseGroupmemberIdentities.Count) Base Group Members for Group $Identity"
        $BaseGroupMembership = @(foreach ($m in $BaseGroupMemberIdentities) {Get-TrusteeObject -TrusteeIdentity $m.objectguid.guid -HRPropertySet $hrPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash})
        $iteration = 0
        $AllResolvedMembers = @(
            do
            {
                $iteration++
                $BaseGroupMembership | Where-Object -FilterScript {$_.RecipientTypeDetails -notlike '*group*'}
                $RemainingGroupMembers =  @($BaseGroupMembership | Where-Object -FilterScript {$_.RecipientTypeDetails -like '*group*'})
                Write-Verbose -Message "Got $($RemainingGroupMembers.Count) Remaining Nested Group Members for Group $identity.  Iteration: $iteration"
                $BaseGroupMemberIdentities = @($RemainingGroupMembers | ForEach-Object {$splat = @{Identity = $_.guid.guid;ErrorAction = 'Stop'};invoke-command -Session $ExchangeSession -ScriptBlock {Get-Group @using:splat | Select-Object -ExpandProperty Members}})
                $BaseGroupMembership = @(foreach ($m in $BaseGroupMemberIdentities) {Get-TrusteeObject -TrusteeIdentity $m.objectguid.guid -HRPropertySet $hrPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash})
                Write-Verbose -Message "Got $($baseGroupMembership.count) Newly Explanded Group Members for Group $identity"
            }
            until ($BaseGroupMembership.count -eq 0 -or $iteration -ge $iterationLimit)
        )
        Write-Output -InputObject $AllResolvedMembers
    }
#end function Get-GroupMemberExpandedViaExchange
function Get-GroupMemberExpandedViaLocalLDAP
    {
        [CmdletBinding()]
        param
        (
            [string]$Identity #distinguishedName
            ,
            $ExchangeSession
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
        $TrusteeUserObjects = @($dsLookFor.findall())
        foreach ($u in $TrusteeUserObjects)
        {
            $TrusteeIdentity = $(Get-GuidFromByteArray -GuidByteArray $($u.Properties.objectguid)).guid
            $trusteeRecipient = Get-TrusteeObject -TrusteeIdentity $TrusteeIdentity -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnFoundIdentitiesHash
            if ($null -ne $trusteeRecipient)
            {Write-Output -InputObject $trusteeRecipient}
        }
    }
#end function Get-GroupMemberExpandedViaExchange
function Expand-GroupPermission
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
            $exchangeSession
            ,
            $dropExpandedParentGroupPermissions
            ,
            [switch]$UseExchangeCommandsInsteadOfADOrLDAP
        )
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
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
                                $UserTrustees = @(Get-GroupMemberExpandedViaExchange -Identity $gp.TrusteeObjectGUID -ExchangeSession $exchangeSession -hrPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryRecipientHash $SIDHistoryRecipientHash -UnFoundIdentitiesHash $UnfoundIdentitiesHash -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline)
                            }
                            else
                            {
                                $UserTrustees = @(Get-GroupMemberExpandedViaLocalLDAP -Identity $gp.TrusteeDistinguishedName -ExchangeSession $exchangeSession -hrPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryRecipientHash $SIDHistoryRecipientHash -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -UnfoundIdentitiesHash $UnfoundIdentitiesHash)
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
                                        TargetMailbox = $TargetMailbox
                                        TrusteeIdentity = $trusteeRecipient.guid.guid
                                        TrusteeRecipientObject = $trusteeRecipient
                                        TrusteeGroupObjectGUID = $gp.TrusteeObjectGUID
                                        PermissionType = $gp.PermissionType
                                        AssignmentType = 'GroupMembership'
                                        SourceExchangeOrganization = $ExchangeOrganization
                                        IsInherited = $gp.IsInherited
                                        ParentPermissionIdentity = $gp.PermissionIdentity
                                    }
                                    New-PermissionExportObject @npeoParams
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
                Write-Output -InputObject @($ngPermissions;$expandedPermissions)
            }
            else
            {
                Write-Output -InputObject @($ngPermissions;$gPermissions;$expandedPermissions)
            }
        }
        else
        {
            Write-output -inputobject $permission
        }
    }
#end Function Expand-GroupPermission
###################################################################
#Main/Control Function
###################################################################
Function Get-ExchangePermission
    {
        #ToDo
        #Add an attribute to the permission object which indicates if the target/permholder were in the mailboxes scope
        #add excluded prefixes with split on \
        #add scoping by OU? integrate EXO recipients as a filter of some sort?
        #implement explicit garbage collection. 
        #Add Forwarding detection/export
        #Add Calendar Permissions -- in progress
        #Add Resume capability for broken session scenario
        #use get-group and/or get-user when get-recipient fails to get an object -- done
        #Fix Fullaccess to leverage SID History and Inheritance options -- done
        #Make inheritance work for expanded group perms, too. right now will say false for all which isn't correct. -- done
        #fix ugly out-file hack -- done
        #fix denies --done
        #globalsendas -- done
        ##recip instead of mailbox -- done just for globalsendas
        #sidhistory support -- done
        #AD connection -- done
        #inheritance switch and output -- done
        #hard-code sendas guid -- done
        #add genericall -- done
        #add group detection for SendOnBehalf -- done
        [cmdletbinding(DefaultParameterSetName = 'AllMailboxes')]
        param
        (
            [Parameter(ParameterSetName = 'Resume',Mandatory)]
            [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
            [parameter(ParameterSetName = 'Scoped',Mandatory)]
            [parameter(ParameterSetName = 'GlobalSendAs',Mandatory)]
            [ValidateScript({$_.state -eq 'Opened' -and $_.Availability -eq 'Available'})]
            [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
            ,
            [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
            [parameter(ParameterSetName = 'Scoped',Mandatory)]
            [parameter(ParameterSetName = 'GlobalSendAs',Mandatory)]
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
            [parameter()]#These will be resolved to target recipient objects
            [string[]]$ExcludedIdentities
            ,
            [parameter()]#These will be resolved to trustee objects
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
            [bool]$dropExpandedParentGroupPermissions = $false
            ,
            [bool]$dropInheritedPermissions = $false
            ,
            [bool]$IncludeSIDHistory = $false
            ,
            [parameter()]
            [ValidateScript({$_.gettype().name -eq 'ADDriveInfo'})]#doing this as a validatescript instead of a type declaration so that this will run on a system that lacks the ActiveDirectory module if the user doesn't need this parameter.
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
            [Parameter(ParameterSetName = 'Resume',Mandatory)]
            [ValidateScript({Test-Path -Path $_})]
            [string]$ResumeFile

        )#End Param
        Begin
        {
            #$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $BeginTimeStamp = Get-Date -Format yyyyMMdd-HHmmss
            $ExchangeOrganization = Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-OrganizationConfig | Select-Object -ExpandProperty Identity | Select-Object -ExpandProperty Name}
            $ExchangeOrganizationIsInExchangeOnline = $ExchangeOrganization -like '*.onmicrosoft.com'
            switch ($PSCmdlet.ParameterSetName -eq 'Resume')
            {
                $true
                {
                    $ImportedExchangePermissionsExportResumeData = Import-ExchangePermissionExportResumeData -Path $ResumeFile
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
                        if ($v.name -ne 'ExchangeSession')
                        {
                            Set-Variable -Name $v.name -Value $v.value -Force
                        }
                    }
                    $script:LogPath = Join-Path -path $OutputFolderPath -ChildPath $($BeginTimeStamp + 'ExchangePermissionsExportOperations.log')
                    $script:ErrorLogPath = Join-Path -path $OutputFolderPath -ChildPath $($BeginTimeStamp + 'ExchangePermissionsExportOperations-ERRORS.log')
                    Write-Log -Message "Calling Invocation = $($MyInvocation.Line)" -EntryType Notification
                    Write-Log -Message "Provided Exchange Session is Running in Exchange Organzation $ExchangeOrganization" -EntryType Notification
                    $ResumeIndex = getarrayIndexForIdentity -array $InScopeRecipients -property 'guid' -Value $ResumeIdentity -ErrorAction Stop
                    Write-Log -Message "Resume index set to $ResumeIndex based on ResumeIdentity $resumeIdentity" -EntryType Notification
                }
                $false
                {
                    $script:LogPath = Join-Path -path $OutputFolderPath -ChildPath $($BeginTimeStamp + 'ExchangePermissionsExportOperations.log')
                    $script:ErrorLogPath = Join-Path -path $OutputFolderPath -ChildPath $($BeginTimeStamp + 'ExchangePermissionsExportOperations-ERRORS.log')
                    Write-Log -Message "Calling Invocation = $($MyInvocation.Line)" -EntryType Notification
                    Write-Log -Message "Provided Exchange Session is Running in Exchange Organzation $ExchangeOrganization" -EntryType Notification
                    $ExportedExchangePermissionsFile = Join-Path -Path $OutputFolderPath -ChildPath $($BeginTimeStamp + 'ExportedExchangePermissions.csv')
                    $ResumeIndex = 0
                    [uint32]$Script:PermissionIdentity = 0
                    if ($IncludeSIDHistory -eq $true)
                    {
                        if ($null -eq $ActiveDirectoryDrive)
                        {throw("If IncludeSIDHistory is required an Active Directory PS Drive connection to the appropriate domain or forest must be provided")}
                    }
                    #create a property set for storing of recipient data during processing.  We don't need all attributes in memory/storage.
                    $HRPropertySet = @('*name*','*addr*','RecipientType*','*Id','Identity','GrantSendOnBehalfTo')
                    
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
                                    Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @Using:splat | Select-Object -Property $using:HRPropertySet} -ErrorAction 'Stop'
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
                                    Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @Using:splat | Select-Object -Property $using:HRPropertySet} -ErrorAction 'Stop'
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
                                        Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @Using:splat | Select-Object -Property $Using:HRPropertySet} -ErrorAction Stop
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
                                $InScopeRecipients = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Mailbox @Using:splat | Select-Object -Property $Using:HRPropertySet} -ErrorAction Stop)
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
                                $InScopeRecipients = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Recipient @Using:splat | Select-Object -Property $Using:HRPropertySet} -ErrorAction Stop)
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
                    Write-Log -Message "Got $InScopeRecipientCount In Scope Recipient Objects" -EntryType Notification
                    #EndRegion GetInScopeRecipients
        
                    #Region GetSIDHistoryData
                    if ($IncludeSIDHistory -eq $true)
                    {
                        $SIDHistoryRecipientHash = Get-SIDHistoryRecipientHash -ActiveDirectoryDrive $ActiveDirectoryDrive -ExchangeSession $ExchangeSession -ErrorAction Stop
                    }
                    else 
                    {
                        $SIDHistoryRecipientHash = @{}
                    }
                    #EndRegion GetSIDHistoryData
        
                    #Region BuildLookupHashTables
                    Write-Log -Message "Building Recipient Lookup HashTables" -EntryType Notification
                    $ObjectGUIDHash = $InScopeRecipients | Select-object -property $HRPropertySet | Group-Object -AsHashTable -Property Guid -AsString
                    #Also Add the Exchange GUIDs to this lookup if we are dealing with Exchange Online
                    if ($ExchangeOrganizationIsInExchangeOnline)
                    {
                        $InScopeRecipients | ForEach-Object -Process {$ObjectGUIDHash.$($_.ExchangeGuid.Guid) = $_}
                    }
                }
            }
            # Setup for Possible Resume if requested by the user
            if ($EnableResume -eq $true)
            {
                $ExportExchangePermissionsExportResumeData = @{
                    ExcludedRecipientGuidHash = $ExcludedRecipientGuidHash
                    ExcludedTrusteeGuidHash = $ExcludedTrusteeGuidHash
                    SIDHistoryRecipientHash = $SIDHistoryRecipientHash
                    InScopeRecipients = $InScopeRecipients
                    ObjectGUIDHash = $ObjectGUIDHash
                    outputFolderPath = $outputFolderPath
                    ExportedExchangePermissionsFile = $ExportedExchangePermissionsFile
                    TimeStamp = $BeginTimeStamp
                    ErrorAction = 'Stop'
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
                $message = "Enable Resume and Export Resume Data"
                Write-Log -Message $message -EntryType Attempting
                $ResumeFile = Export-ExchangePermissionExportResumeData @ExportExchangePermissionsExportResumeData
                $message = $message + " to file $ResumeFile"
                Write-Log -Message $message -EntryType Succeeded
            }

            #these have to be populated as we go
            $DomainPrincipalHash = @{}
            $UnfoundIdentitiesHash = @{}
            if ($expandGroups -eq $true)
            {
                $script:ExpandedGroupsNonGroupMembershipHash = @{}
            }

            #EndRegion BuildLookupHashtables
        }
        End
        {
            #Set Up to Loop through Mailboxes/Recipients
            $ISRCounter = $ResumeIndex
            $ExportedPermissions = @(
            :nextISR Foreach ($ISR in $InScopeRecipients[$ResumeIndex..$($InScopeRecipientCount - 1)])
            {
                Try
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
                    $PermissionExportObjects = @(
                        If (($IncludeSendOnBehalf) -and (!($GlobalSendAs)))
                        {
                            Write-Verbose -Message "Getting SendOnBehalf Permissions for Target $ID"
                            Get-SendOnBehalfPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $ExchangeSession -ExcludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization -HRPropertySet $HRPropertySet -DomainPrincipalHash $DomainPrincipalHash -UnfoundIdentitiesHash $UnfoundIdentitiesHash
                        }
                        If (($IncludeFullAccess) -and (!($GlobalSendAs)))
                        {
                            Write-Verbose -Message "Getting FullAccess Permissions for Target $ID"
                            Get-FullAccessPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $ExchangeSession -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization -DomainPrincipalHash $DomainPrincipalHash -HRPropertySet $HRPropertySet -dropInheritedPermissions $dropInheritedPermissions -UnfoundIdentitiesHash $UnfoundIdentitiesHash
                        }
                        #Get Send As Users
                        If (($IncludeSendAs) -or ($GlobalSendAs))
                        {
                            Write-Verbose -Message "Getting SendAS Permissions for Target $ID"
                            if ($ExchangeOrganizationIsInExchangeOnline -or $UseExchangeCommandsInsteadOfADOrLDAP)
                            {
                                Write-Verbose -Message "Getting SendAS Permissions for Target $ID Via Exchange Commands"
                                Get-SendASPermissionsViaExchange -TargetMailbox $ISR -ExchangeSession $ExchangeSession -ObjectGUIDHash $ObjectGUIDHash -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -dropInheritedPermissions $dropInheritedPermissions -DomainPrincipalHash $DomainPrincipalHash -ExchangeOrganization $ExchangeOrganization -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -HRPropertySet $HRPropertySet -UnfoundIdentitiesHash $UnfoundIdentitiesHash
                            }
                            else
                            {
                                Write-Verbose -Message "Getting SendAS Permissions for Target $ID Via LDAP Commands"
                                Get-SendASPermisssionsViaLocalLDAP -TargetMailbox $ISR -ExchangeSession $ExchangeSession -ObjectGUIDHash $ObjectGUIDHash -excludedTrusteeGUIDHash $excludedRecipientGUIDHash -dropInheritedPermissions $dropInheritedPermissions -DomainPrincipalHash $DomainPrincipalHash -ExchangeOrganization $ExchangeOrganization -ExchangeOrganizationIsInExchangeOnlin $ExchangeOrganizationIsInExchangeOnline -HRPropertySet $HRPropertySet -UnfoundIdentitiesHash $UnfoundIdentitiesHash
                            }
                        }
                    )
                    if ($expandGroups -eq $true)
                    {
                        Write-Verbose -Message "Expanding Group Based Permissions for Target $ID"
                        $splat = @{
                            Permission = $PermissionExportObjects
                            ObjectGUIDHash = $ObjectGUIDHash
                            SIDHistoryHash = $SIDHistoryRecipientHash
                            excludedTrusteeGUIDHash = $excludedTrusteeGUIDHash
                            UnfoundIdentitiesHash = $UnfoundIdentitiesHash
                            HRPropertySet = $HRPropertySet
                            exchangeSession = $ExchangeSession
                            TargetMailbox = $ISR
                        }
                        if ($dropExpandedParentGroupPermissions -eq $true)
                        {$splat.dropExpandedParentGroupPermissions = $true}
                        if ($ExchangeOrganizationIsInExchangeOnline -or $UseExchangeCommandsInsteadOfADOrLDAP)
                        {$splat.UseExchangeCommandsInsteadOfADOrLDAP = $true}
                        $PermissionExportObjects = @(Expand-GroupPermission @splat)
                    }
                    if (Test-ExchangeSession -Session $ExchangeSession)
                    {
                        if ($PermissionExportObjects.Count -eq 0 -and -not $ExcludeNonePermissionOutput -eq $true)
                        {
                            $GPEOParams = @{
                                TargetMailbox = $ISR
                                TrusteeIdentity = 'Not Applicable'
                                TrusteeRecipientObject = $null
                                PermissionType = 'None'
                                AssignmentType = 'None'
                                SourceExchangeOrganization = $ExchangeOrganization
                                None = $true
                            }
                            $NonPerm = New-PermissionExportObject @GPEOParams
                            Write-Output $NonPerm
                        }
                        elseif ($PermissionExportObjects.Count -gt 0)
                        {
                            Write-Output $PermissionExportObjects
                        }
                        Write-Log -Message $message -EntryType Succeeded
                    }
                    else
                    {
                        Write-Log -Message $message -EntryType Failed -ErrorLog -Verbose
                        $exitmessage = "Exchange Session Failed/Disconnected during permission processing for ID $ID."
                        Write-Log -Message $exitmessage -EntryType Notification -ErrorLog -Verbose
                        if ($PSBoundParameters.ContainsKey('EnableResume'))
                        {
                            Write-Log -Message "Resume File $ResumeFile is available to resume this operation after you have re-connected the Exchange Session" -Verbose
                            Write-Log -Message "Resume Recipient ID is $ID" -Verbose
                            $ResumeIDFile = Export-ResumeID -ID $ID -outputFolderPath $OutputFolderPath -TimeStamp $BeginTimeStamp -NextPermissionID $Script:PermissionIdentity++
                            Write-Log -Message "Resume ID exported to file $resumeIDFile" -Verbose
                            $message = "Run `'Get-ExchangePermission -ResumeFile $ResumeFile`' and also specify any common parameters desired (such as -verbose) since common parameters are not included in the Resume Data File."
                            Write-Log -Message $message -EntryType Notification
                        }
                        Break nextISR
                    }
                }
                Catch
                {
                    $myerror = $_
                    Write-Log -Message $myError.tostring() -EntryType Failed -ErrorLog -Verbose
                    if ($PSBoundParameters.ContainsKey('EnableResume'))
                    {
                        Write-Log -Message "Resume File $ResumeFile is available to resume this operation after you have re-connected the Exchange Session" -Verbose
                        Write-Log -Message "Resume Recipient ID is $ID" -Verbose
                        $ResumeIDFile = Export-ResumeID -ID $ID -outputFolderPath $OutputFolderPath -TimeStamp $BeginTimeStamp -NextPermissionID $Script:PermissionIdentity
                        Write-Log -Message "Resume ID exported to file $resumeIDFile" -Verbose
                        $message = "Run `'Get-ExchangePermission -ResumeFile $ResumeFile`' and also specify any common parameters desired (such as -verbose) since common parameters are not included in the Resume Data File."
                        Write-Log -Message $message -EntryType Notification
                    }
                    Break nextISR
                }
            }#Foreach recipient in set
            )# end ExportedPermissions
            Try
            {
                $message = "Export $($ExportedPermissions.Count) Exported Permissions to File $ExportedExchangePermissionsFile."
                Write-Log -Message $message -EntryType Attempting
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
                Write-Log -Message $message -EntryType Succeeded
                if ($KeepExportedPermissionsInGlobalVariable -eq $true)
                {
                    Write-Log -Message "Saving Exported Permissions to Global Variable $($BeginTimeStamp + "ExportedExchangePermissions") for recovery/manual export."
                    Set-Variable -Name $($BeginTimeStamp + "ExportedExchangePermissions") -Value $ExportedPermissions -Scope Global
                }
            }
            Catch
            {
                $myerror = $_
                Write-Log -Message $message -EntryType Failed -ErrorLog -Verbose
                Write-Log -Message $myError.tostring() -ErrorLog
                Write-Log -Message "Saving Exported Permissions to Global Variable $($BeginTimeStamp + "ExportedExchangePermissions") for recovery/manual export."
                Set-Variable -Name $($BeginTimeStamp + "ExportedExchangePermissions") -Value $ExportedPermissions -Scope Global
            }
        }#end End
    }
#End Function Export-ExchangePermission
###################################################################
#Import Additional Files
###################################################################
. $(Join-Path $PSScriptRoot 'SupportAndThirdPartyFunctions.ps1')