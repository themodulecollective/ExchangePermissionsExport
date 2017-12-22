#should we look for forwarded mailboxes?
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
        [int]$iterationLimit = 100
    )
    $splat = @{
        Identity = $Identity
        ErrorAction = 'Stop'
    }
    $BaseGroupMemberIdentities = @(Invoke-Command -Session $ExchangeSession -ScriptBlock {Get-Group @using:splat | Select-Object -ExpandProperty Members})
    $BaseGroupMembership = @(foreach ($m in $BaseGroupMemberIdentities) {Get-TrusteeObject -TrusteeIdentity $m.objectguid.guid -HRPropertySet $hrPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline})
    $iteration = 0
    $AllResolvedMembers = @(
        do
        {
            $iteration++
            $BaseGroupMembership | Where-Object -FilterScript {$_.RecipientTypeDetails -notlike '*group*'}
            $RemainingGroupMembers =  @($BaseGroupMembership | Where-Object -FilterScript {$_.RecipientTypeDetails -like '*group*'})
            $BaseGroupMemberIdentities = @($RemainingGroupMembers | ForEach-Object {$splat = @{Identity = $_.objectguid.guid;ErrorAction = 'Stop'};invoke-command -Session $ExchangeSession -ScriptBlock {Get-Group @using:splat | Select-Object -ExpandProperty Members}})
            $BaseGroupMembership = @(foreach ($m in $BaseGroupMemberIdentities) {Get-TrusteeObject -TrusteeIdentity $m.objectguid.guid -HRPropertySet $hrPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline})
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
        $trusteeRecipient = Get-TrusteeObject -TrusteeIdentity $TrusteeIdentity -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline
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
            [hashtable]$ObjectGUIDHash
            ,
            [hashtable]$SIDHistoryHash
            ,
            $excludedTrusteeGUIDHash
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
                            Write-Verbose -Message "Previously Expanded Group $($gp.TrusteeObjectGUID) Members Count: $($userTrustees.count)" -EntryType Notification
                        }
                        $false
                        {
                            #if not, get the terminal trustee objects now
                            if ($UseExchangeCommandsInsteadOfADOrLDAP -eq $true)
                            {
                                $UserTrustees = @(Get-GroupMemberExpandedViaExchange -Identity $gp.TrusteeObjectGUID -ExchangeSession $exchangeSession -hrPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryRecipientHash $SIDHistoryRecipientHash)
                            }
                            else
                            {
                                $UserTrustees = @(Get-GroupMemberExpandedViaLocalLDAP -Identity $gp.TrusteeDistinguishedName -ExchangeSession $exchangeSession -hrPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryRecipientHash $SIDHistoryRecipientHash)
                            }
                            #and add them to the expansion hashtable
                            $script:ExpandedGroupsNonGroupMembershipHash.$($gp.TrusteeObjectGUID) = $UserTrustees
                            Write-Verbose -Message "Newly Expanded Group $($gp.TrusteeObjectGUID) Members Count: $($userTrustees.count)" -EntryType Notification
                        }
                    }
                    foreach ($u in $UserTrustees)
                    {
                        if ($UseExchangeCommandsInsteadOfADOrLDAP -eq $true)
                        {
                            $trusteeRecipient = $u
                        }
                        else
                        {
                        }
                        switch ($null -eq $trusteeRecipient)
                        {
                            $true
                            {
                                $npeoParams = @{
                                    TargetMailbox = $TargetMailbox
                                    TrusteeIdentity = $TrusteeIdentity
                                    TrusteeRecipientObject = $null
                                    PermissionType = $gp.PermissionType
                                    AssignmentType = 'GroupMembership'
                                    SourceExchangeOrganization = $ExchangeOrganization
                                    IsInherited = $gp.IsInherited
                                }
                                New-PermissionExportObject @npeoParams
                            }#end $true
                            $false
                            {
                                if (-not $excludedTrusteeGUIDHash.ContainsKey($trusteeRecipient.guid.guid))
                                {
                                    $npeoParams = @{
                                        TargetMailbox = $TargetMailbox
                                        TrusteeIdentity = $TrusteeIdentity
                                        TrusteeRecipientObject = $trusteeRecipient
                                        PermissionType = $gp.PermissionType
                                        AssignmentType = 'GroupMembership'
                                        SourceExchangeOrganization = $ExchangeOrganization
                                        IsInherited = $gp.IsInherited
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
function Get-CalendarPermission
    {
        $CalendarPermission = Get-MailboxFolderPermission -Identity ($Mailbox.alias + ':\Calendar') -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | ?{$_.User -notlike "Anonymous" -and $_.User -notlike "Default"} | Select User, AccessRights
        if (!$CalendarPermission){
            $Calendar = (($Mailbox.PrimarySmtpAddress.ToString())+ ":\" + (Get-MailboxFolderStatistics -Identity $Mailbox.DistinguishedName -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | where-object {$_.FolderType -eq "Calendar"} | Select-Object -First 1).Name)
            $CalendarPermission = Get-MailboxFolderPermission -Identity $Calendar -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | ?{$_.User -notlike "Anonymous" -and $_.User -notlike "Default"} | Select User, AccessRights
        }
    }
#end Get-CalendarPermission
###################################################################
#Get Permission Functions
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
            $ExchangeSession
            ,
            $ExchangeOrganizationIsInExchangeOnline
        )
        $trusteeObject = $(
            $AddToLookup = $null
            Write-Verbose -Verbose -Message "Getting Object for TrusteeIdentity $TrusteeIdentity"
            switch ($TrusteeIdentity)
            {
                {$ObjectGUIDHash.ContainsKey($_)}
                {
                    $ObjectGUIDHash.$($_)
                    Write-Verbose -Verbose -Message 'Found Trustee in ObjectGUIDHash'
                    break
                }
                {$DomainPrincipalHash.ContainsKey($_)}
                {
                    $DomainPrincipalHash.$($_)
                    Write-Verbose -Verbose -Message 'Found Trustee in DomainPrincipalHash'
                    break
                }
                {$SIDHistoryHash.ContainsKey($_)}
                {
                    $SIDHistoryHash.$($_)
                    Write-Verbose -Verbose -Message 'Found Trustee in SIDHistoryHash'
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
            Write-Verbose -Verbose -Message "Found Trustee $TrusteeIdentity via new lookup"
            $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$ObjectGUIDHash.$($_.ExchangeGuid.Guid) = $_} -ErrorAction SilentlyContinue
            Write-Verbose -Verbose -Message "ObjectGUIDHash Count is $($ObjectGUIDHash.count)"
            $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$ObjectGUIDHash.$($_.Guid.Guid) = $_} -ErrorAction SilentlyContinue
            if ($TrusteeIdentity -like '*\*' -or $TrusteeIdentity -like '*@*')
            {
                $AddToLookup | Select-Object -Property $HRPropertySet | ForEach-Object -Process {$DomainPrincipalHash.$($TrusteeIdentity) = $_} -ErrorAction SilentlyContinue
                Write-Verbose -Verbose -Message "DomainPrincipalHash Count is $($DomainPrincipalHash.count)"
            }
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
            $ExchangeOrganization
            ,
            $HRPropertySet #Property set for recipient object inclusion in object lookup hashtables
        )
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
        if ($TargetMailbox.GrantSendOnBehalfTo.ToArray().count -ne 0)
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
                $trusteeRecipient = Get-TrusteeObject -TrusteeIdentity $sb.objectguid.guid -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline
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
            $trusteeRecipient = Get-TrusteeObject -TrusteeIdentity $user -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline
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
            $trusteeRecipient = Get-TrusteeObject -TrusteeIdentity $sa.$IdentityProperty -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline
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
            $trusteeRecipient = Get-TrusteeObject -TrusteeIdentity $sa.$IdentityProperty -HRPropertySet $HRPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline
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
###################################################################
#Main/Control Function
###################################################################
Function Export-ExchangePermission
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
        )#End Param
        Begin
        {
            #$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
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
            else 
            {
                $SIDHistoryRecipientHash = @{}
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
                $script:ExpandedGroupsNonGroupMembershipHash = @{}
            }
            #this one has to be populated as we go
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
                $PermissionExportObjects = @(
                    If (($IncludeSendOnBehalf) -and (!($GlobalSendAs)))
                    {
                        Write-Verbose -Message "Getting SendOnBehalf Permissions for Target $ID"
                        Get-SendOnBehalfPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $ExchangeSession -ExcludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization -HRPropertySet $HRPropertySet
                    }
                    If (($IncludeFullAccess) -and (!($GlobalSendAs)))
                    {
                        Write-Verbose -Message "Getting FullAccess Permissions for Target $ID"
                        Get-FullAccessPermission -TargetMailbox $ISR -ObjectGUIDHash $ObjectGUIDHash -ExchangeSession $ExchangeSession -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -ExchangeOrganization $ExchangeOrganization -DomainPrincipalHash $DomainPrincipalHash -HRPropertySet $HRPropertySet -dropInheritedPermissions $dropInheritedPermissions
                    }
                    #Get Send As Users
                    If (($IncludeSendAs) -or ($GlobalSendAs))
                    {
                        Write-Verbose -Message "Getting SendAS Permissions for Target $ID"
                        if ($ExchangeOrganizationIsInExchangeOnline -or $UseExchangeCommandsInsteadOfADOrLDAP)
                        {
                            Write-Verbose -Message "Getting SendAS Permissions for Target $ID Via Exchange Commands"
                            Get-SendASPermissionsViaExchange -TargetMailbox $ISR -ExchangeSession $ExchangeSession -ObjectGUIDHash $ObjectGUIDHash -excludedTrusteeGUIDHash $excludedTrusteeGUIDHash -dropInheritedPermissions $dropInheritedPermissions -DomainPrincipalHash $DomainPrincipalHash -ExchangeOrganization $ExchangeOrganization -ExchangeOrganizationIsInExchangeOnline $ExchangeOrganizationIsInExchangeOnline -HRPropertySet $HRPropertySet
                        }
                        else
                        {
                            Write-Verbose -Message "Getting SendAS Permissions for Target $ID Via LDAP Commands"
                            Get-SendASPermisssionsViaLocalLDAP -TargetMailbox $ISR -ExchangeSession $ExchangeSession -ObjectGUIDHash $ObjectGUIDHash -excludedTrusteeGUIDHash $excludedRecipientGUIDHash -dropInheritedPermissions $dropInheritedPermissions -DomainPrincipalHash $DomainPrincipalHash -ExchangeOrganization $ExchangeOrganization -ExchangeOrganizationIsInExchangeOnlin $ExchangeOrganizationIsInExchangeOnline -HRPropertySet $HRPropertySet
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
                        HRPropertySet = $HRPropertySet
                        exchangeSession = $ExchangeSession
                    }
                    if ($dropExpandedParentGroupPermissions -eq $true)
                    {$splat.dropExpandedParentGroupPermissions = $true}
                    if ($ExchangeOrganizationIsInExchangeOnline -or $UseExchangeCommandsInsteadOfADOrLDAP)
                    {$splat.UseExchangeCommandsInsteadOfADOrLDAP = $true}
                    $PermissionExportObjects = @(Expand-GroupPermission @splat)
                }
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
            }#Foreach recipient in set
        }#end End
    }
#End Function Export-ExchangePermission
###################################################################
#Import Additional Files
###################################################################
. $(Join-Path $PSScriptRoot 'SupportAndThirdPartyFunctions.ps1')