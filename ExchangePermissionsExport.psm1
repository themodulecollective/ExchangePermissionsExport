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
Function Export-Permissions
{
    #ToDo
    #Add an attribute to the permission object which indicates if the target/permholder were in the mailboxes scope
    #switch ExchangeOrganization to a dynamic parameter
    #use get-group and/or get-user when get-recipient fails to get an object
    #move code to add additional attributes to export object to a new function or update the existin function
    #Fix Fullaccess to leverage SID History and Inheritance options
    #Make inheritance work for expanded group perms, too. right now will say false for all which isn't correct.
    #add excluded prefixes with split on \
    #add scoping by OU? integrate EXO recipients as a filter of some sort?
    #fix ugly out-file hack
    #implement explicit garbage collection. 
    #fix denies --done
    #globalsendas -- done
    ##parameterset -- done
    ##recip instead of mailbox -- done just for globalsendas
    #sid stuff -- done
    #AD connection -- done
    #inheritance switch and output -- done
    #hard-code sendas guid -- done
    #add genericall -- done

    [cmdletbinding(DefaultParameterSetName = 'AllMailboxes')]
    param(
        [string]$ExchangeOrganization
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
        #Trustees in these NETBIOS domains will be ignored. Only SendAs for now.
        [string[]]$ExcludedTrusteeDomains
        ,
        #These trustees (Domain\username) will be ignored. Only SendAs for now.
        [string[]]$ExcludedTrustees
        ,
        [parameter(ParameterSetName = 'Scoped',Mandatory)]
        [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
        [boolean]$IncludeSendOnBehalf = $true
        ,
        [parameter(ParameterSetName = 'Scoped',Mandatory)]
        [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
        [boolean]$IncludeFullAccess = $true
        ,
        [parameter(ParameterSetName = 'Scoped',Mandatory)]
        [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
        [boolean]$IncludeSendAs = $true
        ,
        [boolean]$expandGroups = $true
        ,
        [boolean]$dropExpandedGroups = $false
        ,
        [boolean]$dropInheritedPermissions = $false #Currently Functional Only For Send-As, though this function is hard-coded to ignore inherited FMB and inherited SendOnBehalf is not possible.
        ,
        [parameter(Mandatory)]
        [string]$ActiveDirectoryInstance
    )#End Param
    Function Get-SIDHistoryRecipientHash {
        param (
            [parameter(Mandatory)]
            $ActiveDirectoryInstance,
            $ExchangeOrganization
        )#End param
        Write-Log -Message "Operation: Retrieve Mapping for all User Recipients with SIDHistory." -Verbose
        $SIDHistoryRecipientHash = @{}
        Push-Location
        Set-Location $("$ActiveDirectoryInstance`:") -ErrorAction Stop
        $sidhistoryusers = get-aduser -ldapfilter "(&(legacyExchangeDN=*)(sidhistory=*))" -Properties sidhistory,legacyExchangeDN
        Pop-Location
        $CurrentEA = $Global:ErrorActionPreference
        $sidhistoryusercounter = 0
        $Global:ErrorActionPreference = 'Stop'
        Foreach ($sidhistoryuser in $sidhistoryusers) {
            $sidhistoryusercounter++
            $message = 'Generating hash of SIDHistory SIDs and Recipient objects...'
            $ProgressInterval = [int]($($sidhistoryusers.Count) * .01)
            if ($($sidhistoryusercounter) % $ProgressInterval -eq 0)
                {Write-Progress -Activity $message -status "Items processed: $($sidhistoryusercounter) of $($sidhistoryusers.Count)" -percentComplete (($sidhistoryusercounter / $($sidhistoryusers.Count))*100)}
            $splat = @{Identity = $sidhistoryuser.ObjectGuid.guid}
            $sidhistoryuserrecipient = $Null
            Try {$sidhistoryuserrecipient = Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat}
            Catch {}
            If (!($sidhistoryuserrecipient)) {Continue}
            Foreach ($sidhistorysid in $sidhistoryuser.sidhistory) {
                $SIDHistoryRecipientHash.$($sidhistorysid.value) = $sidhistoryuserrecipient
            }#End Foreach
        }#End Foreach
        $Global:ErrorActionPreference = $CurrentEA
        Write-Output $SIDHistoryRecipientHash
    }#End Get-SIDHistoryRecipientHash
    if (!(Connect-Exchange -ExchangeOrganization $ExchangeOrganization)) {
        write-log -Message "Could not connect to Exchange Organization $($ExchangeOrganization)" -ErrorLog
        throw {"Could not connect to Exchange Organization $($ExchangeOrganization)"}
        
    }#End If
    if (!(Connect-ADInstance $ActiveDirectoryInstance)) {
        write-log -Message "Could not connect to Active Directory Intance $($ActiveDirectoryInstance)" -ErrorLog
        throw {"Could not connect to Active Directory Instance $($ActiveDirectoryInstance)"}
    }#End If
    #Region GetInScopeMailboxes
    switch ($PSCmdlet.ParameterSetName)
    {
        'Scoped'
        { 
            Write-Log -Message "Operation: Scoped Permission retrieval with $($Identity.Count) Identities provided." -Verbose
            $message = "Retrieve mailbox object for each provided Identity in Exchange Organization $ExchangeOrganization."
            Write-Log -Message $message -EntryType Attempting -Verbose
            $InScopeMailboxes = @($Identity | ForEach-Object {
                    $splat = @{Identity = $_}
                    Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat
                }
            )
            Write-Log -Message $message -EntryType Succeeded -Verbose
        }
        'AllMailboxes'
        {
            Write-Log -Message "Operation: Permission retrieval for all mailboxes." -Verbose
            $message = "Retrieve all available mailbox objects in Exchange Organization $ExchangeOrganization."
            Write-Log -Message $message -EntryType Attempting -Verbose
            $splat = @{ResultSize = 'Unlimited'}
            $InScopeMailboxes = @(Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Mailbox' -splat $splat)
            Write-Log -Message $message -EntryType Succeeded -Verbose
        }
        'GlobalSendAs'
        {
            Write-Log -Message "Operation: Send As Permission retrieval for all recipients." -Verbose
            $message = "Retrieve all available recipient objects in Exchange Organization $ExchangeOrganization."
            Write-Log -Message $message -EntryType Attempting -Verbose
            $splat = @{ResultSize = 'unlimited'}
            $InScopeMailboxes = @(Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat)
            Write-Log -Message $message -EntryType Succeeded -Verbose
        }
    }
    #EndRegion GetInScopeMailboxes
    if ($PSBoundParameters.ContainsKey('ExcludedIdentities'))
    {
        $excludedRecipients = @(
            $ExcludedIdentities | ForEach-Object {
                $splat = @{
                    Identity = $_
                    ErrorAction = 'SilentlyContinue'
                }
                Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat
            }
        )
        $excludedRecipientsGUIDHash = $excludedRecipients | Group-Object -Property GUID -AsString -AsHashTable
    }

    #ADSI Adapter: http://social.technet.microsoft.com/wiki/contents/articles/4231.working-with-active-directory-using-powershell-adsi-adapter.aspx
    <#$dse = [ADSI]"LDAP://Rootdse"
    $ext = [ADSI]("LDAP://CN=Extended-Rights," + $dse.ConfigurationNamingContext)
    $dn = [ADSI]"LDAP://$($dse.DefaultNamingContext)"
    $dsLookFor = New-Object System.DirectoryServices.DirectorySearcher($dn)
    $permission = "Send As"
    $right = $ext.psbase.Children | Where-Object { $_.DisplayName -eq $permission }

    commented out the above since the GUID for this right seems to be well-known. the below is the GUID is extracted from the above object if you want to revert.

    [GUID]$right.RightsGuid.Value#>

    $right = [GUID]'ab721a54-1e2f-11d0-9819-00aa0040529b' #Well-known GUID for Send As Permissions
    $CanonicalNameHash = @{}
    $DomainPrincipalHash = @{}
    $DistinguishedNameHash = $InScopeMailboxes | Group-Object -AsHashTable -Property DistinguishedName -AsString
    $SIDHistoryRecipientHash = Get-SIDHistoryRecipientHash -ActiveDirectoryInstance $ActiveDirectoryInstance -ExchangeOrganization $ExchangeOrganization
    $MissingOrAmbiguousRecipients = @()
    $mailboxCounter = 0
    $InScopeMailboxCount = $InScopeMailboxes.count
    [uint32]$Script:PermissionIdentity = 0
    Foreach ($mailbox in $InScopeMailboxes)
    {
        $mailboxCounter++
        if ($PSBoundParameters.ContainsKey('ExcludedIdentities'))
        {
            if ($excludedRecipientsGUIDHash.ContainsKey($mailbox.guid.Guid))
            {
                continue
            }
        }
        $ID = $mailbox.PrimarySMTPAddress.ToString();
        $message = "Collect permissions for $($ID)"
        Write-Progress -Activity $message -status "Items processed: $($mailboxCounter) of $($InScopeMailboxCount)" -percentComplete (($mailboxCounter / $InScopeMailboxCount)*100)
        Write-Log -Message $message -EntryType Attempting -Verbose
        $rawPermissions = @(
            #Get Delegate Users (actual permissions are stored in the mailbox . . . so these are not true delegates just a likely correlation to delegates) This section should also check if the grantsendonbehalfto permission holder is a group, because it can be . . .
            If (($IncludeSendOnBehalf) -and (!($GlobalSendAs)))
            {
                $sbTrustees = $mailbox.grantsendonbehalfto.ToArray()
                foreach ($sb in $sbTrustees)
                {
                    New-PermissionExportObject -TargetMailbox $mailbox -TrusteeIdentity $sb -PermissionType SendOnBehalf -AssignmentType Direct -SourceExchangeOrganization $ExchangeOrganization
                }
            }
            #Get Full Access Users
            If (($IncludeFullAccess) -and (!($GlobalSendAs)))
            {
                $faTrustees = @(
                    $splat = @{Identity = $ID; ErrorAction = 'SilentlyContinue'}
                    Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-MailboxPermission' -splat $splat |
                    Where-Object -FilterScript {
                        ($_.AccessRights -like “*FullAccess*”) -and 
                        ($_.IsInherited -eq $false) -and -not 
                        ($_.User -like “NT AUTHORITY\SELF”) -and -not 
                        ($_.Deny -eq $True) -and -not
                        ($_.User -like "S-1-5*")
                    } | Select-Object -ExpandProperty User
                )
                foreach ($fa in $faTrustees)
                {
                    New-PermissionExportObject -TargetMailbox $mailbox -TrusteeIdentity $fa -PermissionType FullAccess -AssignmentType Direct -SourceExchangeOrganization $ExchangeOrganization
                }
            }
            #Get Send As Users
            If (($IncludeSendAs) -or ($GlobalSendAs))
            {
                if (!(Connect-Exchange -ExchangeOrganization $ExchangeOrganization)) {
                    write-log -Message "Could not connect to Exchange Organization $($ExchangeOrganization)" -ErrorLog
                    throw {"Could not connect to Exchange Organization $($ExchangeOrganization)"}
                    
                }#End If
                $userDN = [ADSI]("LDAP://$($mailbox.DistinguishedName)")
                $saTrustees = @(
                    $userDN.psbase.ObjectSecurity.Access | Where-Object -FilterScript { (($_.ObjectType -eq $right) -or ($_.ActiveDirectoryRights -eq 'GenericAll')) -and ($_.AccessControlType -eq 'Allow')} | 
                    Where-Object -FilterScript {$_.identityreference -notin $ExcludedTrustees}|Where-Object -FilterScript {($_.identityreference.ToString().split('\')[0]) -notin $ExcludedTrusteeDomains}|Select-Object identityreference,IsInherited 
                    #| Where-Object -FilterScript {$_ -notlike "NT AUTHORITY\SELF"}
                )
                foreach ($sa in $saTrustees)
                {	
                    If ($sa.IsInherited -eq $true) {
                        If ($dropInheritedPermissions) {Continue}
                    }#End If
                    
                    New-PermissionExportObject -TargetMailbox $mailbox -TrusteeIdentity $sa.identityreference -PermissionType SendAs -AssignmentType Direct -SourceExchangeOrganization $ExchangeOrganization -IsInherited $sa.IsInherited
                }
            }
        )
        #compile permissions information and permission holders identity details
        foreach ($rp in $rawPermissions)
        {
            $Recipient = @()
            switch ($rp.PermissionType)
            {
                'SendOnBehalf' #uses CanonicalName format!?!
                {
                    if ($CanonicalNameHash.ContainsKey($rp.TrusteeIdentity))
                    {
                        $Recipient = @($CanonicalNameHash.$($rp.TrusteeIdentity))
                    }
                }
                Default #both SendAs and FullAccess use Domain\SecurityPrincipal format
                {
                    if ($DomainPrincipalHash.ContainsKey($rp.TrusteeIdentity))
                    {
                        $Recipient = @($DomainPrincipalHash.$($rp.TrusteeIdentity))
                    }
                    elseif ($SIDHistoryRecipientHash.ContainsKey($rp.TrusteeIdentity)) {
                        $Recipient = @($SIDHistoryRecipientHash.$($rp.TrusteeIdentity))
                    }#End elseif
                }
            }
            if ($Recipient.Count -eq 0)
            {
                $splat = @{Identity = $rp.TrusteeIdentity; ErrorAction = 'SilentlyContinue'}
                $Recipient = @(Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat)
            }
            switch ($Recipient.Count)
            {
                1
                {
                    $Recipient = $Recipient[0]
                    Add-TrusteeAttributesToPermissionExportObject -rawPermissionExportObject $rp -TrusteeRecipientObject $Recipient
                    switch ($rp.permissionType) {
                        'SendOnBehalf' {$CanonicalNameHash.$($rp.TrusteeIdentity) = $Recipient}
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
                            $Recipient = @(Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat)
                        }
                        switch ($Recipient.count)
                        {
                            1
                            {
                                $Recipient = $Recipient[0]
                                $GPEOParams = @{
                                    TargetMailbox = $Mailbox
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
                                    TargetMailbox = $Mailbox
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
                    (-not $excludedRecipientsGUIDHash.ContainsKey($_.TrusteeObjectGUID))
                }
            )
        }
        if ($AllPermissionsOutput.Count -eq 0)
        {
            $GPEOParams = @{
                TargetMailbox = $mailbox
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
        Write-Log -Message $message -EntryType Succeeded -Verbose
    }#Foreach mailbox in set
        if ($MissingOrAmbiguousRecipients.count -ge 1)
        {
            $MissingOrAmbiguousRecipients = $MissingOrAmbiguousRecipients | Sort-Object | Select-Object -Unique
            $joinedIDs = $MissingOrAmbiguousRecipients -join '|'
            Write-Log -Message "The following identities are missing (as recipient objects) or ambiguous: $joinedIDs" -EntryType Notification -Verbose -ErrorLog
            $ExportFilePath = $script:ExportDataPath +  (get-timestamp)  + 'MissingOrAmbiguousRecipients' + '.txt'
            $MissingOrAmbiguousRecipients | out-file $exportFilePath
        }
}
#End Function Export-Permissions