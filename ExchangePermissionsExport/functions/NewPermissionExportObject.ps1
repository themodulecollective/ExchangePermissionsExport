Function NewPermissionExportObject
{

    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        $TargetMailbox
        ,
        [parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$TrusteeIdentity
        ,
        [parameter()]
        [AllowNull()]
        $TrusteeRecipientObject
        ,
        [parameter(Mandatory)]
        [ValidateSet('FullAccess', 'SendOnBehalf', 'SendAs', 'None', 'Folder','AutoMapping')]
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
        [Nullable[boolean]]$IsInherited = $False
        ,
        [Nullable[boolean]]$IsAutoMapped = $null
        ,
        [switch]$none
        ,
        $TargetFolderPath
        ,
        $TargetFolderType
        ,
        $FolderAccessRights

    )#End Param
    $PermissionExportObject =
    [pscustomobject]@{
        PermissionIdentity          = $([guid]::NewGuid()).guid
        ParentPermissionIdentity    = $ParentPermissionIdentity
        SourceExchangeOrganization  = $SourceExchangeOrganization
        TargetObjectGUID            = $TargetMailbox.Guid.Guid
        TargetExchangeGUID          = $TargetMailbox.ExchangeGuid.Guid
        TargetDistinguishedName     = $TargetMailbox.DistinguishedName
        TargetPrimarySMTPAddress    = $TargetMailbox.PrimarySmtpAddress.ToString()
        TargetAlias                 = $TargetMailbox.Alias
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
        IsAutoMapped                = $IsAutoMapped
        TrusteeObjectGUID           = $null
        TrusteeExchangeGUID         = $null
        TrusteeDistinguishedName    = if ($None) { 'none' } else { $null }
        TrusteePrimarySMTPAddress   = if ($None) { 'none' } else { $null }
        TrusteeAlias                = $null
        TrusteeRecipientType        = $null
        TrusteeRecipientTypeDetails = $null
    }
    if ($null -ne $TrusteeRecipientObject)
    {
        $PermissionExportObject.TrusteeObjectGUID = $TrusteeRecipientObject.guid.Guid
        $PermissionExportObject.TrusteeExchangeGUID = $TrusteeRecipientObject.ExchangeGuid.Guid
        $PermissionExportObject.TrusteeDistinguishedName = $TrusteeRecipientObject.DistinguishedName
        $PermissionExportObject.TrusteePrimarySMTPAddress = $TrusteeRecipientObject.PrimarySmtpAddress.ToString()
        $PermissionExportObject.TrusteeAlias = $TrusteeRecipientObject.Alias
        $PermissionExportObject.TrusteeRecipientType = $TrusteeRecipientObject.RecipientType
        $PermissionExportObject.TrusteeRecipientTypeDetails = $TrusteeRecipientObject.RecipientTypeDetails
    }
    $PermissionExportObject

}
