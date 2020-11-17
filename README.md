# ExchangePermissionsExport

PowerShell Module for Improved Permissions Export Functions to Support Exchange Migrations including upgrades, on-premises to on-premises, on-premises to online, online to online, etc. Exported permissions can be used for permission replay for migrations and/or for analysis of user relationships for migration batching.

This module improves on soyalejolopez/Find-MailboxDelegates to improve output so that it is coherent and consistent across permission types and Exchange Organizations whether they are in Exchange Online or Exchange On Premises.  It also fixes a number of performance and logical errors compared to Find-MailboxDelegates and provides more modular code for easier troubleshooting and improvement.

This module does not provide permissions analysis for migration batching.  Instead, another module will do that entitled ExchangePermissionsAnalysis.

## Using ExchangePermissionsExport - Getting Started

1. Download a release and install into one of the module folder paths that is in your $env:PSModulePath variable
2. From a Windows PowerShell 3.0 or later session (not tested on PowerShell 6.x), import the module

```powershell

Import-Module ExchangePermissionsExport

# Or if you just downloaded the files to a non PSModulePath location do this using the full path to the psd1 file or first set the location to the directory where the ExchangePermissionsExport.psd1 file is located:

Import-module .\ExchangePermissionsExport.psd1

```

3. Use the Connect-ExchangeOrganization function to connect to your Exchange environment.

Exchange Online and Exchange On Premises (2010-2019) are supported. For the credential to use, the minimum Role Group membership required is Recipient Management.  The Export-ExchangePermission function requires that you connect to Exchange via the Connect-ExchangeOrganization function so that it can automatically re-connect as needed during processing. It does not import the session into the local powershell session but instead invokes commands in that session.

If you need to use PSSessionOption to connect to your Exchange from your workstation or server (usually due to proxy connections), you can create a PSSessionOption using New-PSSessionOption and pass it to Connect-ExchangeOrganization using the -PSSessionOption parameter.

Basic support for the ExchangeOnlineManagement (V2) module is now included.  You provide your credential to the Connect-ExchangeOrganization function but if you have previously established a connection to Exchange Online using ExchangeOnlineManagement and performed MFA (if required in your scenario) you should usually not be prompted for MFA again, unless the MFA lifetime has expired.

- Connect to Exchange Online with an administrative credential.

```powershell

# This example uses basic auth with Exchange Online
Connect-ExchangeOrganization -ExchangeOrgType ExchangeOnline -Credential $YourCredential -ConnectionMethod RemotePowerShellBasicAuth

# This example uses the ExchangeOnlineManagement module to connect (possibly with MFA)
Connect-ExchangeOrganization -ExchangeOrgType ExchangeOnline -ConnectionMethod ExchangeOnlineManagement -Credential $YourCredential

```

OR

- Connect to Exchange On Premises with an administrative credential.

For Exchange On Premises you will also need to specify the fully qualified domain name of one of your Exchange Servers.

```powershell

Connect-ExchangeOrganization -ExchangeOnPremisesServer 'exchange01.contoso.com' -Credential $YourCredential -ExchangeOrgType ExchangeOnPremises

```

When working with Exchange On Premises it is usually best to perform some of the operations using AD connections versus Exchange Connections (peformance of retrieval of SendAs permissions and group expansion can be much more performant with AD than with Exchange).  In that case run the following in the same session where you establish an Exchange connection:

```powershell

import-module activedirectory #needs to connect to the domain where your mailboxes reside.  Multi-domain/forest support is not tested at this time.
$AD = Get-PSDrive -PSProvider ActiveDirectory

```

Later, when running Export-ExchangePermission use the -ActiveDirectoryDrive parameter with value $AD.

4. Use the Export-ExchangePermission function to export the desired set of permissions.

### Basic Usage Pattern

-OutputFolderPath is a required parameter.

- to export permissions for all mailboxes in the organization including FullAccess, SendAS, SendOnBehalf, and Calendar permissions, and to expand group permissions out to include the group members in the output use the following syntax:

```powershell

Export-ExchangePermission -OutputFolderPath c:\SharedData -AllMailboxes

```

- common modifications to the above would be to add the -dropInheritedPermissions boolean parameter or to use the -ExcludedIdentities to skip certain mailboxes or -ExcludedTrusteeIdentities to ignore certain permission holders.

### Recommended Usage Pattern

After establishing your connection, the following pattern is recommended for best performance.

```powershell

# On Premises

import-module activedirectory #needs to connect to ADMED domain
$AD = Get-PSDrive -PSProvider ActiveDirectory

#gets all the full access, delegate, and calendar permissions
Export-ExchangePermission -OutputFolderPath D:\ExchangeReports\PermissionsExport -IncludeSendOnBehalf $true -IncludeCalendar $true -IncludeFullAccess $true -expandGroups $false -dropInheritedPermissions $true -ActiveDirectoryDrive $AD -ExcludeNonePermissionOutput -AllMailboxes

#gets all sendas permissions
Export-ExchangePermission -OutputFolderPath D:\ExchangeReports\PermissionsExportGlobalSendAS -GlobalSendAs -expandGroups $false -ActiveDirectoryDrive $AD -ExcludeNonePermissionOutput -KeepExportedPermissionsInGlobalVariable

```

## Resume functionality being deprecated

There are currently some parameters in the Export-ExchangePermission function that purport to support 'Resume' functionality.  It is recommended that you NOT use this funcitonality at this time as it is likely to be completely removed and is currently untested with the latest revisions to the module.

## Additional Usage Scenarios

Several other usage scenarios exist which are not yet documented in this file, such as specifying a subset of identities to scan, doing a global SendAS permissions export, using Active Directory to retrieve SendAS permissions (for performance reasons if you have on premises Excange) and/or SIDHistory permissions export (again if you have on premises Exchange but in order to resolve SIDHistory SIDs in your permissions output).

## A note about terminology

In parameters, output, and documenation this module always uses the term 'Trustee' to refer to the holder of a permission to another resource and always uses the term 'Target' to refer to the target resource of a permission.  For example:

- if user Bob has FullAccess permission to user Mary mailbox then Bob is the Trustee and Mary is the Target.
- if group SalesManagers has SendAS permission for mailbox Orders then SalesManagers is the Trustee and Orders is the Target.
- if Steve is a delegate (holds SendOnBehalf permission) for Jenna, then Steve is the Trustee and Jenna is the target.

This approach avoids other sometimes confusing or ambiguous terminology associated with discussion of permissions in Exchange.

## Output

Each permission is exported with the following details as applicable/possible:

- PermissionIdentity          = [incrementing value for this export]
- ParentPermissionIdentity    = [if the original permission was a group, the group permission Identity]
- SourceExchangeOrganization  = [determined from the Get-OrganizationConfig command]
- TargetObjectGUID            = AD or Exchange Online GUID
- TargetObjectExchangeGUID    = ExchangeGUID if available
- TargetDistinguishedName     = AD or Exchange Online Distinguished Name
- TargetPrimarySMTPAddress    = Primary SMTP Address
- TargetRecipientType         = RecipientType
- TargetRecipientTypeDetails  = RecipientTypeDetails
- TargetFolderPath            = [for folder permissions, the folder path, otherwise - NULL]
- TargetFolderType            = [for folder permissions, the folder type, otherwise NULL]
- FolderAccessRights          = [for folder permissions, the folder access rights, delimited by | if necessary]
- PermissionType              = [FullAccess,SendAS,SendOnBehalf,Folder,None]
- AssignmentType              = [Direct,Undetermined,Group]
- TrusteeGroupObjectGUID      = [if the original permission holder was a group, the group AD or Exchange Online object guid]
- TrusteeIdentity             = [the identifier value from the permission object that was used to try to resolve the Trustee]
- IsInherited                 = [IsInherited]
- TrusteeObjectGUID           = [the trustee object's AD guid or Exchange Online Guid if the trustee was resolved]
- TrusteeExchangeGUID         = [the trustee object's ExchangeGUID if trustee was resolved and an ExchangeGUID was found]
- TrusteeDistinguishedName    = [the trustee object's distinguished name if the trustee was resolved]
- TrusteePrimarySMTPAddress   = [the trustee object's primary smtp address if the trustee was resolved and a primary smtp address was found]
- TrusteeRecipientType        = [Recipient type from the resolved trustee object]
- TrusteeRecipientTypeDetails = [Recipient type details from the resolved trustee object]