#Requires -Version 5.1
###############################################################################################
# Module Variables
###############################################################################################
$ModuleVariableNames = ('ExchangePermissionsExportConfiguration', 'ConnectExchangeOrganizationCompleted', 'OrganizationType','HRPropertySet')
$ModuleVariableNames.ForEach( { Set-Variable -Scope Script -Name $_ -Value $null })
$script:ConnectExchangeOrganizationCompleted = $false
$script:HRPropertySet = @(
  'Alias'
  'DisplayName'
  'Name'
  'SamAccountName'
  'UserPrincipalName'
  'ArchiveName'
  'SimpleDisplayName'
  'DistinguishedName'
  'PrimarySmtpAddress'
  'WindowsEmailAddress'
  'RemoteRecipientType'
  'RecipientType'
  'RecipientTypeDetails'
  'ExchangeGuid'
  'NetID'
  'WindowsLiveID'
  'ImmutableId'
  'ExternalDirectoryObjectId'
  'Identity'
  'Guid'
)
#enum InstallManager { Chocolatey; Git; PowerShellGet; Manual; WinGet }

###############################################################################################
# Module Removal
###############################################################################################
#Clean up objects that will exist in the Global Scope due to no fault of our own . . . like PSSessions

$OnRemoveScript = {
  # perform cleanup
  Write-Verbose -Message 'Removing Module Items from Global Scope'
}

$ExecutionContext.SessionState.Module.OnRemove += $OnRemoveScript
