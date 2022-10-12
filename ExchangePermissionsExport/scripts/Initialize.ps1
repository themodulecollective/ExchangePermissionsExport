#Requires -Version 5.1
###############################################################################################
# Module Variables
###############################################################################################
$ModuleVariableNames = ('ExchangePermissionsExportConfiguration', 'ConnectExchangeOrganizationCompleted', 'OrganizationType','HRPropertySet')
$ModuleVariableNames.ForEach( { Set-Variable -Scope Script -Name $_ -Value $null })
$script:ConnectExchangeOrganizationCompleted = $false
$script:HRPropertySet = @('*name*', '*addr*', 'RecipientType*', '*Id', 'Identity', 'GrantSendOnBehalfTo','Alias')
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
