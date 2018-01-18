###################################################################
#Exchange Permissions Export Module
###################################################################
$script:ConnectExchangeOrganizationCompleted = $false
###################################################################
#Import Function Scripts
###################################################################
. $(Join-Path $PSScriptRoot 'PrivateFunctions.ps1')
. $(Join-Path $PSScriptRoot 'SupportingFunctions.ps1')
. $(Join-Path $PSScriptRoot 'ThirdPartyFunctions.ps1')
. $(Join-Path $PSScriptRoot 'PublicFunctions.ps1')