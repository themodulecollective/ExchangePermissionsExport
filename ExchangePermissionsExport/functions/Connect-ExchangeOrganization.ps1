Function Connect-ExchangeOrganization
{
    <#
    .SYNOPSIS
        Establishes a resilient connection to an Exchange Organization.  Used to Re-connect if needed during long running operations.
    .DESCRIPTION
        Establishes a resilient connection to an Exchange Organization.  Used to Re-connect if needed during long running operations. Works with Exchange Online and Exchange On Premises. Required for the commands in this module.
    .NOTES

    .LINK

    .EXAMPLE
        Connect-ExchangeOrganization -ExchangeOnPremisesServer 'Exchange01' -Credential $ExchangeCred
        Establishes a powershell session to the Microsoft.Exchange endpoint on the named Exchange server.  Stores the server information and credential in memory for re-connect during long running permission export operations if a disconnection is detected.
    #>

    [CmdletBinding(DefaultParameterSetName = 'ExchangeOnline')]
    param
    (
        #Name of Exchange On Premises Server to Connect to.  Use FQDN if necessary for name resolution.
        [parameter(ParameterSetName = 'ExchangeOnPremises', Mandatory)]
        [string]$ExchangeOnPremisesServer
        ,
        #Specify the type of Exchange Organization to be connected to.  Function uses this internally to determine the connection method to use.
        [parameter(Mandatory, ParameterSetName = 'ExchangeOnPremises')]
        [switch]$OnPremises
        ,
        #Specify the type of Exchange Organization to be connected to.  Function uses this internally to determine the connection method to use.
        [parameter(Mandatory, ParameterSetName = 'ExchangeOnline')]
        [switch]$Online
        ,
        #Credential to use with the On Premises Exchange Session.  Recommended even where Kerberso SSO would otherwise work--Required for reconnection scenarios with Exchange On Premises
        [parameter(ParameterSetName = 'ExchangeOnPremises')]
        [pscredential]$Credential
        ,
        #use if your Exchange On Premises environment requires particular PSSessionOptions.
        [parameter(ParameterSetName = 'ExchangeOnPremises')]
        [System.Management.Automation.Remoting.PSSessionOption]$PSSessionOption
        ,
        #hashtable to be used with Exchange Online connection - will be passed through to Connect-ExchangeOnline, for example @{UserPrincipalName = 'Admin@contoso.com'}
        [parameter(Mandatory, ParameterSetName = 'ExchangeOnline')]
        [hashtable]$ConnectExchangeOnlineParams

    )


    #since this is user facing we always assume that if called the existing session needs to be replaced
    if ($null -ne $script:PsSession -and $script:PsSession -is [System.Management.Automation.Runspaces.PSSession])
    {
        Remove-PSSession -Session $script:PsSession -ErrorAction SilentlyContinue
    }
    $GetExchangePSSessionParams = @{
        ErrorAction = 'Stop'
    }

    if ($Online)
    {
        $Script:OrganizationType = 'ExchangeOnline'
        $RequiredModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement
        switch ($RequiredModule)
        {
            $null
            {
                throw('PowerShell Module ExchangeOnlineManagement 3.0.0 or later is required.')
            }
            {$RequiredModule.Version.Major -lt 3}
            {
                throw('PowerShell Module ExchangeOnlineManagement 3.0.0 or later is required.')
            }
        }
        $Script:ConnectExchangeOnlineParams = $ConnectExchangeOnlineParams
        $GetExchangePSSessionParams.ConnectExchangeOnlineParams = $script:ConnectExchangeOnlineParams
    }
    if ($OnPremises)
    {
        $Script:OrganizationType = 'ExchangeOnPremises'
        $script:Credential = $Credential
        if ($null -ne $script:Credential)
        {
            $GetExchangePSSessionParams.Credential = $script:Credential
        }
        if ($null -ne $PSSessionOption)
        {
            $script:PSSessionOption = $PSSessionOption
            $GetExchangePSSessionParams.PSSessionOption = $script:PSSessionOption
        }

        $Script:ExchangeOnPremisesServer = $ExchangeOnPremisesServer
        $GetExchangePSSessionParams.ExchangeServer = $script:ExchangeOnPremisesServer
    }

    $script:PsSession = GetExchangePSSession @GetExchangePSSessionParams
    $script:ConnectExchangeOrganizationCompleted = $true

}
