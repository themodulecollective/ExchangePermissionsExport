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
        [parameter(Mandatory)]
        [validateset('ExchangeOnPremises', 'ExchangeOnline')]
        [string]$ExchangeOrgType
        ,
        #Used to specify the connection method to use with Exchange Online. Will be deprecated with the advent of the OAuth ExchangeOnlineManagement module.
        [parameter(ParameterSetName = 'ExchangeOnline', Mandatory)]
        [validateset('RemotePowerShellBasicAuth', 'ExchangeOnlineManagement')]
        [string]$ConnectionMethod
        ,
        #Credential to use with the Exchange Session.  Required for reconnection scenarios with Exchange On Premises
        [parameter()]
        [pscredential]$Credential
        ,
        #use if your Exchange On Premises environment requires particular PSSessionOptions.
        [System.Management.Automation.Remoting.PSSessionOption]$PSSessionOption
    )

    switch ($ExchangeOrgType)
    {
        'ExchangeOnPremises'
        {
            if ([string]::IsNullOrWhiteSpace($ExchangeOnPremisesServer))
            {
                throw("Parameter -ExchangeOnPremisesServer is required when -ExchangeOrgType is 'ExchangeOnPremises'")
            }
        }
        'ExchangeOnline'
        {
            if ([string]::IsNullOrWhiteSpace($ConnectionMethod))
            {
                throw("Parameter -ConnectionMethod is required when -ExchangeOrgType is 'ExchangeOnline'")
            }
        }
    }

    $script:Credential = $Credential
    #since this is user facing we always assume that if called the existing session needs to be replaced
    if ($null -ne $script:PsSession -and $script:PsSession -is [System.Management.Automation.Runspaces.PSSession])
    {
        Remove-PSSession -Session $script:PsSession -ErrorAction SilentlyContinue
    }
    $GetExchangePSSessionParams = @{
        ErrorAction = 'Stop'
    }
    if ($null -ne $script:Credential)
    {
        $GetExchangePSSessionParams.Credential = $script:Credential
    }
    if ($null -ne $PSSessionOption)
    {
        $script:PSSessionOption = $PSSessionOption
        $GetExchangePSSessionParams.PSSessionOption = $script:PSSessionOption
    }
    switch ($PSCmdlet.ParameterSetName)
    {
        'ExchangeOnline'
        {
            $Script:OrganizationType = 'ExchangeOnline'
            $Script:ExchangeOnlineConnectionMethod = $ConnectionMethod
            $GetExchangePSSessionParams.ExchangeOnline = $true
            $GetExchangePSSessionParams.ConnectionMethod = $Script:ExchangeOnlineConnectionMethod
        }
        'ExchangeOnPremises'
        {
            $Script:OrganizationType = 'ExchangeOnPremises'
            $Script:ExchangeOnPremisesServer = $ExchangeOnPremisesServer
            $GetExchangePSSessionParams.ExchangeServer = $script:ExchangeOnPremisesServer
        }
    }
    $script:PsSession = GetExchangePSSession @GetExchangePSSessionParams
    $script:ConnectExchangeOrganizationCompleted = $true

}
