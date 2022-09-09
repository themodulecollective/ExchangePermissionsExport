Function Connect-ExchangeOrganization
{
    
    [CmdletBinding(DefaultParameterSetName = 'ExchangeOnline')]
    param
    (
        [parameter(ParameterSetName = 'ExchangeOnPremises', Mandatory)]
        [string]$ExchangeOnPremisesServer
        ,
        [parameter(Mandatory)]
        [validateset('ExchangeOnPremises', 'ExchangeOnline')]
        [string]$ExchangeOrgType
        ,
        [parameter(ParameterSetName = 'ExchangeOnline', Mandatory)]
        [validateset('RemotePowerShellBasicAuth', 'ExchangeOnlineManagement')]
        [string]$ConnectionMethod
        ,
        [parameter()]
        [pscredential]$Credential
        ,
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

