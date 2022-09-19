Function GetGetExchangePSSessionParams
{

    $GetExchangePSSessionParams = @{
        ErrorAction = 'Stop'
        Credential  = $script:Credential
    }
    if ($null -ne $script:PSSessionOption -and $script:PSSessionOption -is [System.Management.Automation.Remoting.PSSessionOption])
    {
        $GetExchangePSSessionParams.PSSessionOption = $script:PSSessionOption
    }
    switch ($Script:OrganizationType)
    {
        'ExchangeOnline'
        {
            $GetExchangePSSessionParams.ExchangeOnline = $true
            $GetExchangePSSessionParams.ConnectionMethod = $script:ExchangeOnlineConnectionMethod
        }
        'ExchangeOnPremises'
        {
            $GetExchangePSSessionParams.ExchangeServer = $script:ExchangeOnPremisesServer
        }
    }
    $GetExchangePSSessionParams

}
