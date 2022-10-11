Function GetGetExchangePSSessionParams
{
    $GetExchangePSSessionParams = @{
        ErrorAction = 'Stop'
    }
    if ($null -ne $script:PSSessionOption -and $script:PSSessionOption -is [System.Management.Automation.Remoting.PSSessionOption])
    {
        $GetExchangePSSessionParams.PSSessionOption = $script:PSSessionOption
    }
    if ($null -ne $script:Credential)
    {
        $GetExchangePSSessionParams.Credential = $script:Credential
    }
    switch ($Script:OrganizationType)
    {
        'ExchangeOnline'
        {
            $GetExchangePSSessionParams.ConnectExchangeOnlineParams = $ConnectExchangeOnlineParams
        }
        'ExchangeOnPremises'
        {
            $GetExchangePSSessionParams.ExchangeServer = $script:ExchangeOnPremisesServer
        }
    }
    $GetExchangePSSessionParams

}
