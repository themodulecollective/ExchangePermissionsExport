Function GetExchangePSSession
{

    [CmdletBinding(DefaultParameterSetName = 'ExchangeOnline')]
    param
    (
        [parameter(ParameterSetName = 'ExchangeOnPremises')]
        [pscredential]$Credential = $script:Credential
        ,
        [parameter(Mandatory, ParameterSetName = 'ExchangeOnPremises')]
        [string]$ExchangeServer
        ,
        [parameter(Mandatory, ParameterSetName = 'ExchangeOnline')]
        [Hashtable]$ConnectExchangeOnlineParams
        ,
        [System.Management.Automation.Remoting.PSSessionOption]$PSSessionOption
    )


    switch ($PSCmdlet.ParameterSetName)
    {
        'ExchangeOnline'
        {
            $NewPsSessionParams = @{}
            $NewPsSessionParams.EnableNetworkAccess = $true
            $ExchangeSession = New-PSSession @NewPsSessionParams
            Invoke-Command -Session $ExchangeSession -ScriptBlock {
                Import-Module ExchangeOnlineManagement -MinimumVersion '3.0.0'
                Connect-ExchangeOnline @ConnectExchangeOnlineParams
            }

        }
        'ExchangeOnPremises'
        {
            $NewPsSessionParams = @{}
            if ($null -ne $Credential)
            {
                $NewPsSessionParams.Credential = $Credential
            }
            $NewPsSessionParams.ConnectionURI = 'http://' + $ExchangeServer + '/PowerShell/'
            $NewPsSessionParams.Authentication = 'Kerberos'
            $ExchangeSession = New-PSSession @NewPsSessionParams
            Invoke-Command -Session $ExchangeSession -ScriptBlock { Set-ADServerSettings -ViewEntireForest $true -ErrorAction 'Stop' } -ErrorAction Stop
        }
    }
    $ExchangeSession

}
