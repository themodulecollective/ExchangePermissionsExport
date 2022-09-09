Function GetExchangePSSession
{
    
    [CmdletBinding(DefaultParameterSetName = 'ExchangeOnline')]
    param
    (
        [parameter(ParameterSetName = 'ExchangeOnline', Mandatory)]
        [parameter(ParameterSetName = 'ExchangeOnPremises')]
        [pscredential]$Credential = $script:Credential
        ,
        [parameter(Mandatory, ParameterSetName = 'ExchangeOnline')]
        [switch]$ExchangeOnline
        ,
        [parameter(Mandatory, ParameterSetName = 'ExchangeOnPremises')]
        [string]$ExchangeServer
        ,
        [parameter(ParameterSetName = 'ExchangeOnline')]
        $ConnectionMethod = $script:ExchangeOnlineConnectionMethod
        ,
        [System.Management.Automation.Remoting.PSSessionOption]$PSSessionOption
    )
    $NewPsSessionParams = @{
        ErrorAction       = 'Stop'
        ConfigurationName = 'Microsoft.Exchange'
    }
    if ($null -ne $Credential)
    {
        $NewPsSessionParams.Credential = $Credential
    }
    switch ($PSCmdlet.ParameterSetName)
    {
        'ExchangeOnline'
        {
            switch ($ConnectionMethod)
            {
                'RemotePowerShellBasicAuth'
                {
                    $NewPsSessionParams.ConnectionURI = 'https://outlook.office365.com/powershell-liveid/'
                    $NewPsSessionParams.Authentication = 'Basic'
                    $ExchangeSession = New-PSSession @NewPsSessionParams
                }
                'ExchangeOnlineManagement'
                {
                    $CEXOParams = @{
                        ErrorAction = 'Stop'
                        ShowBanner  = $False
                    }
                    try
                    {
                        Connect-ExchangeOnline -Credential $Credential @CEXOParams
                    }
                    catch
                    {
                        Write-Verbose -Verbose -Message "MFA Required $($_.tostring())"
                        Connect-ExchangeOnline -UserPrincipalName $Credential.UserName @CEXOParams
                    }
                    finally
                    {
                        $ExchangeSession = Get-PSSession | Where-Object -FilterScript { $_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.Name -like 'ExchangeOnlineInternalSession_*' | Select-Object -First 1 }
                    }
                }
            }
        }
        'ExchangeOnPremises'
        {
            $NewPsSessionParams.ConnectionURI = 'http://' + $ExchangeServer + '/PowerShell/'
            $NewPsSessionParams.Authentication = 'Kerberos'
            $ExchangeSession = New-PSSession @NewPsSessionParams
            Invoke-Command -Session $ExchangeSession -ScriptBlock { Set-ADServerSettings -ViewEntireForest $true -ErrorAction 'Stop' } -ErrorAction Stop
        }
    }
    $ExchangeSession

}

