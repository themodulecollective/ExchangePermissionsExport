function TestIsWriteableDirectory
    {
        #Credits to the following:
        #http://poshcode.org/2236
        #http://stackoverflow.com/questions/9735449/how-to-verify-whether-the-share-has-write-access
        #pulled in from OneShell module: https://github.com/exactmike/OneShell
        [CmdletBinding()]
        param
        (
            [parameter()]
            [ValidateScript(
                {
                    $IsContainer = Test-Path -Path ($_) -PathType Container
                    if ($IsContainer)
                    {
                        $Item = Get-Item -Path $_
                        if ($item.PsProvider.Name -eq 'FileSystem') {$true}
                        else {$false}
                    }
                    else {$false}
                }
            )]
            [string]$Path
        )
        try
        {
            $testPath = Join-Path -Path $Path -ChildPath ([IO.Path]::GetRandomFileName())
                New-Item -Path $testPath -ItemType File -ErrorAction Stop > $null
            $true
        }
        catch
        {
            $false
        }
        finally
        {
            Remove-Item -Path $testPath -ErrorAction SilentlyContinue
        }
    }
#end function TestIsWriteableDirectory
function GetGuidFromByteArray
    {
        [CmdletBinding()]
        param
        (
            [byte[]]$GuidByteArray
        )
        New-Object -TypeName guid -ArgumentList (,$GuidByteArray)
    }
#end function GetGuidFromByteArray
Function WriteLog
    {
        [cmdletbinding()]
        Param
        (
            [Parameter(Mandatory,Position=0)]
            [ValidateNotNullOrEmpty()]
            [string]$Message
            ,
            [Parameter(Position=1)]
            [string]$LogPath
            ,
            [Parameter(Position=2)]
            [switch]$ErrorLog
            ,
            [Parameter(Position=3)]
            [string]$ErrorLogPath
            ,
            [Parameter(Position=4)]
            [ValidateSet('Attempting','Succeeded','Failed','Notification')]
            [string]$EntryType
        )
        GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
        $TimeStamp = Get-Date -Format yyyyMMdd-HHmmss
        #Add the Entry Type to the message or add nothing to the message if there is not EntryType specified - preserves legacy functionality and adds new EntryType capability
        if (-not [string]::IsNullOrWhiteSpace($EntryType)) {$Message = $EntryType + ':' + $Message}
        $Message = $TimeStamp + ' ' + $Message
        #check the Log Preference to see if the message should be logged or not
        if ($null -eq $LogPreference -or $LogPreference -eq $true)
        {
            #Set the LogPath and ErrorLogPath to the parent scope values if they were not specified in parameter input.  This allows either global or parent scopes to set the path if not set locally
            if ([string]::IsNullOrWhiteSpace($Local:LogPath))
            {
                if (-not [string]::IsNullOrWhiteSpace($Script:LogPath))
                {
                    $Local:LogPath = $script:LogPath
                }
            }
            #Write to Log file if LogPreference is not $false and LogPath has been provided
            if (-not [string]::IsNullOrWhiteSpace($Local:LogPath))
            {
                $Message | Out-File -FilePath $Local:LogPath -Append
            }
            else
            {
                Write-Error -Message 'No LogPath has been provided. Writing Log Entry to script module variable UnwrittenLogEntries' -ErrorAction SilentlyContinue
                if (Test-Path -Path variable:script:UnwrittenLogEntries)
                {
                    $Script:UnwrittenLogEntries += $Message
                }
                else
                {
                    $Script:UnwrittenLogEntries = @()
                    $Script:UnwrittenLogEntries += $Message
                }
            }
            #if ErrorLog switch is present also write log to Error Log
            if ($ErrorLog) {
                if ([string]::IsNullOrWhiteSpace($Local:ErrorLogPath))
                {
                    if (-not [string]::IsNullOrWhiteSpace($Script:ErrorLogPath))
                    {
                        $Local:ErrorLogPath = $Script:ErrorLogPath
                    }
                }
                if (-not [string]::IsNullOrWhiteSpace($Local:ErrorLogPath))
                {
                    $Message | Out-File -FilePath $Local:ErrorLogPath -Append
                }
                else
                {
                    if (Test-Path -Path variable:script:UnwrittenErrorLogEntries)
                    {
                        $Script:UnwrittenErrorLogEntries += $Message 
                    }
                    else
                    {
                        $Script:UnwrittenErrorLogEntries = @()
                        $Script:UnwrittenErrorLogEntries += $Message
                    }
                }
            }
        }
        #Pass on the message to Write-Verbose if -Verbose was detected
        Write-Verbose -Message $Message
    }
#end Function WriteLog
Function GetCommonParameter
    {
        [cmdletbinding(SupportsShouldProcess)]
        param()
        $MyInvocation.MyCommand.Parameters.Keys
    }
#end function Get-CommonParameter
function GetAllParametersWithAValue
    {
        [cmdletbinding()]
        param
        (
            $BoundParameters #$PSBoundParameters
            ,
            $AllParameters #$MyInvocation.MyCommand.Parameters
        )
        GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
        $AllKeys = @($AllParameters.Keys ; $BoundParameters.Keys)
        $AllKeys = @($AllKeys | Sort-Object -Unique)
        Write-Verbose -Message "$($allKeys.count) Parameter Keys Found: $($allKeys -join ';')"
        $AllKeys = @($AllKeys | Where-Object -FilterScript {$_ -notin @(GetCommonParameter)})
        $AllParametersWithAValue = @(
            foreach ($k in $AllKeys)
            {
                try
                {
                    Get-Variable -Name $k -ErrorAction Stop -Scope 1 | Where-Object -FilterScript {$null -ne $_.Value -and -not [string]::IsNullOrWhiteSpace($_.Value)}
                    # -Scope $Scope
                }
                catch
                {
                    #don't care if a particular variable is not found
                    Write-Verbose -Message "$k was not found"
                }
            }
        )
        $AllParametersWithAValue
    }
#end function Get-AllParametersWithAValue
function GetArrayIndexForIdentity
    {
        [cmdletbinding()]
        param(
            [parameter(mandatory=$true)]
            $array #The array for which you want to find a value's index
            ,
            [parameter(mandatory=$true)]
            $value #The Value for which you want to find an index
            ,
            [parameter(Mandatory)]
            $property #The property name for the value for which you want to find an index
        )
        Write-Verbose -Message 'Using Property Match for Index'
        [array]::indexof(($array.$property).guid,$value)
    }
#end function GetArrayIndexForIdentity
function GetExchangePSSession
    {
        [CmdletBinding(DefaultParameterSetName = 'ExchangeOnline')]
        param
        (
            [parameter(Mandatory)]
            [pscredential]$Credential = $script:Credential
            ,
            [parameter(Mandatory,ParameterSetName = 'ExchangeOnline')]
            [switch]$ExchangeOnline
            ,
            [parameter(Mandatory,ParameterSetName = 'ExchangeOnPremises')]
            [string]$ExchangeServer
            ,
            [System.Management.Automation.Remoting.PSSessionOption]$PSSessionOption
        )
        $NewPsSessionParams = @{
            ErrorAction = 'Stop'
            ConfigurationName = 'Microsoft.Exchange'
            Credential = $Credential
        }
        switch ($PSCmdlet.ParameterSetName)
        {
            'ExchangeOnline'
            {
                $NewPsSessionParams.ConnectionURI = 'https://outlook.office365.com/powershell-liveid/'
                $NewPsSessionParams.Authentication = 'Basic'
            }
            'ExchangeOnPremises'
            {
                $NewPsSessionParams.ConnectionURI = 'http://' + $ExchangeServer + '/PowerShell/'
                $NewPsSessionParams.Authentication = 'Kerberos'
            }
        }
        $ExchangeSession = New-PSSession @NewPsSessionParams
        if ($PSCmdlet.ParameterSetName -eq 'ExchangeOnPremises')
        {
            Invoke-Command -Session $ExchangeSession -ScriptBlock {Set-ADServerSettings -ViewEntireForest $true -ErrorAction 'Stop'} -ErrorAction Stop
        }
        $ExchangeSession
    }
#end Function Get-ExchangePSSession
function GetGetExchangePSSessionParams
{
    $GetExchangePSSessionParams = @{
        ErrorAction = 'Stop'
        Credential = $script:Credential
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
        }
        'ExchangeOnPremises'
        {
            $GetExchangePSSessionParams.ExchangeServer = $script:ExchangeOnPremisesServer
        }
    }
    $GetExchangePSSessionParams
}
Function TestExchangePSSession
    {
        [CmdletBinding()]
        param
        (
            [System.Management.Automation.Runspaces.PSSession]$PSSession = $script:PSSession
        )
        switch ($PSSession.State -eq 'Opened')
        {
            $true
            {
                Try
                {
                    $TestCommandResult = invoke-command -Session $PSSession -ScriptBlock {Get-OrganizationConfig -ErrorAction Stop | Select-Object -ExpandProperty Identity | Select-Object -ExpandProperty Name} -ErrorAction Stop
                    $(-not [string]::IsNullOrEmpty($TestCommandResult))
                }
                Catch
                {
                    $false
                }
            }
            $false
            {
                $false
            }
        }
    }
#end Function TestExchangePSSession
Function RemoveExchangePSSession
    {
        [CmdletBinding()]
        param
        (
            [System.Management.Automation.Runspaces.PSSession]$PSSession = $script:PSSession
        )
        Remove-PSSession -Session $PsSession -ErrorAction SilentlyContinue
    }
#end Function RemoveExchangePSSession
function WriteUserInstructionError
{
    $message = "You must call the Connect-ExchangeOrganization function before calling any other cmdlets which require an active Exchange Organization connection."
    throw($message)
}