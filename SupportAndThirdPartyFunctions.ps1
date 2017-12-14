function Get-CallerPreference
{
    <#
    .Synopsis
    Fetches "Preference" variable values from the caller's scope.
    .DESCRIPTION
    Script module functions do not automatically inherit their caller's variables, but they can be
    obtained through the $PSCmdlet variable in Advanced Functions.  This function is a helper function
    for any script module Advanced Function; by passing in the values of $ExecutionContext.SessionState
    and $PSCmdlet, Get-CallerPreference will set the caller's preference variables locally.
    .PARAMETER Cmdlet
    The $PSCmdlet object from a script module Advanced Function.
    .PARAMETER SessionState
    The $ExecutionContext.SessionState object from a script module Advanced Function.  This is how the
    Get-CallerPreference function sets variables in its callers' scope, even if that caller is in a different
    script module.
    .PARAMETER Name
    Optional array of parameter names to retrieve from the caller's scope.  Default is to retrieve all
    Preference variables as defined in the about_Preference_Variables help file (as of PowerShell 4.0)
    This parameter may also specify names of variables that are not in the about_Preference_Variables
    help file, and the function will retrieve and set those as well.
    .EXAMPLE
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    Imports the default PowerShell preference variables from the caller into the local scope.
    .EXAMPLE
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name 'ErrorActionPreference','SomeOtherVariable'

    Imports only the ErrorActionPreference and SomeOtherVariable variables into the local scope.
    .EXAMPLE
    'ErrorActionPreference','SomeOtherVariable' | Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    Same as Example 2, but sends variable names to the Name parameter via pipeline input.
    .INPUTS
    String
    .OUTPUTS
    None.  This function does not produce pipeline output.
    .LINK
    about_Preference_Variables
    #>
    #https://gallery.technet.microsoft.com/scriptcenter/Inherit-Preference-82343b9d
    [CmdletBinding(DefaultParameterSetName = 'AllVariables')]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({ $_.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
        $Cmdlet,

        [Parameter(Mandatory)]
        [Management.Automation.SessionState]
        $SessionState,

        [Parameter(ParameterSetName = 'Filtered', ValueFromPipeline)]
        [string[]]
        $Name
    )
    begin
    {
        $filterHash = @{}
    }
    process
    {
        if ($null -ne $Name)
        {
            foreach ($string in $Name)
            {
                $filterHash[$string] = $true
            }
        }
    }
    end
    {
        # List of preference variables taken from the about_Preference_Variables help file in PowerShell version 4.0
        $vars = @{
            'ErrorView' = $null
            'FormatEnumerationLimit' = $null
            'LogCommandHealthEvent' = $null
            'LogCommandLifecycleEvent' = $null
            'LogEngineHealthEvent' = $null
            'LogEngineLifecycleEvent' = $null
            'LogProviderHealthEvent' = $null
            'LogProviderLifecycleEvent' = $null
            'MaximumAliasCount' = $null
            'MaximumDriveCount' = $null
            'MaximumErrorCount' = $null
            'MaximumFunctionCount' = $null
            'MaximumHistoryCount' = $null
            'MaximumVariableCount' = $null
            'OFS' = $null
            'OutputEncoding' = $null
            'ProgressPreference' = $null
            'PSDefaultParameterValues' = $null
            'PSEmailServer' = $null
            'PSModuleAutoLoadingPreference' = $null
            'PSSessionApplicationName' = $null
            'PSSessionConfigurationName' = $null
            'PSSessionOption' = $null
            'ErrorActionPreference' = 'ErrorAction'
            'DebugPreference' = 'Debug'
            'ConfirmPreference' = 'Confirm'
            'WhatIfPreference' = 'WhatIf'
            'VerbosePreference' = 'Verbose'
            'WarningPreference' = 'WarningAction'
        }
        foreach ($entry in $vars.GetEnumerator())
        {
            if (([string]::IsNullOrEmpty($entry.Value) -or -not $Cmdlet.MyInvocation.BoundParameters.ContainsKey($entry.Value)) -and
                ($PSCmdlet.ParameterSetName -eq 'AllVariables' -or $filterHash.ContainsKey($entry.Name)))
            {
                $variable = $Cmdlet.SessionState.PSVariable.Get($entry.Key)
                
                if ($null -ne $variable)
                {
                    if ($SessionState -eq $ExecutionContext.SessionState)
                    {
                        Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -Confirm:$false -WhatIf:$false
                    }
                    else
                    {
                        $SessionState.PSVariable.Set($variable.Name, $variable.Value)
                    }
                }
            }
        }
        if ($PSCmdlet.ParameterSetName -eq 'Filtered')
        {
            foreach ($varName in $filterHash.Keys)
            {
                if (-not $vars.ContainsKey($varName))
                {
                    $variable = $Cmdlet.SessionState.PSVariable.Get($varName)
                
                    if ($null -ne $variable)
                    {
                        if ($SessionState -eq $ExecutionContext.SessionState)
                        {
                            Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -Confirm:$false -WhatIf:$false
                        }
                        else
                        {
                            $SessionState.PSVariable.Set($variable.Name, $variable.Value)
                        }
                    }
                }
            }
        }
    } # end
}
#end function Get-CallerPreference
function Test-IsWriteableDirectory
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
#end function Test-IsWriteableDirectory
Function Write-Log
{
    [cmdletbinding()]
    Param(
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
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
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
            Write-Output -InputObject $Message | Out-File -FilePath $Local:LogPath -Append
        }
        else
        {
            Write-Error -Message 'No LogPath has been provided. Writing Log Entry to script module variable UnwrittenLogEntries' -ErrorAction SilentlyContinue
            if (Test-Path -Path variable:script:UnwrittenLogEntries)
            {
                $Script:UnwrittenLogEntries += Write-Output -InputObject $Message
            }
            else
            {
                $Script:UnwrittenLogEntries = @()
                $Script:UnwrittenLogEntries += Write-Output -InputObject $Message
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
                Write-Output -InputObject $Message | Out-File -FilePath $Local:ErrorLogPath -Append
            }
            else
            {
                if (Test-Path -Path variable:script:UnwrittenErrorLogEntries)
                {
                    $Script:UnwrittenErrorLogEntries += Write-Output -InputObject $Message 
                }
                else
                {
                    $Script:UnwrittenErrorLogEntries = @()
                    $Script:UnwrittenErrorLogEntries += Write-Output -InputObject $Message
                }
            }
        }
    }
    #Pass on the message to Write-Verbose if -Verbose was detected
    Write-Verbose -Message $Message
}
#end Function Write-Log
Function Get-SendASRightGUID
{
    #ADSI Adapter: http://social.technet.microsoft.com/wiki/contents/articles/4231.working-with-active-directory-using-powershell-adsi-adapter.aspx
        $dse = [ADSI]"LDAP://Rootdse"
        $ext = [ADSI]("LDAP://CN=Extended-Rights," + $dse.ConfigurationNamingContext)
        $dn = [ADSI]"LDAP://$($dse.DefaultNamingContext)"
        $dsLookFor = New-Object System.DirectoryServices.DirectorySearcher($dn)
        $permission = "Send As"
        $right = $ext.psbase.Children | Where-Object { $_.DisplayName -eq $permission }

        #commented out the above since the GUID for this right seems to be well-known. the below is the GUID is extracted from the above object if you want to revert.

        [GUID]$right.RightsGuid.Value
}