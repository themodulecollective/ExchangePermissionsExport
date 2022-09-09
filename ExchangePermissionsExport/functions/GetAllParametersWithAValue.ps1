Function GetAllParametersWithAValue
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
    $AllKeys = @($AllKeys | Where-Object -FilterScript { $_ -notin @(GetCommonParameter) })
    $AllParametersWithAValue = @(
        foreach ($k in $AllKeys)
        {
            try
            {
                Get-Variable -Name $k -ErrorAction Stop -Scope 1 | Where-Object -FilterScript { $null -ne $_.Value -and -not [string]::IsNullOrWhiteSpace($_.Value) }
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

