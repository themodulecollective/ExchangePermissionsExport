Function TestExchangePSSession
{
    [outputtype([bool])]
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
                $TestCommandResult = Invoke-Command -Session $PSSession -ScriptBlock { Get-OrganizationConfig -ErrorAction Stop | Select-Object -ExpandProperty Identity | Select-Object -ExpandProperty Name } -ErrorAction Stop
                $(-not [string]::IsNullOrWhiteSpace($TestCommandResult))
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
