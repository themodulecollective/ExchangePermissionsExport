Function RemoveExchangePSSession
{
    
    [CmdletBinding()]
    param
    (
        [System.Management.Automation.Runspaces.PSSession]$PSSession = $script:PSSession
    )
    Remove-PSSession -Session $PsSession -ErrorAction SilentlyContinue

}

