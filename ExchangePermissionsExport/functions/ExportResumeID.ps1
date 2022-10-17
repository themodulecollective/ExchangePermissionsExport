Function ExportResumeID
{

    [CmdletBinding()]
    param
    (
        $ID
        ,
        $outputFolderPath
        ,
        $TimeStamp
    )
    $ExportFilePath = Join-Path -Path $outputFolderPath -ChildPath $($TimeStamp + 'ExchangePermissionExportResumeID.xml')
    $Identities = @{
        ResumeID = $ID
    }
    Export-Clixml -Depth 1 -Path $ExportFilePath -InputObject $Identities -Encoding UTF8
    $ExportFilePath

}
