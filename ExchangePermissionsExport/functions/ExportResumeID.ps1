Function ExportResumeID
{

    [CmdletBinding()]
    param
    (
        $ID
        ,
        $nextPermissionID
        ,
        $outputFolderPath
        ,
        $TimeStamp
    )
    $ExportFilePath = Join-Path -Path $outputFolderPath -ChildPath $($TimeStamp + 'ExchangePermissionExportResumeID.xml')
    $Identities = @{
        NextPermissionIdentity = $nextPermissionID
        ResumeID               = $ID
    }
    Export-Clixml -Depth 1 -Path $ExportFilePath -InputObject $Identities -Encoding UTF8
    $ExportFilePath

}
