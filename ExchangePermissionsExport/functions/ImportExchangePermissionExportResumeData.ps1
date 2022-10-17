Function ImportExchangePermissionExportResumeData
{

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory)]
        $path
    )
    $ImportedExchangePermissionsExportResumeData = Import-Clixml -Path $path -ErrorAction Stop
    $parentpath = Split-Path -Path $path -Parent
    $ResumeIDFilePath = Join-Path -Path $parentpath -ChildPath $($ImportedExchangePermissionsExportResumeData.TimeStamp + 'ExchangePermissionExportResumeID.xml')
    $ResumeIDs = Import-Clixml -Path $ResumeIDFilePath -ErrorAction Stop
    $ImportedExchangePermissionsExportResumeData.ResumeID = $ResumeIDs.ResumeID
    $ImportedExchangePermissionsExportResumeData

}
