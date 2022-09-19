Function ExportExchangePermissionExportResumeData
{

    [CmdletBinding()]
    param
    (
        $ExchangePermissionsExportParameters
        ,
        $ExcludedRecipientGuidHash
        ,
        $ExcludedTrusteeGuidHash
        ,
        $SIDHistoryRecipientHash
        ,
        $InScopeRecipients
        ,
        $ObjectGUIDHash
        ,
        $outputFolderPath
        ,
        $ExportedExchangePermissionsFile
        ,
        $TimeStamp
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    $ExchangePermissionExportResumeData = @{
        ExchangePermissionsExportParameters = $ExchangePermissionsExportParameters
        ExcludedRecipientGuidHash           = $ExcludedRecipientGuidHash
        ExcludedTrusteeGuidHash             = $ExcludedTrusteeGuidHash
        SIDHistoryRecipientHash             = $SIDHistoryRecipientHash
        InScopeRecipients                   = $InScopeRecipients
        ObjectGUIDHash                      = $ObjectGUIDHash
        ExportedExchangePermissionsFile     = $ExportedExchangePermissionsFile
        TimeStamp                           = $TimeStamp
    }
    $ExportFilePath = Join-Path -Path $outputFolderPath -ChildPath $($TimeStamp + 'ExchangePermissionExportResumeData.xml')
    Export-Clixml -Depth 2 -Path $ExportFilePath -InputObject $ExchangePermissionExportResumeData -Encoding UTF8
    $ExportFilePath

}
