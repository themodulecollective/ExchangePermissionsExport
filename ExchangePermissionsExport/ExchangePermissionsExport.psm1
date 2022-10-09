###################################################################
#Exchange Permissions Export Module
###################################################################
###################################################################
#Import Functions
###################################################################

$ModuleFolder = Split-Path $PSCommandPath -Parent

$Scripts = Join-Path -Path $ModuleFolder -ChildPath 'scripts'
$Functions = Join-Path -Path $ModuleFolder -ChildPath 'functions'

#Write-Information -MessageData "Scripts Path  = $Scripts" -InformationAction Continue
#Write-Information -MessageData "Functions Path  = $Functions" -InformationAction Continue

$Script:ModuleFiles = @(
    $(Join-Path -Path $Scripts -ChildPath 'Initialize.ps1')

    # Load Functions
    $(Join-Path -Path $functions -ChildPath Connect-ExchangeOrganization.ps1)
    $(Join-Path -Path $functions -ChildPath ExpandGroupPermission.ps1)
    $(Join-Path -Path $functions -ChildPath Export-ExchangePermission.ps1)
    $(Join-Path -Path $functions -ChildPath ExportExchangePermissionExportResumeData.ps1)
    $(Join-Path -Path $functions -ChildPath ExportResumeID.ps1)
    $(Join-Path -Path $functions -ChildPath Get-SendASRightGUID.ps1)
    $(Join-Path -Path $functions -ChildPath GetAllParametersWithAValue.ps1)
    $(Join-Path -Path $functions -ChildPath GetArrayIndexForIdentity.ps1)
    $(Join-Path -Path $functions -ChildPath GetCalendarPermission.ps1)
    $(Join-Path -Path $functions -ChildPath GetFolderPermission.ps1)
    $(Join-Path -Path $functions -ChildPath GetAllFolderPermission.ps1)
    $(Join-Path -Path $functions -ChildPath GetCallerPreference.ps1)
    $(Join-Path -Path $functions -ChildPath GetCommonParameter.ps1)
    $(Join-Path -Path $functions -ChildPath GetExchangePSSession.ps1)
    $(Join-Path -Path $functions -ChildPath GetFullAccessPermission.ps1)
    $(Join-Path -Path $functions -ChildPath GetGetExchangePSSessionParams.ps1)
    $(Join-Path -Path $functions -ChildPath GetGroupMemberExpandedViaExchange.ps1)
    $(Join-Path -Path $functions -ChildPath GetGroupMemberExpandedViaLocalLDAP.ps1)
    $(Join-Path -Path $functions -ChildPath GetGuidFromByteArray.ps1)
    $(Join-Path -Path $functions -ChildPath GetSendASPermissionsViaExchange.ps1)
    $(Join-Path -Path $functions -ChildPath GetSendASPermisssionsViaLocalLDAP.ps1)
    $(Join-Path -Path $functions -ChildPath GetSendOnBehalfPermission.ps1)
    $(Join-Path -Path $functions -ChildPath GetSIDHistoryRecipientHash.ps1)
    $(Join-Path -Path $functions -ChildPath GetAutoMappingHash.ps1)
    $(Join-Path -Path $functions -ChildPath GetTrusteeObject.ps1)
    $(Join-Path -Path $functions -ChildPath ImportExchangePermissionExportResumeData.ps1)
    $(Join-Path -Path $functions -ChildPath NewPermissionExportObject.ps1)
    $(Join-Path -Path $functions -ChildPath RemoveExchangePSSession.ps1)
    $(Join-Path -Path $functions -ChildPath TestExchangePSSession.ps1)
    $(Join-Path -Path $functions -ChildPath TestIsWriteableDirectory.ps1)
    $(Join-Path -Path $functions -ChildPath WriteLog.ps1)
    $(Join-Path -Path $functions -ChildPath WriteUserInstructionError.ps1)

    # Finalize / Run any Module Functions defined above
    $(Join-Path -Path $Scripts -ChildPath 'RunFunctions.ps1')
)
foreach ($f in $ModuleFiles)
{
    . $f
}