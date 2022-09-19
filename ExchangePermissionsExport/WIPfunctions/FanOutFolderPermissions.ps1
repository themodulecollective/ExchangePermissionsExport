<#
The purpose of this script is to run an Exchange Permissions Export operation for all mailbox folder level permissions in an on premises organization.
Performance may be better running the folder permission operation from the server where the mailbox is currently hosted.
The script first retrieves all mailboxes for the organization and then groups them by servername to create a job per server.
Each job runs a remote session on the designated server.
The ServerGroups can also be exported (using export-clixml) and then copied to another server if there are sufficient exchange servers in the environment where not all jobs can be run in parallel from one server.
A future version of this script might use a queuing method to address the above issue.
#>
param(
    $InitialExchangeServer
    ,
    $OutputFolderPath
    ,
    [pscredential]$Credential
)

Import-Module ExchangePermissionsExport
Connect-ExchangeOrganization -ExchangeOrgType ExchangeOnPremises -ExchangeOnPremisesServer $InitialExchangeServer
$AllMailboxes =
@(Invoke-Command -Session $Script:PSSession -ErrorAction Stop -ScriptBlock {
        Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
    } ) | Select-Object -Property ExchangeGuid,ServerName,Database

$ServerGroups = $AllMailboxes | Group-Object -Property ServerName

foreach ($sg in $ServerGroups)
{

    $JobExchangeOnPremisesServer = $sg.Name
    $JobMailboxIdentities = $sg.Group.exchangeguid.guid
    $JobExchangeOrgType = 'ExchangeOnPremises'

    Start-Job -ScriptBlock {
        Import-Module ActiveDirectory
        $ad = Get-PSDrive -PSProvider ActiveDirectory
        Import-Module ExchangePermissionsExport
        $ceoParams = @{
            ExchangeOrgType          = $using:JobExchangeOrgType
            ExchangeOnPremisesServer = $using:JobExchangeOnPremisesServer
            Credential               = $using:Credential
        }
        Connect-ExchangeOrganization @ceoParams

        $eepParams = @{
            outputFolderPath     = $using:OutputFolderPath
            Identity             = $using:JobMailboxIdentities
            IncludeSendOnBehalf  = $false
            IncludeFullAccess    = $false
            IncludeSendAs        = $false
            IncludeCalendar      = $false
            expandGroups         = $true
            IncludeAllFolder     = $true
            ActiveDirectoryDrive = $ad
        }
        Export-ExchangePermission @eepParams
    } -Name $JobExchangeOnPremisesServer
}
