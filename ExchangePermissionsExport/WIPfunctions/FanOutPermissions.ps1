param(
    $InitialExchangeServer
    ,
    $OutputFolderPath
)

Import-Module ExchangePermissionsExport
Connect-ExchangeOrganization -ExchangeOrgType ExchangeOnPremises -ExchangeOnPremisesServer $InitialExchangeServer
$AllMailboxes =
@(Invoke-Command -Session $Script:PSSession -ErrorAction Stop -ScriptBlock {
        Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
    } )

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
        Connect-ExchangeOrganization -ExchangeOrgType $using:JobExchangeOrgType -ExchangeOnPremisesServer $using:JobExchangeOnPremisesServer
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
        Export-Exchange @eepParams
    } -Name $JobExchangeOnPremisesServer
}
