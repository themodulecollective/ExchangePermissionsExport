#developing
function Get-ForwardingMailbox
{}

function Get-CalendarPermission
    {
        $CalendarPermission = Get-MailboxFolderPermission -Identity ($Mailbox.alias + ':\Calendar') -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | ?{$_.User -notlike "Anonymous" -and $_.User -notlike "Default"} | Select User, AccessRights
        if (!$CalendarPermission){
            $Calendar = (($Mailbox.PrimarySmtpAddress.ToString())+ ":\" + (Get-MailboxFolderStatistics -Identity $Mailbox.DistinguishedName -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | where-object {$_.FolderType -eq "Calendar"} | Select-Object -First 1).Name)
            $CalendarPermission = Get-MailboxFolderPermission -Identity $Calendar -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | ?{$_.User -notlike "Anonymous" -and $_.User -notlike "Default"} | Select User, AccessRights
        }
    }
#end Get-CalendarPermission