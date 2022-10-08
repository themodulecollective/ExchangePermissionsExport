Function GetGroupMemberExpandedViaExchange
{

    [CmdletBinding()]
    param
    (
        [string]$Identity
        ,
        [System.Management.Automation.Runspaces.PSSession]$ExchangeSession
        ,
        $hrPropertySet
        ,
        $ObjectGUIDHash
        ,
        $DomainPrincipalHash
        ,
        $SIDHistoryRecipientHash
        ,
        $UnFoundIdentitiesHash
        ,
        [int]$iterationLimit = 100
    )
    GetCallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
    $splat = @{
        Identity    = $Identity
        ErrorAction = 'Stop'
    }
    Try
    {
        $BaseGroupMemberIdentities = @(Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-Group @using:splat | Select-Object -ExpandProperty Members })
    }
    Catch
    {
        $MyError = $_
        $BaseGroupMemberIdentities = @()
        WriteLog -Message $MyError.tostring() -EntryType Failed -ErrorLog -Verbose
    }
    Write-Verbose -Message "Got $($BaseGroupmemberIdentities.Count) Base Group Members for Group $Identity"
    $BaseGroupMembership = @(foreach ($m in $BaseGroupMemberIdentities) { GetTrusteeObject -TrusteeIdentity $m.objectguid.guid -HRPropertySet $hrPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -UnfoundIdentitiesHash $UnFoundIdentitiesHash })
    $iteration = 0
    $AllResolvedMembers = @(
        do
        {
            $iteration++
            $BaseGroupMembership | Where-Object -FilterScript { $_.RecipientTypeDetails -notlike '*group*' }
            $RemainingGroupMembers = @($BaseGroupMembership | Where-Object -FilterScript { $_.RecipientTypeDetails -like '*group*' })
            Write-Verbose -Message "Got $($RemainingGroupMembers.Count) Remaining Nested Group Members for Group $identity.  Iteration: $iteration"
            $BaseGroupMemberIdentities = @($RemainingGroupMembers | ForEach-Object { $splat = @{Identity = $_.guid.guid; ErrorAction = 'Stop' }; Invoke-Command -Session $ExchangeSession -ScriptBlock { Get-Group @using:splat | Select-Object -ExpandProperty Members } })
            $BaseGroupMembership = @(foreach ($m in $BaseGroupMemberIdentities) { GetTrusteeObject -TrusteeIdentity $m.objectguid.guid -HRPropertySet $hrPropertySet -ObjectGUIDHash $ObjectGUIDHash -DomainPrincipalHash $DomainPrincipalHash -SIDHistoryHash $SIDHistoryRecipientHash -ExchangeSession $ExchangeSession -UnfoundIdentitiesHash $UnFoundIdentitiesHash })
            Write-Verbose -Message "Got $($baseGroupMembership.count) Newly Explanded Group Members for Group $identity"
        }
        until ($BaseGroupMembership.count -eq 0 -or $iteration -ge $iterationLimit)
    )
    $AllResolvedMembers

}
