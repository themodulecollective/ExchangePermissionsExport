Function Get-SendASRightGUID
{
    
    #not necessary because the guid is well known but here so you can see how to find it if necessary.
    #ADSI Adapter: http://social.technet.microsoft.com/wiki/contents/articles/4231.working-with-active-directory-using-powershell-adsi-adapter.aspx
    $dse = [ADSI]"LDAP://Rootdse"
    $ext = [ADSI]("LDAP://CN=Extended-Rights," + $dse.ConfigurationNamingContext)
    $dn = [ADSI]"LDAP://$($dse.DefaultNamingContext)"
    $permission = "Send As"
    $right = $ext.psbase.Children | Where-Object { $_.DisplayName -eq $permission }
    [GUID]$right.RightsGuid.Value

}

