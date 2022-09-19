Function GetCommonParameter
{

    [cmdletbinding(SupportsShouldProcess)]
    param()
    $MyInvocation.MyCommand.Parameters.Keys

}
