Function WriteUserInstructionError
{
    
    $message = "You must call the Connect-ExchangeOrganization function before calling any other cmdlets which require an active Exchange Organization connection."
    throw($message)

}

