#Daniel Owen
#2017-08-27
#Script to identify unauthorized accounts added to the Domain Admins group
cls
$allowed = Import-Csv 'C:\scripts\get-admins\allowed.csv' #Path to file containing SIDs of users allowed to be a member of Domain Admins
$group = "Domain Admins" #Group being protected
$members = Get-ADGroupMember $group #Get members of the group we are protecting

if ($allowed.count -eq 0) {exit} #Failsafe to kill the script if the text file does not contain any data or is not read for some reason.

ForEach ($m in $members) { #Create a loop to look at each member of the $group
    $account = $m.sid.ToString() #Create a string variable that holds the SID for the member of $group to be compared. This simplifies code later. 
    if ($allowed.sid -notcontains $account) { #Does the $allowed array contain the member of $goup currently being compared? If not take action.
        Disable-ADAccount -Identity $account #Disable the AD account that was added to $group but is not in the $allowed file. 
        Remove-ADGroupMember -Identity $group -Members $account -Confirm:$false #Remove $account from the $group.
        #This is a good place to send an email alert or write an alert to a console. 
        if ((Get-EventLog -LogName Application -Source "get-admins-script" -ErrorAction SilentlyContinue) -eq $null) { 
            New-EventLog -LogName Application -Source 'get-admins-script' #Create a new event log type in the Application log if it does not exist. 
        }
        Write-EventLog -LogName Application -Source 'get-admins-script' -EntryType Warning -EventId 0 `
        -Message "$account was removed from $group as part of the get-admins security process." #Write an event to the local systems Security Event Log. 
    }     
}
