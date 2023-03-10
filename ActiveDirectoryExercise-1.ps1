#Gathering information in Active Directory
    #View AD Hieararchy
    get-adobject -Filter * |ft name,objectclass
    
    Get-ADObject -Filter {ObjectClass -eq "OrganizationalUnit"}
    
    Get-ADObject -SearchBase 'OU=CompanyOU,DC=Romlab,DC=internal' `
        -Filter {ObjectClass -eq "OrganizationalUnit"}|
        FT Name,DistinguishedName -AutoSize
    
    #Find Objects
    get-adobject -Filter * | gm
    
    get-adobject -Filter * -Properties * | gm # -properties * brings extended Properties
    
    Get-ADObject -Filter {(name -like '*romulus*') -and (ObjectClass -eq 'user')} -Properties *|
        ft Name,DistinguishedName
    
    #Finding specific user objects
    Get-ADObject `
        -Identity 'CN=Chris Romulus-Admin,OU=Users,OU=San Francisco,OU=CompanyOU,DC=romlab,DC=internal' `
        -Properties * | FL

    get-adobject -Filter {SamAccountName -eq 'cradmin'} -Properties * | FL

    #Add OU for Users and Computer under Austin
    New-ADOrganizationalUnit `
        -Name Users `
        -Path 'OU=San Francisco,OU=CompanyOU,DC=Romlab,DC=internal' `
        -Verbose
    
    New-ADOrganizationalUnit `
        -Name Computers `
        -Path 'OU=San Francisco,OU=CompanyOU,DC=E,DC=internal' `
        -Verbose
    
    Get-ADObject -SearchBase 'OU=CompanyOU,DC=romlab,DC=internal' `
        -Filter {ObjectClass -eq "OrganizationalUnit"}



#Get User Information
get-aduser -Filter * -Properties *| gm

get-ADUser -Filter * -Properties *| fl Name,DistinguishedName,City

Get-ADUser -SearchBase 'OU=CompanyOU,DC=Romlab,DC=internal'|
     ft Name,DistinguishedName -AutoSize

Get-ADUser -Filter {Name -like '*romulus*'}  -Properties * |
 ft Name,DistinguishedName -AutoSize

Get-aduser -Identity 'cradmin' -Properties *

#Find all users in Madison and in IT department; Export to CSV file 

get-aduser -Filter {(City -eq 'Albany') -and (department -eq 'IT')} -Properties *|
    select-object Name,City,Enabled,EmailAddress|
    export-csv -Path C:\demos\Demo5\AlbanyUsers.csv

notepad C:\demos\Demo5\AlbanyUsers.csv

#Create a New user with PowerShell
    $SetPass = read-host -assecurestring
    New-ADUser `
        -Server Server1 `
        -Path 'OU=Users,OU=San Francisco,OU=CompanyOU,DC=Romlab,DC=intenal' `
        -department IT `
        -SamAccountName JimJ `
        -Name Jimj `
        -Surname Jones `
        -GivenName Jim `
        -UserPrincipalName Jimj@wiredbrain.priv `
        -City San Francisco `
        -AccountPassword $setpass `
        -ChangePasswordAtLogon $True `
        -Enabled $False -Verbose 
    
    Get-ADUser -Identity 'Timj'

#Modify single user object
Set-ADuser -Identity 'jimJ' -Enabled $True -Description 'Tim is a demo User' -Title 'Demo User'
Get-ADUser -Identity 'jimj' -Properties *| FL Name,Description,Title,Enabled

#Modify Existing users without state of Wisconsin
Get-ADUser  `
    -filter { ( State -eq $null) } `
    -SearchBase 'OU=CompanyOU,DC=Romlab,DC=internal' -SearchScope Subtree|
    ft Name,SamAccountName,City

Get-ADUser  `
    -filter { -not( State -like '*') } `
    -SearchBase 'OU=CompanyOU,DC=Romlab,DC=internal' -SearchScope Subtree -Properties *|
    ft Name,SamAccountName,State

Get-ADUser  `
    -filter { -not( City -like '*') } `
    -SearchBase 'OU=CompanyOU,DC=Romlab,DC=internal' -SearchScope Subtree|
    Set-ADUser -State 'WI' -Verbose

get-aduser -Filter {State -eq 'NY'} -Properties *|
        ft name,SamAccountName,State

#Find users that are disabled
    get-aduser -Filter {enabled -eq $false} `
        -SearchBase 'OU=Users,OU=Albany,OU=CompanyOU,DC=Romlab,DC=internal'|
        ft Name,SamAccountName,Enabled -AutoSize

    get-aduser -Filter {enabled -eq $false} `
        -SearchBase 'OU=Users,OU=Albany,OU=CompanyOU,DC=Romlab,DC=internal'|
        Set-ADUser -Enabled $true

    get-aduser -Filter * `
        -SearchBase 'OU=Users,OU=Albany,OU=CompanyOU,DC=Romlab,DC=internal'|
        ft Name,SamAccountName,Enabled -AutoSize

#Determine status of LockedOut Account
    Search-ADAccount -LockedOut | select Name  
        
    Unlock-ADAccount -Identity 'crtest'

#Reset Password
    $newPassword = (Read-Host -Prompt "Provide New Password" -AsSecureString)

    Set-ADAccountPassword -Identity crtest -NewPassword $newPassword -Reset

    Set-ADuser -Identity crtest -ChangePasswordAtLogon $True

#endregion Demo3

#region Demo4 - Computers

#Find all computers in domain
Get-ADComputer -Filter * -Properties * |ft Name,DNSHostName,OperatingSystem

Get-adcomputer -Filter {OperatingSystem -eq 'Windows 10 Enterprise Evaluation'} -Properties *|
    ft Name,DNSHostName,OperatingSystem

#View information for server1
Get-ADComputer -Identity 'Server1' -Properties *

#Modify Description on Computer 
Set-ADComputer -Identity 'Server1' -Description 'This is a Server for App/Dev Testing' -PassThru|
    Get-ADComputer -Properties * | ft Name,DNSHostName,Description

#Move computer to OU
Get-ADComputer -Identity Server2 |
    Move-ADObject -TargetPath 'OU=Computers,OU=San Francisco,OU=CompanyOU,DC=Romlab,DC=internal'

Get-ADComputer -Identity Server1 -Properties * | FT Name,DistinguishedName



#View all Groups
Get-ADGroup -Filter * -Properties *| FT Name,Description -AutoSize -Wrap

#View Specific Group
get-adgroup -Identity 'Domain Users' -Properties *

#create a new group for IT users
New-ADGroup `
    -Name 'IT Users' `
    -GroupCategory Security `
    -GroupScope Global

Set-ADGroup -Identity 'IT Users' -Description 'This is a group for IT Users'

get-adgroup -Identity 'IT Users' -Properties * | fl Name,Description

#View Group Membership of Group
Get-ADGroupMember -Identity 'Domain Users'|ft Name

#Add Users to Group for IT
Get-ADGroupMember -Identity 'IT Users'

Add-ADGroupMember `
    -Identity 'IT Users' `
    -Members (get-aduser -Filter {department -eq 'IT'})

Get-ADGroupMember -Identity 'IT Users'|ft Name

#Remove IT Users Group
Remove-ADGroup -Identity 'IT Users'
