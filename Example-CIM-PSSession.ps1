$cimsession = New-CimSession -Credential (get-credential) -ComputerName 192.168.215.100

#get IP Configuration on Remote Machine
Get-NetIPConfiguration -CimSession $cimsession

#set IP Configuration on remote system
New-netIPAddress `
-CimSession $cimsession `
-IPAddress 192.168.215.40 `
-PrefixLength 24 `
-DefaultGateway 192.168.215.2 `
-InterfaceIndex 12

Get-NetIPConfiguration -CimSession $cimsession

#Reconnect

$cimsession = New-CimSession -Credential (get-credential) -ComputerName 192.168.215.40

Get-NetIPConfiguration -CimSession $cimsession

Set-DnsClientServerAddress `
-CimSession $cimsession `
-InterfaceIndex 12 `
-ServerAddresses 192.168.215.20

#Rename Server to Server1
Enter-PSSession -ComputerName 192.168.215.40 -Credential (get-credential)
    #Rename-Computer -NewName Server2
    #Set Time Zone
    #Tzutilexe /?
    #Tzutilexe /g
    #Tzutil.exe /s "Eastern Standard Time"
    #Restart-computer 

#Domain Join Server2
$cred = Get-Credential
Invoke-command `
-ComputerName 192.168.215.40 `
-Credential (Get-Credential) `
-scriptblock {Add-Computer -DomainName romlab.internal -credential $using:cred -Restart}

#Re-Set Trusted Hosts

Get-Item WSMan:\localhost\Client\TrustedHosts

Set-item WSMAN:\Localhost\Client\TrustedHosts -value ''

##Remote to Computer
help Enter-PSSession 

Help Enter-PSSession -Examples

Enter-PSSession -ComputerName Localhost

Enable-PSRemoting

Enter-PSSession -ComputerName Localhost