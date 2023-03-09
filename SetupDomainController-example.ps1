﻿ Rename-Computer -NewName Server1
 Restart-computer 
#endregion
#region - Set IP, Timezone, Install AD & DNS RUN ON Server1

    #Set IP Address
        New-netIPAddress -IPAddress 192.168.215.20 `
        -PrefixLength 24 `
        -DefaultGateway 192.168.215.2 `
        -InterfaceAlias Ethernet0
    #Set TimeZone
        Tzutil.exe /s "Eastern Standard Time"
    #Install AD & DNS
       #Install ADDS Role and Mgt Tools
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
       ##Import ADDSDeployment Module
        Import-Module ADDSDeployment
       ##Install a new AD Forest
        Install-ADDSForest `
	        -CreateDnsDelegation:$false `
	        -DatabasePath "C:\Windows\NTDS" `
	        -DomainMode "Win2012R2" `
	        -DomainName "romlab.internal" `
	        -DomainNetbiosName "romlab" `
	        -ForestMode "Win2012r2" `
	        -InstallDns:$true `
	        -LogPath "C:\Windows\NTDS" `
	        -NoRebootOnCompletion:$false `
	        -SysvolPath "C:\Windows\SYSVOL" `
	        -Force:$true

  #Set DNS Forwarder
        Set-DnsServerForwarder -IPAddress 4.2.2.1 -ComputerName Server1
    #Install DHCP
        install-windowsfeature -computerName Server1 -name DHCP -IncludeManagementTools
    
    #Complete Post Configuration
        #Create DHCP Groups
        netsh dhcp add securitygroups

        #Add Server into Active Directory
        Add-DhcpServerInDC -IPAddress 192.168.215.20 -DnsName Server1.romlab.internal
    
    #Create Initial Scope for 192.168.95.0 subnet
        Add-DhcpServerv4Scope -Name 'Production Scope' `
            -ComputerName Server1.romlab.internal `
            -StartRange 192.168.215.100 `
            -EndRange 192.168.215.200 `
            -SubnetMask 255.255.255.0 `
            -LeaseDuration 08:00:00
        
        set-DhcpServerv4OptionValue `
            -ScopeId 192.168.215.0 `
            -ComputerName Server1.romlab.internal `
            -DnsDomain romlab.internal `
            -router 192.168.215.2 `
            -DnsServer 192.168.215.20