
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName admin@yourdomain.com -ShowProgress $true

# Specify the user to remove from distribution lists
$UserToRemove = "usertoremove@iginnovate.com"

# Get all distribution lists
$DistributionLists = Get-DistributionGroup -ResultSize Unlimited

# Loop through each distribution list
foreach ($DL in $DistributionLists) {
    # Check if the user is a member of the distribution list
    $DLMembers = Get-DistributionGroupMember -Identity $DL.Identity | Where-Object { $_.PrimarySmtpAddress -eq $UserToRemove }
    if ($DLMembers) {
        # Remove the user from the distribution list
        Remove-DistributionGroupMember -Identity $DL.Identity -Member $UserToRemove -Confirm:$false
        Write-Host "User $UserToRemove removed from $($DL.DisplayName)" -ForegroundColor Green
    } else {
        Write-Host "User $UserToRemove is not a member of $($DL.DisplayName)" -ForegroundColor Yellow
    }
}
 