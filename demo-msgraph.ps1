
#region Create resource group

$resourceGroupName_UAMI = "demo-gha-rg"
$location = "northeurope"

az group create -n $resourceGroupName -l $location

#endregion


#region Assign Microsoft Graph permissions to the user-assigned managed identity 

# Create a user-assigned managed identity

Install-Module -Name Az.ManagedServiceIdentity -AllowPrerelease
New-AzUserAssignedIdentity -Name uami-demo-gha -ResourceGroupName $resourceGroupName_UAMI -Location $location

$uami_principalId = (Get-AzUserAssignedIdentity -ResourceGroupName $resourceGroupName_UAMI -Name uami-demo-gha).PrincipalId
$appId = (Get-AzADServicePrincipal -ObjectId $uami_principalId).AppId
$GraphSP = Get-AzAdServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'"

$PermissionName = 'User.Read.All'
$AppRole = $GraphSP.AppRole | Where-Object {$_.Value -eq $PermissionName}

# Existing service principal used to authenticate to Microsoft Graph
# Required scope "AppRoleAssignment.ReadWrite.All" is already assigned to the service principal
$sp = Get-AzADServicePrincipal -DisplayName MSGirafa

Get-SecretInfo -Vault MySecretStore | Format-Table *
$ClientSecret = Get-Secret MSGirafa_ClientSecret

$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $sp.AppId, $ClientSecret

Connect-MgGraph -TenantId $sp.AppOwnerOrganizationId -ClientSecretCredential $cred
Get-MgContext

New-MgServicePrincipalAppRoleAssignment -AppRoleId $AppRole.Id -ServicePrincipalId $uami_principalId -ResourceId $GraphSP.Id -PrincipalId $uami_principalId

#endregion


#region Configure a user-assigned managed identity to trust an external identity provider (GitHub)

$resourceGroupName_UAMI = "demo-gha-rg"

New-AzFederatedIdentityCredentials -Name fic-demo-gha -IdentityName uami-demo-gha -ResourceGroupName $resourceGroupName_UAMI -Issuer "https://token.actions.githubusercontent.com" -Subject "repo:alexandair/demo-gha:ref:refs/heads/main" -Audience "api://AzureADTokenExchange"

<#
Name         Issuer                                      Subject                                      Audience
----         ------                                      -------                                      --------
fic-demo-gha https://token.actions.githubusercontent.com repo:alexandair/demo-gha:ref:refs/heads/main {api://AzureADTokenExchange}
#>

Get-AzFederatedIdentityCredentials -IdentityName uami-demo-gha -ResourceGroupName $resourceGroupName_UAMI | fl * 

$uami_clientId = (Get-AzUserAssignedIdentity -ResourceGroupName $resourceGroupName_UAMI -Name uami-demo-gha).ClientId

cd c:\gh\demo-gha
gh secret set AZURE_UAMI_CLIENT_ID --body $uami_clientId

#endregion


#region Migration (kind of)

Get-Command -Module PSAzureMigrationAdvisor
Convert-AzScriptFile
Export-AzScriptReport
Read-AzScriptFile
Update-AzADMapping

cd C:\gh\espc23-msgraphps
dir .\Get-AzureADGraphApps.ps1 | Read-AzScriptFile
Convert-AzScriptFile -path .\Get-AzureADGraphApps.ps1 -OutPath ./convertedScripts
code --diff .\Get-AzureADGraphApps.ps1 .\convertedScripts\Get-AzureADGraphApps.ps1

#endregion


#region Let's start with a GUI. Blasphemy!
# Graph Explorer
Start-Process 'https://aka.ms/ge'

# Access token tab
# Modify permissions tab
# Code snippets tab

# be aware all permissions are delegated permissions
# ATM, you cannot use the Graph Explorer to test application permissions

#endregion

#region Discovering Microsoft Graph PowerShell commands
Get-Command -Module Microsoft.Graph.Authentication |
    Sort-Object noun |
    Format-Table -GroupBy noun

# Find Microsoft Graph PowerShell commands using a command wildcard
Find-MgGraphCommand -Command *MgUser* -ApiVersion 'v1.0'
Find-MgGraphCommand -Command .*MgUser.* -ApiVersion 'v1.0'

Find-MgGraphCommand -Uri /groups -Method GET -ApiVersion 'v1.0' | Select-Object -ExpandProperty Permissions
# Permissions (from least to most privileged)
Start-Process 'https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http#permissions'

# Surprise!
# Get-Help Find-MgGraphPermission -Online
Get-Help Find-MgGraphPermission -Full
Start-Process https://docs.microsoft.com/graph/permissions-reference
# Microsoft Graph Permission Explorer
Start-Process https://graphpermissions.merill.net/

Find-MgGraphPermission -All | Measure-Object
# All:         514
# Application: 222
# Delegated:   292

Get-Help Find-MgGraphPermission -Parameter Online
# Connect-MgGraph
Find-MgGraphPermission -Online
Find-MgGraphPermission -All | Measure-Object
# All:         825
# Application: 384
# Delegated:   441

#endregion

#region Oh, it's full of IDs!

<#
Retrieve a list of oAuth2PermissionGrant entities, which represent delegated permissions granted to enable a client application to access an API on behalf of the user.

Note: Querying the delegated permission grants for a user will only return delegated permissions grants that are specifically for the given user. Delegated permissions granted on behalf of all users in the organization are not included in the response.
#>

$Diego = Get-MgUser -UserId diegos@yourdomain.onmicrosoft.com
Get-MgUserOauth2PermissionGrant -UserId $Diego.Id -ov userScopes

$userScopes | Format-List

$Diego.Id -eq $userScopes[0].PrincipalId

# Need to find out the client

$userScopes.ClientId | ForEach-Object { Get-MgServicePrincipal -ServicePrincipalId $_ }

Get-MgUserOauth2PermissionGrant -UserId $Diego.Id |
    ForEach-Object -Begin { $user = Get-MgUser -UserId $Diego.Id } {
        $ht = [ordered]@{
            DisplayName       = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            ClientId          = $_.ClientId
            ClientDisplayName = (Get-MgServicePrincipal -ServicePrincipalId $_.ClientId).DisplayName
            Scope             = $_.Scope
        }
        [PSCustomObject]$ht
    }


# List all delegated permissions
Get-MgOauth2PermissionGrant | Format-List

# Map IDs to their display names
$ClientDisplayName = @{n = 'ClientDisplayName'; e = { (Get-MgServicePrincipal -ServicePrincipalId $_.ClientId).DisplayName } }
$PrincipalDisplayName = @{n = 'PrincipalDisplayName'; e = { if ($_.PrincipalId) { (Get-MgUser -UserId $_.PrincipalId).DisplayName } else { 'All users' } } }
$ResourceDisplayName = @{n = 'ResourceDisplayName'; e = { (Get-MgServicePrincipal -ServicePrincipalId $_.ResourceId).DisplayName } }

Get-MgOauth2PermissionGrant |
    Select-Object *, $ClientDisplayName, $PrincipalDisplayName, $ResourceDisplayName -First 3

Get-MgOauth2PermissionGrant |
    Select-Object *, $ClientDisplayName, $PrincipalDisplayName, $ResourceDisplayName |
    Where-Object { $_.PrincipalDisplayName -eq 'Diego Siciliani' }

Get-MgOauth2PermissionGrant |
    Select-Object *, $ClientDisplayName, $PrincipalDisplayName, $ResourceDisplayName |
    Where-Object { $_.PrincipalDisplayName -eq 'All Users' }

Get-MgOauth2PermissionGrant |
    Select-Object *, $ClientDisplayName, $PrincipalDisplayName, $ResourceDisplayName |
    Sort-Object ClientDisplayName |
    Format-Table ClientDisplayName, PrincipalDisplayName, ResourceDisplayName, Scope -GroupBy ClientDisplayName

#endregion

#region How to get app roles' names that are assigned to a service principal

$sp = Get-MgServicePrincipal -Filter "displayName eq 'TrainingApp'"

# App roles assigned to the service principal; only AppRoleId is returned. We don't know the name of the app role.
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id | Format-List

Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -pv assignments | ForEach-Object {
    Get-MgServicePrincipal -Filter "displayName eq '$($_.ResourceDisplayName)'" |
        Select-Object -ExpandProperty AppRoles |
        Where-Object { $_.Id -eq $assignments.AppRoleId }
    }

#endregion

#region Get users including their last sign-in time
<#
Details for the signInActivity property require an Azure AD Premium P1/P2 license and the AuditLog.Read.All permission.

Note: When you specify $select=signInActivity or $filter=signInActivity while listing users, the maximum page size for $top is 120. Requests with $top set higher than 120 will return pages with up to 120 users. signInActivity supports $filter (eq, ne, not, ge, le) but not with any other filterable properties.
#>
    Get-MgUser -Property 'displayName,userPrincipalName,signInActivity' 
    Get-MgUser -Property displayName, userPrincipalName, signInActivity
    # Where is signinActivity?
    Get-MgUser -Property displayName, userPrincipalName, signInActivity | Get-Member 
    Get-MgUser -Property displayName,userPrincipalName,signInActivity | Where-Object UserPrincipalName -eq 'aleksandar@yourdomain.onmicrosoft.com' -ov user
    $user.signInActivity
    
    $user.ToJsonString()
    $user.ToJsonString() | ConvertFrom-Json | fl

    Get-MgUser -Property displayName, userPrincipalName, signInActivity |
        ForEach-Object { $_.ToJsonString() | ConvertFrom-Json } | Format-List

#endregion

#region AssignedPlans

$user = get-azureaduser -ObjectId aleksandar@yourdomain.onmicrosoft.com
$user | Format-List objectid, displayname, assignedplans
<#
ObjectId      : XXXXXXXX-acf1-419b-b06d-f44abb945bde
DisplayName   : Aleksandar Nikolic
AssignedPlans : {class AssignedPlan {
                  AssignedTimestamp: 4/7/2022 9:23:53 PM
                  CapabilityStatus: Enabled
                  Service: ProcessSimple
                  ServicePlanId: AAAAAAAA-e9ae-43fc-93c2-20783f0840c3
                }
                , class AssignedPlan {
                  AssignedTimestamp: 4/7/2022 9:23:53 PM
                  CapabilityStatus: Enabled
                  Service: PowerAppsService
                  ServicePlanId: BBBBBBBB-357e-4acb-9c21-8495fb025d1f
                }
                , class AssignedPlan {
                  AssignedTimestamp: 4/7/2022 9:23:53 PM
                  CapabilityStatus: Enabled
                  Service: LearningAppServiceInTeams
                  ServicePlanId: CCCCCCCC-6ba6-402a-b9f9-83d28acb3d86
                }
                , class AssignedPlan {
                  AssignedTimestamp: 10/17/2021 8:15:00 PM
                  CapabilityStatus: Enabled
                  Service: MIPExchangeSolutions
                  ServicePlanId: DDDDDDDD-6326-4d1b-ae1b-997b625182e6
                }
                ...}
#>
$user = Get-MgUser -UserId aleksandar@yourdomain.onmicrosoft.com
$user | Format-List objectid, displayname, assignedplans
<#
DisplayName   : Aleksandar Nikolic
AssignedPlans : 
#>
$user = Get-MgUser -UserId aleksandar@yourdomain.onmicrosoft.com -Property id, displayname, assignedplans
$user | Format-List id, displayname, assignedplans
<#
Id            : XXXXXXXX-acf1-419b-b06d-f44abb945bde
DisplayName   : Aleksandar Nikolic
AssignedPlans : {AAAAAAAA-e9ae-43fc-93c2-20783f0840c3, BBBBBBBB-357e-4acb-9c21-8495fb025d1f, CCCCCCCC-6ba6-402a-b9f9-83d28acb3d86, DDDDDDDD-6326-4d1b-ae1b-997b625182e6…}
#>
$user | Format-List id, displayname, @{n = 'assignedplans'; e = { $_.assignedplans.tojsonstring() } }
<#
Id            : XXXXXXXX-acf1-419b-b06d-f44abb945bde
DisplayName   : Aleksandar Nikolic
assignedplans : {{
                  "assignedDateTime": "2022-04-07T21:23:53.0000000Z",
                  "capabilityStatus": "Enabled",
                  "service": "ProcessSimple",
                  "servicePlanId": "AAAAAAAA-e9ae-43fc-93c2-20783f0840c3"
                }, {
                  "assignedDateTime": "2022-04-07T21:23:53.0000000Z",
                  "capabilityStatus": "Enabled",
                  "service": "PowerAppsService",
                  "servicePlanId": "BBBBBBBB-357e-4acb-9c21-8495fb025d1f"
                }, {
                  "assignedDateTime": "2022-04-07T21:23:53.0000000Z",
                  "capabilityStatus": "Enabled",
                  "service": "LearningAppServiceInTeams",
                  "servicePlanId": "CCCCCCCC-6ba6-402a-b9f9-83d28acb3d86"
                }, {
                  "assignedDateTime": "2021-10-17T20:15:00.0000000Z",
                  "capabilityStatus": "Enabled",
                  "service": "MIPExchangeSolutions",
                  "servicePlanId": "DDDDDDDD-6326-4d1b-ae1b-997b625182e6"
                }…}
#>

#endregion

#region Let's compare Get-MgUser and Get-AzADUser

Get-MgUser | Select-Object Id, DisplayName, UserType -First 3
Get-MgUser -Select UserType | Select-Object Id, DisplayName, UserType -First 3
Get-MgUser -Select Id, DisplayName, UserType | Select-Object Id, DisplayName, UserType -First 3
Get-MgUser -Select Id, DisplayName, UserType | Select-Object Id, DisplayName, UserType, UserPrincipalName -First 3
$props = Write-Output Id DisplayName UserType UserPrincipalName
Get-MgUser -Select $props | Select-Object $props -First 3

Get-AzADUser | Select-Object Id, DisplayName, UserType -First 3
Get-AzADUser -Select UserType | Select-Object Id, DisplayName, UserType -First 3
Get-AzADUser -Select UserType -AppendSelected | Select-Object Id, DisplayName, UserType, UserPrincipalName -First 3
#endregion

#region Get manager chain up to the root level
# Get the manager of a user and expand the manager's manager

# Get-MgUser: Parameter set cannot be resolved using the specified named parameters.
Get-MgUser -UserId 'testni@yourdomain.onmicrosoft.com' -ExpandProperty "manager(`$levels=max;`$select=id,displayName)" -Property 'id,displayName' -CountVariable CountVar -ConsistencyLevel eventual
# you expect to get transitive managers, but you get only direct manager
Get-MgUser -UserId 'testni@yourdomain.onmicrosoft.com' -ExpandProperty "manager(`$levels=max;`$select=id,displayName)" -Property 'id,displayName'

Get-MgUser -UserId 'testni@yourdomain.onmicrosoft.com' -ExpandProperty "manager(`$select=id,displayName)" -Property 'id,displayName' -ov managers
$managers.ToJsonString() | ConvertFrom-Json | Format-List

# returns transitive managers (with an advanced query)
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/testni@yourdomain.onmicrosoft.com?`$expand=manager(`$levels=max;`$select=id,displayName)&`$select=id,displayName&`$count=true" -Headers @{ConsistencyLevel = 'eventual' } -ov response1

$response1.manager
$response1.manager.manager

# returns only direct manager (without an advanced query)
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/testni@yourdomain.onmicrosoft.com?`$expand=manager(`$levels=max;`$select=id,displayName)&`$select=id,displayName" -ov response2

$response2.manager
$response2.manager.manager
#endregion

#region Assign a user's manager

# Navigation properties like manager cannot be used to update a user, and Update-MgUser will give you an error.

$AdeleM = Get-MgUser -UserId adelem@yourdomain.onmicrosoft.com
$me = Get-MgUser -UserId aleksandar@yourdomain.onmicrosoft.com

# The request body is a JSON object with an @odata.id parameter and the read URL for the user object to be assigned as a manager
$params = @{
    '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($me.Id)"
}

Set-MgUserManagerByRef -UserId $AdeleM.Id -BodyParameter $params

Get-MgUserManager -UserId $AdeleM.Id -ov manager
$manager.ToJsonString() | ConvertFrom-Json
#endregion

#region Report all managers in the organization

Get-MgUser | ForEach-Object { $ht = @{} } { 

    $manager = Get-MgUserManager -UserId $_.Id -ea SilentlyContinue
    $ht = [ordered]@{
        DisplayName       = $_.DisplayName
        UserPrincipalName = $_.UserPrincipalName
        Manager           = ($?) ? "$($manager.AdditionalProperties.displayName) ($($manager.AdditionalProperties.userPrincipalName))" : 'Without a manager' # displayName is case sensitive
    }
    [PSCustomObject]$ht 
} | Sort-Object Manager | Format-Table DisplayName, UserPrincipalName -GroupBy manager

#endregion

#region Pipeline and MicrosoftGraphDirectoryObject

# Pipeline
 
# this fails
Get-MgGroup -Filter "displayName eq 'sg-test1'" | Update-MgGroup -Description 'Test group 1'
# Update-MgGroup_UpdateViaIdentity$Expanded: The pipeline has been stopped.
# Exception: InputObject has null value for InputObject.GroupId
 
# this works
Get-MgGroup -Filter "displayName eq 'sg-test1'" | ForEach-Object { @{GroupId = $_.Id } } | Update-MgGroup -Description 'Test group 1'

# Translate Directory Objects to Users 
$group = Get-MgGroup -Filter "displayName eq 'testgroup1'"

Get-MgGroupOwner -GroupId $Group.Id
Get-MgGroupOwner -GroupId $Group.Id | Get-Member   # TypeName: Microsoft.Graph.PowerShell.Models.MicrosoftGraphDirectoryObject
  (Get-MgGroupOwner -GroupId $Group.Id).ToJsonString()
  (Get-MgGroupOwner -GroupId $Group.Id).ToJsonString() | ConvertFrom-Json
  (Get-MgGroupOwner -GroupId $Group.Id).AdditionalProperties # hash table
  (Get-MgGroupOwner -GroupId $Group.Id).AdditionalProperties | ForEach-Object { New-Object PSObject -Property $_ } # PSCustomObject 
  
Get-MgGroupOwner -GroupId $Group.Id | ForEach-Object { @{ UserId = $_.Id } } | Get-MgUser | Get-Member # MicrosoftGraphUser
Get-MgGroupOwner -GroupId $Group.Id | ForEach-Object { @{ UserId = $_.Id } } | Get-MgUser | Format-List *
  
#endregion

#region The case of the deleted directory items

Get-MgDirectoryDeletedItem
Get-MgBetaDirectoryDeletedItem

Get-Command Get-MgDirectoryDeletedItem -Syntax

Get-MgDirectoryDeletedItem -DirectoryObjectId microsoft.graph.group -ov deleted

$deleted.AdditionalProperties
$deleted.AdditionalProperties['value']
$deleted.AdditionalProperties['value'][0]

# V2
# Retrieve a list of recently deleted directory objects. Currently, deleted items functionality is only supported for the application, servicePrincipal, group, administrative unit, and user resources.

# Each derived type will have a dedicated command Get-MgDirectoryDeletedItemAs*
# For example, Get-MgDirectoryDeletedItemAsUser

Get-MgDirectoryDeletedItemAsGroup

#endregion

#region That damn case-sensitivity

Get-MgUser -Filter "UserPrincipalName eq 'aleksandar@yourdomain.onmicrosoft.com'"
Get-MgUser -Filter "userPrincipalName eq 'Aleksandar@yourdomain.onmicrosoft.com'"

Get-MgAuditLogSignIn -Filter "UserPrincipalName eq 'aleksandar@yourdomain.onmicrosoft.com'"
Get-MgAuditLogSignIn -Filter "UserPrincipalName eq 'Aleksandar@yourdomain.onmicrosoft.com'"


# Who doesn't like GUIDs?
Get-MgUser -UserId aleksandar@yourdomain.onmicrosoft.com -ov user
Get-MgUser -UserId aleksandar@yourdomain.onmicrosoft.com -Property signInActivity
Get-MgUser -UserId $user.Id -Property signInActivity -ov user
$user.signInActivity

#endregion