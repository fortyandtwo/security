<#
.SYNOPSIS
Extracts and displays details of Entra ID Conditional Access policies.

.DESCRIPTION
Connects to Microsoft Graph and retrieves all Conditional Access policies.
It then iterates through each policy, displaying its configuration details
in a structured format, including assignments (users, apps, conditions) and controls (grant, session).
It also adds basic evaluation notes (e.g., policy state, blocking policies).

.NOTES
Version:        1.4 (Removed invalid -Confirm parameter from Disconnect-MgGraph calls)
Author:         André Motta - CSA Security - France
Last Modified:  2025-04-29 
Prerequisites:  PowerShell 5.1+
                Microsoft.Graph.Authentication module
                Microsoft.Graph.Identity.SignIns module
Permissions:    Requires permissions to read Conditional Access policies in Entra ID
                (e.g., Security Reader, Conditional Access Administrator, Global Reader).
                Additional permissions (Directory.Read.All, Application.Read.All, RoleManagement.Read.Directory etc.) needed for -ResolveNames.

.EXAMPLE
.\Get-EntraConditionalAccessPolicies.ps1
Connects to Microsoft Graph (you will be prompted to log in) and outputs policy details.

.EXAMPLE
.\Get-EntraConditionalAccessPolicies.ps1 -ResolveNames $true
Attempts to resolve User/Group/Role/App IDs to display names (requires more permissions and takes longer).

#>
param (
    [Parameter(Mandatory = $false)]
    [switch]$ResolveNames # Optional switch to try resolving IDs to Names
)

# Function to safely get property value
function Get-SafeProperty {
    param($Object, $PropertyName)
    # Check if the object is not null and has the property
    if ($Object -ne $null -and $Object.PSObject.Properties.Match($PropertyName).Count -gt 0) {
        return $Object.$PropertyName
    }
    return $null
}

# Function to resolve common IDs to names (Basic Implementation)
# NOTE: This requires additional permissions (e.g., Directory.Read.All, Application.Read.All, RoleManagement.Read.Directory)
#       and can significantly slow down the script in large environments.
function Resolve-IdToName {
    param(
        [string]$Id,
        [string]$Type # 'User', 'Group', 'Role', 'Application', 'NamedLocation'
    )

    if (-not $ResolveNames -or -not $Id) { return $Id } # Return ID if resolving is off or ID is empty

    # Simple caching to avoid repeated lookups within the same script run
    if ($script:IdNameCache -eq $null) { $script:IdNameCache = @{} }
    # Use ${Type} to delimit variable name from the literal colon
    $cacheKey = "${Type}:$Id"
    if ($script:IdNameCache.ContainsKey($cacheKey)) { return $script:IdNameCache[$cacheKey] }

    $Name = $Id # Default to ID if lookup fails
    try {
        Write-Verbose "Attempting to resolve $Type ID: $Id"
        switch ($Type) {
            'User' { $Name = (Get-MgUser -UserId $Id -ErrorAction SilentlyContinue).DisplayName }
            'Group' { $Name = (Get-MgGroup -GroupId $Id -ErrorAction SilentlyContinue).DisplayName }
            'Role' {
                 # Role lookup requires Microsoft.Graph.DirectoryObjects module & RoleManagement.Read.Directory scope potentially
                 if (-not (Get-Module -Name Microsoft.Graph.DirectoryObjects -ListAvailable)) {
                     Write-Warning "Microsoft.Graph.DirectoryObjects module needed for Role resolution. Attempting installation..."
                     Install-Module Microsoft.Graph.DirectoryObjects -Scope CurrentUser -Force -Confirm:$false -AllowClobber
                     Import-Module Microsoft.Graph.DirectoryObjects -ErrorAction SilentlyContinue
                 }
                 # Check if module loaded successfully before trying the command
                 if (Get-Module -Name Microsoft.Graph.DirectoryObjects) {
                    $Name = (Get-MgDirectoryRole -DirectoryRoleId $Id -ErrorAction SilentlyContinue).DisplayName
                 } else {
                    Write-Warning "Failed to load Microsoft.Graph.DirectoryObjects module. Cannot resolve Role ID $Id."
                 }
             }
            'Application' { $Name = (Get-MgServicePrincipal -ServicePrincipalId $Id -ErrorAction SilentlyContinue).DisplayName }
            # Add other types like NamedLocation if needed (Get-MgIdentityConditionalAccessNamedLocation requires Microsoft.Graph.Identity.SignIns)
            'NamedLocation' { $Name = (Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $Id -ErrorAction SilentlyContinue).DisplayName }
        }
    }
    catch {
        # Use ${Id} to delimit variable name from the literal colon
        Write-Warning "Failed to resolve $Type ID ${Id}: $($_.Exception.Message)"
    }

    # Use original ID if lookup returned null/empty but was expected to find something
    if ($Name -eq $null -or $Name -eq '') { $Name = $Id }

    $ResolvedName = if ($Name -ne $Id) { "$Name ($Id)" } else { $Id }
    # Use the $cacheKey variable which correctly formats the string
    $script:IdNameCache[$cacheKey] = $ResolvedName
    return $ResolvedName
}


# --- Main Script ---

Write-Host "Attempting to connect to Microsoft Graph..." -ForegroundColor Cyan

# Define required permissions (scopes)
# Policy.Read.All is essential for CA policies.
# Directory.Read.All, Application.Read.All etc. are needed for -ResolveNames.
$RequiredScopes = @("Policy.Read.All")
if ($ResolveNames) {
    Write-Host "Name resolution requested. Adding Directory.Read.All, Application.Read.All, RoleManagement.Read.Directory scopes." -ForegroundColor Yellow
    # Add scopes needed by the Get-Mg* cmdlets used in Resolve-IdToName
    $RequiredScopes += "Directory.Read.All", "Application.Read.All", "RoleManagement.Read.Directory" # Added Role scope

    # Ensure necessary modules are available for resolution functions
     if (-not (Get-Module -Name Microsoft.Graph.Users -ListAvailable)) { Install-Module Microsoft.Graph.Users -Scope CurrentUser -Force -Confirm:$false -AllowClobber }
     if (-not (Get-Module -Name Microsoft.Graph.Groups -ListAvailable)) { Install-Module Microsoft.Graph.Groups -Scope CurrentUser -Force -Confirm:$false -AllowClobber }
     if (-not (Get-Module -Name Microsoft.Graph.Applications -ListAvailable)) { Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -Confirm:$false -AllowClobber }
     # Role resolution dependency moved inside Resolve-IdToName for clarity
     # Named Location resolution uses Microsoft.Graph.Identity.SignIns (already required)

     # Import necessary modules for resolution to be safe
     Import-Module Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Applications -ErrorAction SilentlyContinue
}

# Connect to Microsoft Graph
try {
    # Check if already connected with sufficient scopes
    $CurrentContext = Get-MgContext -ErrorAction SilentlyContinue
    $HasSufficientScopes = $false
    if ($CurrentContext) {
        $ExistingScopes = $CurrentContext.Scopes | ForEach-Object { $_.ToLower() }
        $MissingScopes = $RequiredScopes | Where-Object { $ExistingScopes -notcontains $_.ToLower() }
        if ($MissingScopes.Count -eq 0) {
            $HasSufficientScopes = $true
            Write-Host "Already connected to Microsoft Graph with sufficient permissions." -ForegroundColor Green
        } else {
            Write-Warning "Currently connected, but missing required scopes: $($MissingScopes -join ', '). Attempting to reconnect..."
            # CORRECTED: Removed invalid -Confirm parameter
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
    }

    if (-not $HasSufficientScopes) {
         # Add -NoWelcome to suppress the welcome message on repeated connections
         Connect-MgGraph -Scopes $RequiredScopes #-NoWelcome
    }
    Write-Host "Successfully connected to Microsoft Graph." -ForegroundColor Green
    $ConnectionCheck = Get-MgContext # Verify connection context
    Write-Host "Connected as: $($ConnectionCheck.Account)"
    Write-Host "Tenant ID: $($ConnectionCheck.TenantId)"
    Write-Host "Scopes granted: $($ConnectionCheck.Scopes -join ', ')"

}
catch {
    Write-Error "Failed to connect to Microsoft Graph. Please ensure the SDK modules are installed and you have internet connectivity. Error: $($_.Exception.Message)"
    # Exit or return based on how you want to handle connection failure
    return
}


Write-Host "`nFetching Conditional Access Policies..." -ForegroundColor Cyan

try {
    # Use -All parameter to handle paging automatically
    $Policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
}
catch {
    Write-Error "Failed to retrieve Conditional Access policies. Error: $($_.Exception.Message)"
    Write-Error "Ensure your account has the necessary permissions (e.g., Security Reader)."
    # CORRECTED: Removed invalid -Confirm parameter
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    return
}

if ($null -eq $Policies -or $Policies.Count -eq 0) {
    Write-Host "No Conditional Access policies found in this tenant." -ForegroundColor Yellow
    # CORRECTED: Removed invalid -Confirm parameter
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    return
}

Write-Host "Found $($Policies.Count) policies. Processing..." -ForegroundColor Green
Write-Host "--------------------------------------------------"

# Initialize cache if resolving names
if ($ResolveNames) { $script:IdNameCache = @{} }

foreach ($Policy in $Policies) {
    Write-Host "`nPolicy Name: $($Policy.DisplayName)" -ForegroundColor White
    Write-Host "Policy ID:   $($Policy.Id)"
    # Use $() around the if statement for -ForegroundColor
    Write-Host "State:       $($Policy.State)" -ForegroundColor $(if ($Policy.State -eq 'enabled') { 'Green' } elseif ($Policy.State -eq 'disabled') { 'Red' } else { 'Yellow' }) # Highlight state

    # --- Assignments (Conditions) ---
    Write-Host "`n  ASSIGNMENTS (Conditions):" -ForegroundColor Cyan

    $Conditions = $Policy.Conditions

    # Users
    Write-Host "    Users:"
    Write-Host "      Include:"
    $IncludeUsers = Get-SafeProperty $Conditions.Users 'IncludeUsers'
    $IncludeGroups = Get-SafeProperty $Conditions.Users 'IncludeGroups'
    $IncludeRoles = Get-SafeProperty $Conditions.Users 'IncludeRoles'
    Write-Host "        Users: $(if ($IncludeUsers) { ($IncludeUsers | ForEach-Object { Resolve-IdToName $_ 'User' }) -join ', ' } else { 'None' })"
    Write-Host "        Groups: $(if ($IncludeGroups) { ($IncludeGroups | ForEach-Object { Resolve-IdToName $_ 'Group' }) -join ', ' } else { 'None' })"
    Write-Host "        Roles: $(if ($IncludeRoles) { ($IncludeRoles | ForEach-Object { Resolve-IdToName $_ 'Role' }) -join ', ' } else { 'None' })"
    # GuestOrExternalUsers check (Complex object)
     $GuestUserCondition = Get-SafeProperty $Conditions.Users 'IncludeGuestsOrExternalUsers'
     if ($GuestUserCondition) {
         Write-Host "        Guest/External Users:"
         Write-Host "          Types: $($GuestUserCondition.GuestOrExternalUserTypes)"
         if ($GuestUserCondition.ExternalTenants) {
             $MembershipKind = Get-SafeProperty $GuestUserCondition.ExternalTenants 'MembershipKind' # e.g., all, enumerated
             Write-Host "          External Tenants specified: Yes (MembershipKind: $MembershipKind)"
             # You could add logic here to list specific tenant IDs if $GuestUserCondition.ExternalTenants.Members has values and $MembershipKind -eq 'enumerated'
         }
     } else { Write-Host "        Guest/External Users: None" }

    Write-Host "      Exclude:"
    $ExcludeUsers = Get-SafeProperty $Conditions.Users 'ExcludeUsers'
    $ExcludeGroups = Get-SafeProperty $Conditions.Users 'ExcludeGroups'
    $ExcludeRoles = Get-SafeProperty $Conditions.Users 'ExcludeRoles'
    Write-Host "        Users: $(if ($ExcludeUsers) { ($ExcludeUsers | ForEach-Object { Resolve-IdToName $_ 'User' }) -join ', ' } else { 'None' })"
    Write-Host "        Groups: $(if ($ExcludeGroups) { ($ExcludeGroups | ForEach-Object { Resolve-IdToName $_ 'Group' }) -join ', ' } else { 'None' })"
    Write-Host "        Roles: $(if ($ExcludeRoles) { ($ExcludeRoles | ForEach-Object { Resolve-IdToName $_ 'Role' }) -join ', ' } else { 'None' })"
     $ExcludeGuestUserCondition = Get-SafeProperty $Conditions.Users 'ExcludeGuestsOrExternalUsers'
     if ($ExcludeGuestUserCondition) {
         Write-Host "        Guest/External Users (Excluded):"
         Write-Host "          Types: $($ExcludeGuestUserCondition.GuestOrExternalUserTypes)"
         # Similar breakdown for ExternalTenants if needed
     } else { Write-Host "        Guest/External Users (Excluded): None" }

    # Applications (Target Resources)
    Write-Host "    Applications (Target Resources):"
    Write-Host "      Include:"
    $Apps = Get-SafeProperty $Conditions 'Applications'
    $IncludeApps = Get-SafeProperty $Apps 'IncludeApplications'
    $IncludeUserActions = Get-SafeProperty $Apps 'IncludeUserActions'
    $IncludeAuthContexts = Get-SafeProperty $Apps 'IncludeAuthenticationContextClassReferences'
    Write-Host "        Applications: $(if ($IncludeApps) { ($IncludeApps | ForEach-Object { Resolve-IdToName $_ 'Application' }) -join ', ' } else { 'None' })"
    Write-Host "        User Actions: $(if ($IncludeUserActions) { $IncludeUserActions -join ', ' } else { 'None' })"
    Write-Host "        Authentication Contexts: $(if ($IncludeAuthContexts) { $IncludeAuthContexts -join ', ' } else { 'None' })"

    Write-Host "      Exclude:"
    $ExcludeApps = Get-SafeProperty $Apps 'ExcludeApplications'
    Write-Host "        Applications: $(if ($ExcludeApps) { ($ExcludeApps | ForEach-Object { Resolve-IdToName $_ 'Application' }) -join ', ' } else { 'None' })"
    # Add ExcludeUserActions, ExcludeAuthenticationContextClassReferences if needed

    # Locations
    Write-Host "    Locations:"
    $Locations = Get-SafeProperty $Conditions 'Locations'
    $IncludeLoc = Get-SafeProperty $Locations 'IncludeLocations'
    $ExcludeLoc = Get-SafeProperty $Locations 'ExcludeLocations'
    # Resolve NamedLocation IDs if requested, handle special values 'All', 'AllTrusted'
    Write-Host "      Include: $(if ($IncludeLoc) { ($IncludeLoc | ForEach-Object { if ($_ -eq 'All' -or $_ -eq 'AllTrusted') { $_ } else { Resolve-IdToName $_ 'NamedLocation' } }) -join ', ' } else { 'None' })"
    Write-Host "      Exclude: $(if ($ExcludeLoc) { ($ExcludeLoc | ForEach-Object { if ($_ -eq 'All' -or $_ -eq 'AllTrusted') { $_ } else { Resolve-IdToName $_ 'NamedLocation' } }) -join ', ' } else { 'None' })"

    # Platforms
    Write-Host "    Device Platforms:"
    $Platforms = Get-SafeProperty $Conditions 'Platforms'
    $IncludePlat = Get-SafeProperty $Platforms 'IncludePlatforms'
    $ExcludePlat = Get-SafeProperty $Platforms 'ExcludePlatforms'
    Write-Host "      Include: $(if ($IncludePlat) { $IncludePlat -join ', ' } else { 'None' })"
    Write-Host "      Exclude: $(if ($ExcludePlat) { $ExcludePlat -join ', ' } else { 'None' })"

    # Devices (Filter)
    Write-Host "    Devices (Filter):"
    $Devices = Get-SafeProperty $Conditions 'Devices'
    $DeviceFilter = Get-SafeProperty $Devices 'DeviceFilter'
    if ($DeviceFilter) {
        Write-Host "      Mode: $(Get-SafeProperty $DeviceFilter 'Mode')"
        Write-Host "      Rule: $(Get-SafeProperty $DeviceFilter 'Rule')"
    } else {
        Write-Host "      Mode: Not Configured"
        Write-Host "      Rule: Not Configured"
    }


    # Client App Types
    Write-Host "    Client App Types:"
    $ClientAppTypes = Get-SafeProperty $Conditions 'ClientAppTypes'
    Write-Host "      Types: $(if ($ClientAppTypes) { $ClientAppTypes -join ', ' } else { 'Any' })"

    # Risk Levels (Sign-in & User) - Check if Identity Protection is used
    Write-Host "    Sign-in Risk:"
    $SignInRiskLevels = Get-SafeProperty $Conditions 'SignInRiskLevels'
    Write-Host "      Levels: $(if ($SignInRiskLevels) { $SignInRiskLevels -join ', ' } else { 'Not Configured' })"

    Write-Host "    User Risk:"
    $UserRiskLevels = Get-SafeProperty $Conditions 'UserRiskLevels'
    Write-Host "      Levels: $(if ($UserRiskLevels) { $UserRiskLevels -join ', ' } else { 'Not Configured' })"


    # --- Controls ---
    Write-Host "`n  CONTROLS:" -ForegroundColor Cyan

    # Grant Controls
    $GrantControls = $Policy.GrantControls
    if ($GrantControls) {
        Write-Host "    Grant Controls:"
        Write-Host "      Operator: $($GrantControls.Operator)" # AND / OR
        if ($GrantControls.BuiltInControls) {
            Write-Host "      Required Controls: $($GrantControls.BuiltInControls -join ', ')" -ForegroundColor Green
        }
        if ($GrantControls.CustomAuthenticationFactors) {
             Write-Host "      Custom Auth Factors: $($GrantControls.CustomAuthenticationFactors -join ', ')"
        }
        if ($GrantControls.TermsOfUse) {
            Write-Host "      Terms of Use: $($GrantControls.TermsOfUse -join ', ')"
        }
        if ($GrantControls.AuthenticationStrength) {
            # AuthenticationStrength object has Id and DisplayName, but DisplayName might be null sometimes
            $authStrengthId = Get-SafeProperty $GrantControls.AuthenticationStrength 'Id'
            $authStrengthName = Get-SafeProperty $GrantControls.AuthenticationStrength 'DisplayName'
            $authStrengthDisplay = if ($authStrengthName -and $authStrengthName -ne '') { "$authStrengthName ($authStrengthId)" } else { $authStrengthId }
            Write-Host "      Authentication Strength: Required ($authStrengthDisplay)"
            # To resolve just an ID, you might need: Get-MgIdentityAuthenticationStrengthPolicy -AuthenticationStrengthPolicyId $authStrengthId
        }

        # Highlight BLOCK access
        if ($GrantControls.Operator -eq 'Block' -or ($GrantControls.BuiltInControls -contains 'block')) {
             Write-Host "      ACTION: BLOCK ACCESS" -ForegroundColor Red -BackgroundColor Black
        }

    } else {
        Write-Host "    Grant Controls: None Configured (Implicit Deny if conditions met, unless Grant is handled by another policy)" -ForegroundColor Yellow
    }


    # Session Controls
    $SessionControls = $Policy.SessionControls
    if ($SessionControls) {
        Write-Host "    Session Controls:"
        if (Get-SafeProperty $SessionControls 'ApplicationEnforcedRestrictions') { Write-Host "      Application Enforced Restrictions: Enabled" }
        if (Get-SafeProperty $SessionControls 'CloudAppSecurity') { Write-Host "      Cloud App Security (MCAS): Enabled (Mode: $(Get-SafeProperty $SessionControls.CloudAppSecurity 'CloudAppSecurityType'))" }
        if (Get-SafeProperty $SessionControls 'SignInFrequency') { Write-Host "      Sign-in Frequency: Value: $(Get-SafeProperty $SessionControls.SignInFrequency 'Value') $(Get-SafeProperty $SessionControls.SignInFrequency 'Type'), Auth Type: $(Get-SafeProperty $SessionControls.SignInFrequency 'AuthenticationType')" }
        if (Get-SafeProperty $SessionControls 'PersistentBrowser') { Write-Host "      Persistent Browser Session: $(Get-SafeProperty $SessionControls.PersistentBrowser 'Mode')" }
        if (Get-SafeProperty $SessionControls 'ContinuousAccessEvaluation') { Write-Host "      Continuous Access Evaluation: $(Get-SafeProperty $SessionControls.ContinuousAccessEvaluation 'Mode')" }
        if ($null -ne (Get-SafeProperty $SessionControls 'DisableResilienceDefaults')) { Write-Host "      Disable Resilience Defaults: $(Get-SafeProperty $SessionControls 'DisableResilienceDefaults')" } # Boolean
        if (Get-SafeProperty $SessionControls 'SecureSignInSession') { Write-Host "      Secure Sign-In Session (requires Proactive remediation): Enabled" }

    } else {
         Write-Host "    Session Controls: None Configured"
    }

    # --- Basic Evaluation Notes ---
    Write-Host "`n  EVALUATION NOTES:" -ForegroundColor Cyan
    if ($Policy.State -ne 'enabled') { Write-Warning "  - Policy is currently NOT ENFORCED (State: $($Policy.State))" }
    # Check for 'All Users' inclusion without any specified exclusions
    if (($IncludeUsers -contains 'All') -and -not ($ExcludeUsers) -and -not ($ExcludeGroups) -and -not ($ExcludeRoles) -and -not $ExcludeGuestUserCondition) { Write-Warning "  - Policy targets 'All Users' without specific user, group, role, or guest exclusions. Verify scope is intended." }
    elseif ($IncludeUsers -contains 'All') { Write-Host "  - Policy targets 'All Users' but has exclusions defined." -ForegroundColor Gray }
    # Check for 'All Apps' inclusion without any specified exclusions
    if (($IncludeApps -contains 'All') -and -not ($ExcludeApps)) { Write-Warning "  - Policy targets 'All Cloud Apps' without exclusions. Verify scope carefully." }
    # Block Policy
    if ($GrantControls -and ($GrantControls.Operator -eq 'Block' -or ($GrantControls.BuiltInControls -contains 'block'))) { Write-Host "  - This is a BLOCK policy." -ForegroundColor Yellow }
    # MFA Enforcement
    if ($GrantControls -and ($GrantControls.BuiltInControls -contains 'mfa')) { Write-Host "  - This policy enforces MFA." -ForegroundColor Green }
    # Legacy Auth potentially targeted
    if ($ClientAppTypes -contains 'other') { Write-Warning "  - Policy includes 'Other clients', potentially matching legacy authentication. Ensure this is intended or use stronger controls/conditions."}
    # Add more checks based on your organization's standards

    Write-Host "--------------------------------------------------"
}

# Disconnect from Microsoft Graph
Write-Host "`nScript finished. Disconnecting from Microsoft Graph." -ForegroundColor Cyan
# CORRECTED: Removed invalid -Confirm parameter
Disconnect-MgGraph -ErrorAction SilentlyContinue
