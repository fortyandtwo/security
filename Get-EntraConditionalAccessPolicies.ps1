<#
.SYNOPSIS
Extracts and displays details of Entra ID Conditional Access policies, with options to export to CSV or JSON.

.DESCRIPTION
Connects to Microsoft Graph and retrieves all Conditional Access policies.
It then iterates through each policy, collecting its configuration details.
Optionally suppresses console output and exports the collected data to a specified file in CSV or JSON format.

.NOTES
Version:        1.5
Author:         André Motta - CSA Security - France
Last Modified:  2025-04-29
Changes:        - Added -OutputFile, -OutputFormat, -Quiet parameters for CSV/JSON export.
                - Collects policy data into objects.
                - Implemented export logic.
Prerequisites:  PowerShell 5.1+
                Microsoft.Graph.Authentication module
                Microsoft.Graph.Identity.SignIns module
Permissions:    Requires permissions to read Conditional Access policies in Entra ID
                (e.g., Security Reader, Conditional Access Administrator, Global Reader).
                Additional permissions (Directory.Read.All, Application.Read.All, RoleManagement.Read.Directory etc.) needed for -ResolveNames.

.EXAMPLE
# Display output only to console (default behavior)
.\Get-EntraConditionalAccessPolicies.ps1

.EXAMPLE
# Export policies to a CSV file (default format) and show console output
.\Get-EntraConditionalAccessPolicies.ps1 -OutputFile "C:\Temp\CAPolicies.csv"

.EXAMPLE
# Export policies to a JSON file and show console output
.\Get-EntraConditionalAccessPolicies.ps1 -OutputFile "C:\Temp\CAPolicies.json" -OutputFormat JSON

.EXAMPLE
# Export policies to CSV, resolve names, and suppress detailed console output
.\Get-EntraConditionalAccessPolicies.ps1 -OutputFile "C:\Temp\CAPolicies_Resolved.csv" -ResolveNames -Quiet

#>
param (
    [Parameter(Mandatory = $false)]
    [switch]$ResolveNames, # Optional switch to try resolving IDs to Names

    [Parameter(Mandatory = $false)]
    [string]$OutputFile, # Path for the export file

    [Parameter(Mandatory = $false)]
    [ValidateSet('CSV', 'JSON')]
    [string]$OutputFormat = 'CSV', # Format for export (required if OutputFile is specified)

    [Parameter(Mandatory=$false)]
    [switch]$Quiet # Suppress detailed console output during processing loop
)

# Determine if exporting to file based on whether OutputFile was provided
$ExportToFile = $PSBoundParameters.ContainsKey('OutputFile')

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
        # Suppress verbose messages if Quiet switch is used
        Write-Verbose "Attempting to resolve $Type ID: $Id" -Verbose:(-not $Quiet)
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

# Helper function to join array elements for CSV, handles $null or empty arrays
function Join-ArrayForCsv {
    param(
        [array]$InputArray,
        [string]$Delimiter = ';'
    )
    if ($null -eq $InputArray -or $InputArray.Count -eq 0) {
        return '' # Return empty string for null/empty arrays
    }
    return $InputArray -join $Delimiter
}


# --- Main Script ---

if (-not $Quiet) { Write-Host "Attempting to connect to Microsoft Graph..." -ForegroundColor Cyan }

# Define required permissions (scopes)
$RequiredScopes = @("Policy.Read.All")
if ($ResolveNames) {
    if (-not $Quiet) { Write-Host "Name resolution requested. Adding Directory.Read.All, Application.Read.All, RoleManagement.Read.Directory scopes." -ForegroundColor Yellow }
    $RequiredScopes += "Directory.Read.All", "Application.Read.All", "RoleManagement.Read.Directory"

    # Ensure necessary modules are available for resolution functions
     if (-not (Get-Module -Name Microsoft.Graph.Users -ListAvailable)) { Install-Module Microsoft.Graph.Users -Scope CurrentUser -Force -Confirm:$false -AllowClobber }
     if (-not (Get-Module -Name Microsoft.Graph.Groups -ListAvailable)) { Install-Module Microsoft.Graph.Groups -Scope CurrentUser -Force -Confirm:$false -AllowClobber }
     if (-not (Get-Module -Name Microsoft.Graph.Applications -ListAvailable)) { Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -Confirm:$false -AllowClobber }

     # Import necessary modules for resolution to be safe
     Import-Module Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Applications -ErrorAction SilentlyContinue
}

# Connect to Microsoft Graph
try {
    $CurrentContext = Get-MgContext -ErrorAction SilentlyContinue
    $HasSufficientScopes = $false
    if ($CurrentContext) {
        $ExistingScopes = $CurrentContext.Scopes | ForEach-Object { $_.ToLower() }
        $MissingScopes = $RequiredScopes | Where-Object { $ExistingScopes -notcontains $_.ToLower() }
        if ($MissingScopes.Count -eq 0) {
            $HasSufficientScopes = $true
            if (-not $Quiet) { Write-Host "Already connected to Microsoft Graph with sufficient permissions." -ForegroundColor Green }
        } else {
            Write-Warning "Currently connected, but missing required scopes: $($MissingScopes -join ', '). Attempting to reconnect..."
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
    }

    if (-not $HasSufficientScopes) {
         Connect-MgGraph -Scopes $RequiredScopes
    }
    if (-not $Quiet) {
        Write-Host "Successfully connected to Microsoft Graph." -ForegroundColor Green
        $ConnectionCheck = Get-MgContext # Verify connection context
        Write-Host "Connected as: $($ConnectionCheck.Account)"
        Write-Host "Tenant ID: $($ConnectionCheck.TenantId)"
        Write-Host "Scopes granted: $($ConnectionCheck.Scopes -join ', ')"
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph. Please ensure the SDK modules are installed and you have internet connectivity. Error: $($_.Exception.Message)"
    return
}


if (-not $Quiet) { Write-Host "`nFetching Conditional Access Policies..." -ForegroundColor Cyan }

try {
    # Use -All parameter to handle paging automatically
    $Policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
}
catch {
    Write-Error "Failed to retrieve Conditional Access policies. Error: $($_.Exception.Message)"
    Write-Error "Ensure your account has the necessary permissions (e.g., Security Reader)."
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    return
}

if ($null -eq $Policies -or $Policies.Count -eq 0) {
    Write-Host "No Conditional Access policies found in this tenant." -ForegroundColor Yellow
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    return
}

if (-not $Quiet) { Write-Host "Found $($Policies.Count) policies. Processing..." -ForegroundColor Green }
if ($ExportToFile -and -not $Quiet) { Write-Host "Data will be exported to $OutputFile (Format: $OutputFormat)" -ForegroundColor Cyan}
if (-not $Quiet) { Write-Host "--------------------------------------------------" }

# Initialize collection to store structured policy data
$PolicyDataCollection = [System.Collections.Generic.List[PSObject]]::new()

# Initialize cache if resolving names
if ($ResolveNames) { $script:IdNameCache = @{} }

# Process each policy
foreach ($Policy in $Policies) {

    if (-not $Quiet) {
        Write-Host "`nProcessing Policy: $($Policy.DisplayName)" -ForegroundColor White
    } else {
        # Provide minimal progress indication even when quiet
        Write-Progress -Activity "Processing Conditional Access Policies" -Status "Policy: $($Policy.DisplayName)" -PercentComplete (($PolicyDataCollection.Count / $Policies.Count) * 100)
    }

    # --- Extract Data into a structured object ---
    $PolicyDetails = [PSCustomObject]@{
        ID = $Policy.Id
        DisplayName = $Policy.DisplayName
        State = $Policy.State

        # Condition Properties (Flattened where necessary)
        IncludeUsers = @()
        IncludeGroups = @()
        IncludeRoles = @()
        IncludeGuestOrExternalUserTypes = $null
        IncludeGuestOrExternalTenantMembershipKind = $null
        ExcludeUsers = @()
        ExcludeGroups = @()
        ExcludeRoles = @()
        ExcludeGuestOrExternalUserTypes = $null
        ExcludeGuestOrExternalTenantMembershipKind = $null

        IncludeApplications = @()
        IncludeUserActions = @()
        IncludeAuthContexts = @()
        ExcludeApplications = @()

        IncludeLocations = @()
        ExcludeLocations = @()

        IncludePlatforms = @()
        ExcludePlatforms = @()

        DeviceFilterMode = $null
        DeviceFilterRule = $null

        ClientAppTypes = @()
        SignInRiskLevels = @()
        UserRiskLevels = @()

        # Grant Control Properties
        GrantControlsOperator = $null
        GrantRequiredControls = @()
        GrantCustomAuthFactors = @()
        GrantTermsOfUse = @()
        GrantAuthStrengthId = $null
        GrantAuthStrengthName = $null

        # Session Control Properties (Flattened)
        SessionAppEnforcedRestrictions = $false
        SessionCloudAppSecurityMode = $null
        SessionSignInFrequencyValue = $null
        SessionSignInFrequencyType = $null
        SessionSignInFrequencyAuthType = $null
        SessionPersistentBrowserMode = $null
        SessionCAEMode = $null
        SessionDisableResilienceDefaults = $false
        SessionSecureSignInSession = $false
    }

    # Populate Conditions
    $Conditions = $Policy.Conditions
    if ($Conditions) {
        $Users = Get-SafeProperty $Conditions 'Users'
        if ($Users) {
            $PolicyDetails.IncludeUsers = if (Get-SafeProperty $Users 'IncludeUsers') { (Get-SafeProperty $Users 'IncludeUsers' | ForEach-Object { Resolve-IdToName $_ 'User' }) } else { @() }
            $PolicyDetails.IncludeGroups = if (Get-SafeProperty $Users 'IncludeGroups') { (Get-SafeProperty $Users 'IncludeGroups' | ForEach-Object { Resolve-IdToName $_ 'Group' }) } else { @() }
            $PolicyDetails.IncludeRoles = if (Get-SafeProperty $Users 'IncludeRoles') { (Get-SafeProperty $Users 'IncludeRoles' | ForEach-Object { Resolve-IdToName $_ 'Role' }) } else { @() }
            $IncludeGuests = Get-SafeProperty $Users 'IncludeGuestsOrExternalUsers'
            if ($IncludeGuests) {
                $PolicyDetails.IncludeGuestOrExternalUserTypes = Get-SafeProperty $IncludeGuests 'GuestOrExternalUserTypes'
                $PolicyDetails.IncludeGuestOrExternalTenantMembershipKind = Get-SafeProperty (Get-SafeProperty $IncludeGuests 'ExternalTenants') 'MembershipKind'
            }

            $PolicyDetails.ExcludeUsers = if (Get-SafeProperty $Users 'ExcludeUsers') { (Get-SafeProperty $Users 'ExcludeUsers' | ForEach-Object { Resolve-IdToName $_ 'User' }) } else { @() }
            $PolicyDetails.ExcludeGroups = if (Get-SafeProperty $Users 'ExcludeGroups') { (Get-SafeProperty $Users 'ExcludeGroups' | ForEach-Object { Resolve-IdToName $_ 'Group' }) } else { @() }
            $PolicyDetails.ExcludeRoles = if (Get-SafeProperty $Users 'ExcludeRoles') { (Get-SafeProperty $Users 'ExcludeRoles' | ForEach-Object { Resolve-IdToName $_ 'Role' }) } else { @() }
            $ExcludeGuests = Get-SafeProperty $Users 'ExcludeGuestsOrExternalUsers'
             if ($ExcludeGuests) {
                $PolicyDetails.ExcludeGuestOrExternalUserTypes = Get-SafeProperty $ExcludeGuests 'GuestOrExternalUserTypes'
                $PolicyDetails.ExcludeGuestOrExternalTenantMembershipKind = Get-SafeProperty (Get-SafeProperty $ExcludeGuests 'ExternalTenants') 'MembershipKind'
            }
        }

        $Apps = Get-SafeProperty $Conditions 'Applications'
        if ($Apps) {
            $PolicyDetails.IncludeApplications = if (Get-SafeProperty $Apps 'IncludeApplications') { (Get-SafeProperty $Apps 'IncludeApplications' | ForEach-Object { Resolve-IdToName $_ 'Application' }) } else { @() }
            $PolicyDetails.IncludeUserActions = Get-SafeProperty $Apps 'IncludeUserActions' # Already an array of strings
            $PolicyDetails.IncludeAuthContexts = Get-SafeProperty $Apps 'IncludeAuthenticationContextClassReferences' # Already an array of strings
            $PolicyDetails.ExcludeApplications = if (Get-SafeProperty $Apps 'ExcludeApplications') { (Get-SafeProperty $Apps 'ExcludeApplications' | ForEach-Object { Resolve-IdToName $_ 'Application' }) } else { @() }
        }

        $Locations = Get-SafeProperty $Conditions 'Locations'
        if ($Locations) {
            $PolicyDetails.IncludeLocations = if (Get-SafeProperty $Locations 'IncludeLocations') { (Get-SafeProperty $Locations 'IncludeLocations' | ForEach-Object { if ($_ -eq 'All' -or $_ -eq 'AllTrusted') { $_ } else { Resolve-IdToName $_ 'NamedLocation' } }) } else { @() }
            $PolicyDetails.ExcludeLocations = if (Get-SafeProperty $Locations 'ExcludeLocations') { (Get-SafeProperty $Locations 'ExcludeLocations' | ForEach-Object { if ($_ -eq 'All' -or $_ -eq 'AllTrusted') { $_ } else { Resolve-IdToName $_ 'NamedLocation' } }) } else { @() }
        }

        $Platforms = Get-SafeProperty $Conditions 'Platforms'
        if ($Platforms) {
            $PolicyDetails.IncludePlatforms = Get-SafeProperty $Platforms 'IncludePlatforms'
            $PolicyDetails.ExcludePlatforms = Get-SafeProperty $Platforms 'ExcludePlatforms'
        }

        $Devices = Get-SafeProperty $Conditions 'Devices'
        $DeviceFilter = Get-SafeProperty $Devices 'DeviceFilter'
        if ($DeviceFilter) {
             $PolicyDetails.DeviceFilterMode = Get-SafeProperty $DeviceFilter 'Mode'
             $PolicyDetails.DeviceFilterRule = Get-SafeProperty $DeviceFilter 'Rule'
        }

        $PolicyDetails.ClientAppTypes = Get-SafeProperty $Conditions 'ClientAppTypes'
        $PolicyDetails.SignInRiskLevels = Get-SafeProperty $Conditions 'SignInRiskLevels'
        $PolicyDetails.UserRiskLevels = Get-SafeProperty $Conditions 'UserRiskLevels'
    }

    # Populate Grant Controls
    $GrantControls = $Policy.GrantControls
    if ($GrantControls) {
        $PolicyDetails.GrantControlsOperator = Get-SafeProperty $GrantControls 'Operator'
        $PolicyDetails.GrantRequiredControls = Get-SafeProperty $GrantControls 'BuiltInControls'
        $PolicyDetails.GrantCustomAuthFactors = Get-SafeProperty $GrantControls 'CustomAuthenticationFactors'
        $PolicyDetails.GrantTermsOfUse = Get-SafeProperty $GrantControls 'TermsOfUse'
        $AuthStrength = Get-SafeProperty $GrantControls 'AuthenticationStrength'
        if ($AuthStrength) {
            $PolicyDetails.GrantAuthStrengthId = Get-SafeProperty $AuthStrength 'Id'
            $PolicyDetails.GrantAuthStrengthName = Get-SafeProperty $AuthStrength 'DisplayName'
        }
    }

    # Populate Session Controls (Flattened)
    $SessionControls = $Policy.SessionControls
    if ($SessionControls) {
        $PolicyDetails.SessionAppEnforcedRestrictions = [bool](Get-SafeProperty $SessionControls 'ApplicationEnforcedRestrictions') # Cast to bool if needed
        $PolicyDetails.SessionCloudAppSecurityMode = Get-SafeProperty (Get-SafeProperty $SessionControls 'CloudAppSecurity') 'CloudAppSecurityType'
        $SignInFreq = Get-SafeProperty $SessionControls 'SignInFrequency'
        if ($SignInFreq) {
            $PolicyDetails.SessionSignInFrequencyValue = Get-SafeProperty $SignInFreq 'Value'
            $PolicyDetails.SessionSignInFrequencyType = Get-SafeProperty $SignInFreq 'Type'
            $PolicyDetails.SessionSignInFrequencyAuthType = Get-SafeProperty $SignInFreq 'AuthenticationType'
        }
        $PolicyDetails.SessionPersistentBrowserMode = Get-SafeProperty (Get-SafeProperty $SessionControls 'PersistentBrowser') 'Mode'
        $PolicyDetails.SessionCAEMode = Get-SafeProperty (Get-SafeProperty $SessionControls 'ContinuousAccessEvaluation') 'Mode'
        $PolicyDetails.SessionDisableResilienceDefaults = [bool](Get-SafeProperty $SessionControls 'DisableResilienceDefaults') # Cast to bool
        $PolicyDetails.SessionSecureSignInSession = [bool](Get-SafeProperty $SessionControls 'SecureSignInSession') # Cast to bool
    }

    # Add the structured object to our collection
    $PolicyDataCollection.Add($PolicyDetails)

    # --- Display output to console if not Quiet ---
    if (-not $Quiet) {
        # (Re-use the Write-Host logic from previous versions if detailed console output is desired)
        # For brevity here, we'll just show the name/state/ID as confirmation
        Write-Host "  ID:    $($PolicyDetails.ID)"
        Write-Host "  State: $($PolicyDetails.State)" -ForegroundColor $(if ($PolicyDetails.State -eq 'enabled') { 'Green' } elseif ($PolicyDetails.State -eq 'disabled') { 'Red' } else { 'Yellow' })
        # Add more Write-Host lines here mirroring previous verbose output if needed
        Write-Host "--------------------------------------------------"
    }

} # End foreach policy

# --- Export Data if requested ---
if ($ExportToFile) {
    if (-not $Quiet) { Write-Host "`nExporting $($PolicyDataCollection.Count) policies to $OutputFormat file: $OutputFile" -ForegroundColor Cyan }
    try {
        # Ensure output directory exists
        $OutputDirectory = Split-Path -Path $OutputFile -Parent
        if ($OutputDirectory -and (-not (Test-Path -Path $OutputDirectory -PathType Container))) {
            if (-not $Quiet) { Write-Host "Creating output directory: $OutputDirectory" }
            New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        }

        if ($OutputFormat -eq 'JSON') {
            # Convert the collection (which contains objects with arrays/nested data) to JSON
            $PolicyDataCollection | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
        }
        elseif ($OutputFormat -eq 'CSV') {
            # Prepare data for CSV: Select properties and flatten arrays using the helper function
            $CsvData = $PolicyDataCollection | Select-Object -Property @(
                'DisplayName', 'ID', 'State',
                @{Name='IncludeUsers'; Expression={Join-ArrayForCsv -InputArray $_.IncludeUsers}},
                @{Name='IncludeGroups'; Expression={Join-ArrayForCsv -InputArray $_.IncludeGroups}},
                @{Name='IncludeRoles'; Expression={Join-ArrayForCsv -InputArray $_.IncludeRoles}},
                'IncludeGuestOrExternalUserTypes',
                'IncludeGuestOrExternalTenantMembershipKind',
                @{Name='ExcludeUsers'; Expression={Join-ArrayForCsv -InputArray $_.ExcludeUsers}},
                @{Name='ExcludeGroups'; Expression={Join-ArrayForCsv -InputArray $_.ExcludeGroups}},
                @{Name='ExcludeRoles'; Expression={Join-ArrayForCsv -InputArray $_.ExcludeRoles}},
                'ExcludeGuestOrExternalUserTypes',
                'ExcludeGuestOrExternalTenantMembershipKind',
                @{Name='IncludeApplications'; Expression={Join-ArrayForCsv -InputArray $_.IncludeApplications}},
                @{Name='IncludeUserActions'; Expression={Join-ArrayForCsv -InputArray $_.IncludeUserActions}},
                @{Name='IncludeAuthContexts'; Expression={Join-ArrayForCsv -InputArray $_.IncludeAuthContexts}},
                @{Name='ExcludeApplications'; Expression={Join-ArrayForCsv -InputArray $_.ExcludeApplications}},
                @{Name='IncludeLocations'; Expression={Join-ArrayForCsv -InputArray $_.IncludeLocations}},
                @{Name='ExcludeLocations'; Expression={Join-ArrayForCsv -InputArray $_.ExcludeLocations}},
                @{Name='IncludePlatforms'; Expression={Join-ArrayForCsv -InputArray $_.IncludePlatforms}},
                @{Name='ExcludePlatforms'; Expression={Join-ArrayForCsv -InputArray $_.ExcludePlatforms}},
                'DeviceFilterMode', 'DeviceFilterRule',
                @{Name='ClientAppTypes'; Expression={Join-ArrayForCsv -InputArray $_.ClientAppTypes}},
                @{Name='SignInRiskLevels'; Expression={Join-ArrayForCsv -InputArray $_.SignInRiskLevels}},
                @{Name='UserRiskLevels'; Expression={Join-ArrayForCsv -InputArray $_.UserRiskLevels}},
                'GrantControlsOperator',
                @{Name='GrantRequiredControls'; Expression={Join-ArrayForCsv -InputArray $_.GrantRequiredControls}},
                @{Name='GrantCustomAuthFactors'; Expression={Join-ArrayForCsv -InputArray $_.GrantCustomAuthFactors}},
                @{Name='GrantTermsOfUse'; Expression={Join-ArrayForCsv -InputArray $_.GrantTermsOfUse}},
                'GrantAuthStrengthId',
                'GrantAuthStrengthName',
                # Flattened Session Controls
                'SessionAppEnforcedRestrictions', 'SessionCloudAppSecurityMode', 'SessionSignInFrequencyValue', 'SessionSignInFrequencyType', 'SessionSignInFrequencyAuthType', 'SessionPersistentBrowserMode', 'SessionCAEMode', 'SessionDisableResilienceDefaults', 'SessionSecureSignInSession'
            )
            # Export to CSV
            $CsvData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 #-Delimiter ',' # Use default delimiter or specify e.g. -Delimiter ';'
        }
        if (-not $Quiet) { Write-Host "Successfully exported data to $OutputFile" -ForegroundColor Green }
    }
    catch {
        Write-Error "Failed to export data to $OutputFile. Error: $($_.Exception.Message)"
    }
}


# Disconnect from Microsoft Graph
if (-not $Quiet) { Write-Host "`nScript finished. Disconnecting from Microsoft Graph." -ForegroundColor Cyan }
Disconnect-MgGraph -ErrorAction SilentlyContinue
