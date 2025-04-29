# Get-EntraConditionalAccessPolicies.ps1

## Overview

This PowerShell script connects to Microsoft Graph to retrieve and report on Entra ID (formerly Azure Active Directory) Conditional Access (CA) policies within your tenant. It provides detailed information about the configuration of each policy, including assignments (users, groups, roles, applications, conditions) and controls (grant, session).

The script offers options to display output directly in the console, resolve object IDs to display names (requires additional permissions), and export the collected data to either CSV or JSON format for further analysis or documentation.

## Features

* Retrieves all Conditional Access policies in the tenant.
* Displays detailed configuration for each policy in the console (can be suppressed).
* Optionally resolves User, Group, Role, Application, and Named Location IDs to their display names for better readability.
* Exports collected policy data to CSV or JSON file formats.
* Includes basic evaluation notes in the console output (e.g., policy state, MFA enforcement, block actions).
* Handles Microsoft Graph connection and authentication.
* Attempts to install required Microsoft Graph PowerShell SDK modules if missing (when `-ResolveNames` is used).
* Includes progress indication when running in quiet mode (`-Quiet`).

## Prerequisites

1.  **PowerShell:** PowerShell 5.1 or later (PowerShell 7+ recommended).
2.  **Microsoft Graph PowerShell SDK Modules:**
    * `Microsoft.Graph.Authentication`
    * `Microsoft.Graph.Identity.SignIns`
    * The following are required *only* if using the `-ResolveNames` parameter and will be installed automatically if missing (requires administrator privileges for installation if running PowerShell as non-admin):
        * `Microsoft.Graph.Users`
        * `Microsoft.Graph.Groups`
        * `Microsoft.Graph.Applications`
        * `Microsoft.Graph.DirectoryObjects` (for Role resolution)
3.  **Internet Connectivity:** Required to connect to Microsoft Graph and potentially download modules.
4.  **Execution Policy:** Your PowerShell execution policy must allow running local scripts (e.g., `RemoteSigned` or `Unrestricted`). You can check with `Get-ExecutionPolicy` and set it using `Set-ExecutionPolicy` (requires administrator privileges).

## Permissions

The script requires an Entra ID account with permissions to read Conditional Access policies and potentially other directory objects if resolving names. Assign one of the following roles (using least privilege principle):

* **Basic Read:** `Security Reader` or `Global Reader` (Sufficient if *not* using `-ResolveNames`).
* **With Name Resolution (`-ResolveNames`):** Requires broader read permissions. `Security Reader` or `Global Reader` **plus** permissions typically granted by roles like `Directory Reader` are needed to resolve Users, Groups, Applications, and Roles. The specific Graph API permissions requested by the script are:
    * `Policy.Read.All` (Core requirement)
    * `Directory.Read.All` (For Users, Groups)
    * `Application.Read.All` (For Applications/Service Principals)
    * `RoleManagement.Read.Directory` (For Directory Roles)

*Note: Roles like `Conditional Access Administrator` or `Global Administrator` also work but grant more permissions than necessary for reading.*

## Parameters

* `[-ResolveNames]`
    * Optional switch. If present, the script attempts to resolve IDs for Users, Groups, Roles, Applications, and Named Locations to their display names.
    * Increases script execution time, especially in large tenants.
    * Requires additional permissions (see Permissions section).
    * Requires additional Graph SDK modules.
* `[-OutputFile <String>]`
    * Optional. Specifies the full path (including filename) for the exported data file (e.g., `C:\Temp\CAPolicies.csv`).
    * If provided, the script will export the collected data.
* `[-OutputFormat <String>]`
    * Optional. Specifies the format for the exported file.
    * Valid values: `CSV` (Default), `JSON`.
    * Only used if `-OutputFile` is specified.
* `[-Quiet]`
    * Optional switch. If present, suppresses the detailed policy-by-policy output to the console during processing.
    * Error messages and final summary/export messages will still be displayed.
    * Shows a progress bar during policy processing.

## Usage Examples

```powershell
# Example 1: Display policy details in the console only
.\Get-EntraConditionalAccessPolicies.ps1

# Example 2: Display details and resolve names in the console
.\Get-EntraConditionalAccessPolicies.ps1 -ResolveNames

# Example 3: Export policies to a CSV file (default format) in the current directory
.\Get-EntraConditionalAccessPolicies.ps1 -OutputFile .\EntraCAPolicies.csv

# Example 4: Export policies to a JSON file in a specific directory
.\Get-EntraConditionalAccessPolicies.ps1 -OutputFile "C:\Exports\EntraCAPolicies.json" -OutputFormat JSON

# Example 5: Export policies to CSV, resolve names, and suppress console processing details
.\Get-EntraConditionalAccessPolicies.ps1 -OutputFile "C:\Exports\EntraCAPolicies_Resolved.csv" -ResolveNames -Quiet

# Example 6: Run with verbose output for troubleshooting connection/resolution
.\Get-EntraConditionalAccessPolicies.ps1 -Verbose
