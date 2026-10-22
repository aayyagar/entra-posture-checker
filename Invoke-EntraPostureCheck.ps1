#Requires -Version 5.1
<#
.SYNOPSIS
    Entra ID Security Posture Checker - read-only identity security assessment for Microsoft Entra ID.

.DESCRIPTION
    Connects to Microsoft Graph with READ-ONLY permissions, collects identity configuration from a
    Microsoft Entra ID tenant, runs 23 security checks, and produces a scored HTML report plus JSON
    and CSV exports.

    Check categories
      Baseline              Security defaults / Conditional Access present
      MFA                   Admin and user MFA registration, phishing-resistant methods for admins
      Conditional Access    Legacy auth block, MFA for all users and admins, risk policies, policy hygiene
      Privileged Access     Global Admin count, standing (permanent) access, guests in roles, inactive admins
      Accounts & Guests     Stale members and guests, pending invitations, invite and guest access settings
      Applications          App registration, user consent, expiring and long-lived secrets, risky Graph permissions

    The script never writes to the tenant. Every Graph call is an HTTP GET.

    Run with -Demo to generate a report from a built-in sample tenant (no Graph connection needed).

.PARAMETER TenantId
    Tenant ID or domain to connect to. Optional; defaults to the account's home tenant.

.PARAMETER OutputPath
    Folder for the HTML, JSON and CSV output. Created if missing.

.PARAMETER StaleDays
    Days without sign-in before an account counts as stale. Default 90.

.PARAMETER SecretExpiryWarningDays
    Flag app secrets and certificates expiring within this many days. Default 30.

.PARAMETER Demo
    Use the built-in sample tenant instead of connecting to Microsoft Graph.

.PARAMETER UseExistingConnection
    Reuse an existing Connect-MgGraph session instead of starting a new one.

.PARAMETER NoDisconnect
    Leave the Graph session connected when the script finishes.

.EXAMPLE
    .\Invoke-EntraPostureCheck.ps1 -Demo
    Generates a sample report from the built-in demo tenant.

.EXAMPLE
    .\Invoke-EntraPostureCheck.ps1 -TenantId contoso.onmicrosoft.com -StaleDays 60
    Signs in interactively and assesses the contoso tenant.

.NOTES
    Author   : Akhilesh Ayyagari  (github.com/aayyagar)
    Version  : 1.0.0
    Requires : PowerShell 5.1 or 7+, module Microsoft.Graph.Authentication (not needed for -Demo)
    Scopes   : Directory.Read.All, Policy.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All,
               UserAuthenticationMethod.Read.All, Application.Read.All  (all read-only, delegated)
    Licenses : Sign-in activity and MFA registration data need Entra ID P1. PIM and risk policies need P2.
               Checks whose data is unavailable are reported as Skipped and do not affect the score.
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath 'EntraPostureReport'),
    [ValidateRange(7, 730)][int]$StaleDays = 90,
    [ValidateRange(1, 365)][int]$SecretExpiryWarningDays = 30,
    [switch]$Demo,
    [switch]$UseExistingConnection,
    [switch]$NoDisconnect
)

$ErrorActionPreference = 'Stop'
$Script:Version = '1.0.0'
$Script:Now = [datetime]::UtcNow

# ---------------------------------------------------------------------------------------------
#  Reference data
# ---------------------------------------------------------------------------------------------
$Script:GlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'

$Script:PrivilegedRoles = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Security Administrator', 'Conditional Access Administrator', 'Exchange Administrator',
    'SharePoint Administrator', 'User Administrator', 'Application Administrator',
    'Cloud Application Administrator', 'Authentication Administrator', 'Hybrid Identity Administrator',
    'Intune Administrator', 'Helpdesk Administrator', 'Billing Administrator', 'Teams Administrator'
)

$Script:PhishingResistantMethods = @(
    'fido2', 'windowsHelloForBusiness', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator',
    'passKeyDeviceBoundWindowsHello', 'x509CertificateMultiFactor'
)

# Graph application permissions that allow a path to tenant takeover
$Script:Tier0GraphPermissions = @(
    'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All',
    'Application.ReadWrite.All', 'Directory.ReadWrite.All'
)
# Broad data-access permissions worth reviewing
$Script:SensitiveGraphPermissions = @(
    'User.ReadWrite.All', 'Group.ReadWrite.All', 'Mail.ReadWrite', 'Mail.Send', 'Files.ReadWrite.All',
    'Sites.FullControl.All', 'Sites.ReadWrite.All', 'UserAuthenticationMethod.ReadWrite.All',
    'Policy.ReadWrite.ConditionalAccess'
)

$Script:SeverityWeight = @{ Critical = 10; High = 7; Medium = 4; Low = 2 }

$Script:GuestRoleNames = @{
    'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'Same access as members'
    '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'Limited access (default)'
    '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'Restricted access'
}

# ---------------------------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------------------------
function Write-Step {
    param([string]$Message)
    Write-Host ('  > ' + $Message) -ForegroundColor Cyan
}

function ConvertTo-UtcDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try {
        return [datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
    } catch { return $null }
}

function Get-Prop {
    # Safe nested property read: Get-Prop $obj 'a.b.c'
    param($Object, [string]$Path)
    $cur = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $cur = $cur[$part] }
        else {
            $p = $cur.PSObject.Properties[$part]
            if ($null -eq $p) { return $null }
            $cur = $p.Value
        }
    }
    return $cur
}

function As-Array {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value)
}

function Invoke-GraphGet {
    param([string]$Uri)
    Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
}

function Invoke-GraphPaged {
    param([string]$Uri)
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        foreach ($v in (As-Array (Get-Prop $resp 'value'))) { $items.Add($v) }
        $next = Get-Prop $resp '@odata.nextLink'
    }
    return , $items.ToArray()
}

function Try-Collect {
    # Runs a collection block; returns $null and records a warning when it fails (license, permission)
    param([string]$Name, [scriptblock]$Block)
    try { return (& $Block) }
    catch {
        $msg = $_.Exception.Message
        if ($msg.Length -gt 160) { $msg = $msg.Substring(0, 160) + '...' }
        $Script:CollectionWarnings.Add("$Name unavailable: $msg")
        Write-Host ("    ! $Name unavailable (" + $msg + ')') -ForegroundColor DarkYellow
        return $null
    }
}

function New-Result {
    param(
        [ValidateSet('Pass', 'Warn', 'Fail', 'Skipped')][string]$Status,
        [string]$Finding,
        [string]$Recommendation = '',
        [object[]]$Evidence = @()
    )
    [pscustomobject]@{ Status = $Status; Finding = $Finding; Recommendation = $Recommendation; Evidence = @($Evidence) }
}

function Get-Pct {
    param([double]$Part, [double]$Total)
    if ($Total -le 0) { return 100 }
    return [math]::Round(($Part / $Total) * 100, 1)
}

function Format-Days {
    param($Date)
    if ($null -eq $Date) { return 'never' }
    $d = [int][math]::Floor(($Script:Now - $Date).TotalDays)
    return "$d days ago"
}

# ---------------------------------------------------------------------------------------------
#  Data collection (Microsoft Graph, GET only)
# ---------------------------------------------------------------------------------------------
function Get-TenantData {
    $D = @{}
    $Script:CollectionWarnings = New-Object System.Collections.Generic.List[string]

    Write-Step 'Tenant details'
    $org = (Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains')[0]
    $D.TenantName = $org.displayName
    $D.TenantId = $org.id
    $D.PrimaryDomain = (As-Array $org.verifiedDomains | Where-Object { $_.isDefault } | Select-Object -First 1).name

    Write-Step 'Users and sign-in activity'
    $sel = 'id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,externalUserState,externalUserStateChangeDateTime'
    $rawUsers = Try-Collect 'Sign-in activity' { Invoke-GraphPaged ("https://graph.microsoft.com/v1.0/users?`$top=999&`$select=$sel,signInActivity") }
    $D.SignInDataAvailable = $null -ne $rawUsers
    if (-not $D.SignInDataAvailable) {
        $rawUsers = Invoke-GraphPaged ("https://graph.microsoft.com/v1.0/users?`$top=999&`$select=$sel")
    }
    $D.Users = foreach ($u in $rawUsers) {
        $last = $null
        $sia = Get-Prop $u 'signInActivity'
        if ($sia) {
            $dates = @(
                (ConvertTo-UtcDate (Get-Prop $sia 'lastSignInDateTime')),
                (ConvertTo-UtcDate (Get-Prop $sia 'lastNonInteractiveSignInDateTime')),
                (ConvertTo-UtcDate (Get-Prop $sia 'lastSuccessfulSignInDateTime'))
            ) | Where-Object { $_ }
            if ($dates) { $last = ($dates | Sort-Object -Descending)[0] }
        }
        [pscustomobject]@{
            Id = $u.id; Upn = $u.userPrincipalName; DisplayName = $u.displayName
            UserType = if ($u.userType) { $u.userType } else { 'Member' }
            Enabled = [bool]$u.accountEnabled
            Created = ConvertTo-UtcDate $u.createdDateTime
            LastSignIn = $last
            ExternalState = $u.externalUserState
            ExternalStateChanged = ConvertTo-UtcDate $u.externalUserStateChangeDateTime
        }
    }

    Write-Step 'MFA registration details'
    $reg = Try-Collect 'MFA registration report' { Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999' }
    $D.RegistrationAvailable = $null -ne $reg
    $D.Registration = @{}
    foreach ($r in (As-Array $reg)) {
        $D.Registration[$r.id] = [pscustomobject]@{
            Upn = $r.userPrincipalName; IsMfaRegistered = [bool]$r.isMfaRegistered
            Methods = @(As-Array $r.methodsRegistered)
        }
    }

    Write-Step 'Conditional Access and security defaults'
    $ca = Try-Collect 'Conditional Access policies' { Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' }
    $D.CAAvailable = $null -ne $ca
    $D.CAPolicies = @(As-Array $ca)
    $sd = Try-Collect 'Security defaults' { Invoke-GraphGet 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' }
    $D.SecurityDefaults = if ($sd) { [bool]$sd.isEnabled } else { $null }

    Write-Step 'Authorization policy'
    $D.AuthPolicy = Try-Collect 'Authorization policy' { Invoke-GraphGet 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' }

    Write-Step 'Directory roles and PIM'
    $defs = Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId'
    $roleName = @{}
    foreach ($r in $defs) { $roleName[$r.id] = $r.displayName; if ($r.templateId) { $roleName[$r.templateId] = $r.displayName } }

    $principalCache = @{}
    foreach ($u in $D.Users) { $principalCache[$u.Id] = [pscustomobject]@{ Name = $u.Upn; Type = 'user'; UserType = $u.UserType } }
    $resolve = {
        param($id)
        if (-not $principalCache.ContainsKey($id)) {
            $obj = $null
            try { $obj = Invoke-GraphGet "https://graph.microsoft.com/v1.0/directoryObjects/$id" } catch { }
            $type = if ($obj) { ("" + (Get-Prop $obj '@odata.type')).Replace('#microsoft.graph.', '') } else { 'unknown' }
            $name = if ($obj -and $obj.displayName) { $obj.displayName } else { $id }
            $principalCache[$id] = [pscustomobject]@{ Name = $name; Type = $type; UserType = $null }
        }
        $principalCache[$id]
    }

    $instances = Try-Collect 'PIM assignment schedules' { Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances' }
    $D.PimAvailable = $null -ne $instances
    if (-not $D.PimAvailable) {
        $instances = foreach ($a in (Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments')) {
            [pscustomobject]@{ principalId = $a.principalId; roleDefinitionId = $a.roleDefinitionId; assignmentType = 'Assigned'; endDateTime = $null }
        }
    }
    $D.Assignments = foreach ($a in (As-Array $instances)) {
        $p = & $resolve $a.principalId
        $end = ConvertTo-UtcDate $a.endDateTime
        $kind = if ($a.assignmentType -eq 'Activated') { 'Activated' } elseif ($null -eq $end) { 'Permanent' } else { 'TimeBound' }
        [pscustomobject]@{
            PrincipalId = $a.principalId; PrincipalName = $p.Name; PrincipalType = $p.Type; UserType = $p.UserType
            RoleName = $roleName[$a.roleDefinitionId]; RoleId = $a.roleDefinitionId; Kind = $kind; End = $end
        }
    }

    $eligible = if ($D.PimAvailable) { Try-Collect 'PIM eligibility' { Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules' } } else { $null }
    $D.Eligible = foreach ($e in (As-Array $eligible)) {
        $p = & $resolve $e.principalId
        [pscustomobject]@{
            PrincipalId = $e.principalId; PrincipalName = $p.Name; PrincipalType = $p.Type; UserType = $p.UserType
            RoleName = $roleName[$e.roleDefinitionId]; RoleId = $e.roleDefinitionId
        }
    }

    Write-Step 'App registrations and credentials'
    $apps = Try-Collect 'App registrations' { Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/applications?$top=999&$select=id,appId,displayName,passwordCredentials,keyCredentials' }
    $D.AppsAvailable = $null -ne $apps
    $D.Apps = foreach ($a in (As-Array $apps)) {
        $creds = @()
        foreach ($c in (As-Array $a.passwordCredentials)) {
            $creds += [pscustomobject]@{ Type = 'Secret'; Name = $c.displayName; Start = ConvertTo-UtcDate $c.startDateTime; End = ConvertTo-UtcDate $c.endDateTime }
        }
        foreach ($c in (As-Array $a.keyCredentials)) {
            $creds += [pscustomobject]@{ Type = 'Certificate'; Name = $c.displayName; Start = ConvertTo-UtcDate $c.startDateTime; End = ConvertTo-UtcDate $c.endDateTime }
        }
        [pscustomobject]@{ Name = $a.displayName; AppId = $a.appId; Credentials = $creds }
    }

    Write-Step 'Microsoft Graph application permissions'
    $D.GraphPerms = Try-Collect 'Graph application permissions' {
        $graphSp = (Invoke-GraphPaged "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles")[0]
        $roleValue = @{}
        foreach ($r in (As-Array $graphSp.appRoles)) { $roleValue[$r.id] = $r.value }
        foreach ($g in (Invoke-GraphPaged "https://graph.microsoft.com/v1.0/servicePrincipals/$($graphSp.id)/appRoleAssignedTo?`$top=999")) {
            if ($g.principalType -eq 'ServicePrincipal') {
                [pscustomobject]@{ App = $g.principalDisplayName; Permission = $roleValue[$g.appRoleId] }
            }
        }
    }
    $D.GraphPermsAvailable = $null -ne $D.GraphPerms
    $D.GraphPerms = @(As-Array $D.GraphPerms)

    $D.Warnings = @($Script:CollectionWarnings)
    return $D
}

# ---------------------------------------------------------------------------------------------
#  Demo tenant (synthetic data, no connection)
# ---------------------------------------------------------------------------------------------
function Get-DemoTenantData {
    $rnd = New-Object System.Random 42
    $now = $Script:Now
    $D = @{
        TenantName = 'Contoso Demo'; TenantId = '00000000-0000-0000-0000-00000000demo'; PrimaryDomain = 'contoso-demo.onmicrosoft.com'
        SignInDataAvailable = $true; RegistrationAvailable = $true; CAAvailable = $true; SecurityDefaults = $false
        PimAvailable = $true; AppsAvailable = $true; GraphPermsAvailable = $true
        Warnings = @('Demo mode: all data is synthetic and generated locally.')
    }
    $first = 'alex', 'blair', 'casey', 'dana', 'eli', 'farah', 'gus', 'hana', 'ivan', 'jade', 'kai', 'lena', 'milo', 'nia', 'omar', 'priya', 'quinn', 'rosa', 'sam', 'tara', 'umar', 'vera', 'wes', 'xena', 'yuri', 'zoe'
    $last = 'adams', 'brooks', 'chen', 'diaz', 'evans', 'fox', 'gupta', 'hill'
    $users = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($f in $first) {
        foreach ($l in $last[0..1]) {
            $i++
            $days = $rnd.Next(0, 40)
            if ($i % 13 -eq 0) { $days = $rnd.Next(120, 400) }   # a few stale members
            $users.Add([pscustomobject]@{
                    Id = "u$i"; Upn = "$f.$l@contoso-demo.com"; DisplayName = "$f $l"; UserType = 'Member'; Enabled = $true
                    Created = $now.AddDays( - $rnd.Next(200, 1500)); LastSignIn = $now.AddDays( - $days); ExternalState = $null; ExternalStateChanged = $null
                })
        }
    }
    $named = @(
        @('a1', 'admin.alex@contoso-demo.com', 5), @('a2', 'admin.blair@contoso-demo.com', 2), @('a3', 'legacy.admin@contoso-demo.com', 210),
        @('bg1', 'breakglass01@contoso-demo.com', 400), @('bg2', 'breakglass02@contoso-demo.com', 400),
        @('a4', 'secops.casey@contoso-demo.com', 1), @('a5', 'helpdesk.dana@contoso-demo.com', 3)
    )
    foreach ($n in $named) {
        $users.Add([pscustomobject]@{ Id = $n[0]; Upn = $n[1]; DisplayName = $n[1].Split('@')[0]; UserType = 'Member'; Enabled = $true; Created = $now.AddDays(-900); LastSignIn = $now.AddDays( - $n[2]); ExternalState = $null; ExternalStateChanged = $null })
    }
    $guests = @(
        @('g1', 'partner.ext_fabrikam.com#EXT#@contoso-demo.com', 12, 'Accepted'), @('g2', 'consultant_tailspin.com#EXT#@contoso-demo.com', 160, 'Accepted'),
        @('g3', 'auditor_northwind.com#EXT#@contoso-demo.com', 300, 'Accepted'), @('g4', 'vendor_adatum.com#EXT#@contoso-demo.com', $null, 'PendingAcceptance'),
        @('g5', 'temp_litware.com#EXT#@contoso-demo.com', $null, 'PendingAcceptance'), @('g6', 'design_woodgrove.com#EXT#@contoso-demo.com', 20, 'Accepted'),
        @('g7', 'legal_proseware.com#EXT#@contoso-demo.com', 95, 'Accepted')
    )
    foreach ($g in $guests) {
        $ls = if ($null -ne $g[2]) { $now.AddDays( - $g[2]) } else { $null }
        $users.Add([pscustomobject]@{ Id = $g[0]; Upn = $g[1]; DisplayName = $g[1].Split('_')[0]; UserType = 'Guest'; Enabled = $true; Created = $now.AddDays(-120); LastSignIn = $ls; ExternalState = $g[3]; ExternalStateChanged = $now.AddDays(-110) })
    }
    $users.Add([pscustomobject]@{ Id = 'u-off'; Upn = 'former.employee@contoso-demo.com'; DisplayName = 'former employee'; UserType = 'Member'; Enabled = $false; Created = $now.AddDays(-1000); LastSignIn = $now.AddDays(-300); ExternalState = $null; ExternalStateChanged = $null })
    $D.Users = $users.ToArray()

    $D.Registration = @{}
    foreach ($u in $D.Users) {
        if ($u.UserType -ne 'Member') { continue }
        $reg = ($rnd.NextDouble() -gt 0.12)
        $methods = if ($reg) { @('microsoftAuthenticatorPush', 'softwareOneTimePasscode') } else { @() }
        if ($u.Id -in 'a1', 'a4') { $reg = $true; $methods = @('fido2', 'microsoftAuthenticatorPush') }
        if ($u.Id -in 'a2', 'a5', 'bg1', 'bg2') { $reg = $true; $methods = @('microsoftAuthenticatorPush') }
        if ($u.Id -eq 'bg1' -or $u.Id -eq 'bg2') { $methods = @('fido2') }
        if ($u.Id -eq 'a3') { $reg = $false; $methods = @() }
        $D.Registration[$u.Id] = [pscustomobject]@{ Upn = $u.Upn; IsMfaRegistered = $reg; Methods = $methods }
    }

    $ga = $Script:GlobalAdminTemplateId
    $mk = { param($pid_, $name, $role, $kind, $ut) [pscustomobject]@{ PrincipalId = $pid_; PrincipalName = $name; PrincipalType = 'user'; UserType = $ut; RoleName = $role; RoleId = ''; Kind = $kind; End = $null } }
    $D.Assignments = @(
        (& $mk 'bg1' 'breakglass01@contoso-demo.com' 'Global Administrator' 'Permanent' 'Member'),
        (& $mk 'bg2' 'breakglass02@contoso-demo.com' 'Global Administrator' 'Permanent' 'Member'),
        (& $mk 'a3' 'legacy.admin@contoso-demo.com' 'Global Administrator' 'Permanent' 'Member'),
        (& $mk 'a2' 'admin.blair@contoso-demo.com' 'Exchange Administrator' 'Permanent' 'Member'),
        (& $mk 'a5' 'helpdesk.dana@contoso-demo.com' 'Helpdesk Administrator' 'Permanent' 'Member'),
        (& $mk 'g1' 'partner.ext_fabrikam.com#EXT#@contoso-demo.com' 'Helpdesk Administrator' 'Permanent' 'Guest'),
        (& $mk 'a1' 'admin.alex@contoso-demo.com' 'Global Administrator' 'Activated' 'Member')
    )
    $D.Eligible = @(
        [pscustomobject]@{ PrincipalId = 'a1'; PrincipalName = 'admin.alex@contoso-demo.com'; PrincipalType = 'user'; UserType = 'Member'; RoleName = 'Global Administrator'; RoleId = $ga },
        [pscustomobject]@{ PrincipalId = 'a2'; PrincipalName = 'admin.blair@contoso-demo.com'; PrincipalType = 'user'; UserType = 'Member'; RoleName = 'Global Administrator'; RoleId = $ga },
        [pscustomobject]@{ PrincipalId = 'a4'; PrincipalName = 'secops.casey@contoso-demo.com'; PrincipalType = 'user'; UserType = 'Member'; RoleName = 'Security Administrator'; RoleId = '' }
    )

    $pol = {
        param($name, $state, $users, $roles, $apps, $clients, $grant, $strength, $signInRisk, $userRisk, $modifiedDays, $excl)
        [pscustomobject]@{
            displayName = $name; state = $state; modifiedDateTime = $now.AddDays( - $modifiedDays)
            conditions = [pscustomobject]@{
                users = [pscustomobject]@{ includeUsers = $users; includeRoles = $roles; excludeUsers = $excl; excludeGroups = @() }
                applications = [pscustomobject]@{ includeApplications = $apps }
                clientAppTypes = $clients; signInRiskLevels = $signInRisk; userRiskLevels = $userRisk
            }
            grantControls = [pscustomobject]@{ builtInControls = $grant; authenticationStrength = $strength }
        }
    }
    $D.CAPolicies = @(
        (& $pol 'CA001 - Block legacy authentication' 'enabled' @('All') @() @('All') @('exchangeActiveSync', 'other') @('block') $null @() @() 200 @('bg1', 'bg2')),
        (& $pol 'CA002 - Require MFA for administrators' 'enabled' @() @($ga, '194ae4cb-b126-40b2-bd5b-6091b380977d') @('All') @('all') @('mfa') $null @() @() 150 @('bg1', 'bg2')),
        (& $pol 'CA003 - Require MFA for all users' 'enabledForReportingButNotEnforced' @('All') @() @('All') @('all') @('mfa') $null @() @() 75 @('bg1', 'bg2')),
        (& $pol 'CA004 - High sign-in risk requires MFA' 'enabled' @('All') @() @('All') @('all') @('mfa') $null @('high') @() 90 @('bg1', 'bg2')),
        (& $pol 'CA099 - OLD block countries' 'disabled' @('All') @() @('All') @('all') @('block') $null @() @() 400 @())
    )

    $D.AuthPolicy = [pscustomobject]@{
        allowInvitesFrom = 'adminsGuestInvitersAndAllMembers'
        guestUserRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3'
        defaultUserRolePermissions = [pscustomobject]@{
            allowedToCreateApps = $true
            permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low')
        }
    }

    $cred = { param($type, $startDays, $endDays) [pscustomobject]@{ Type = $type; Name = "$type"; Start = $now.AddDays($startDays); End = $now.AddDays($endDays) } }
    $D.Apps = @(
        [pscustomobject]@{ Name = 'HR Sync Connector'; AppId = 'demo-1'; Credentials = @((& $cred 'Secret' -170 12)) },
        [pscustomobject]@{ Name = 'Legacy Reporting'; AppId = 'demo-2'; Credentials = @((& $cred 'Secret' -400 -35)) },
        [pscustomobject]@{ Name = 'Backup Automation'; AppId = 'demo-3'; Credentials = @((& $cred 'Secret' -30 700)) },
        [pscustomobject]@{ Name = 'Ticketing Integration'; AppId = 'demo-4'; Credentials = @((& $cred 'Certificate' -60 300)) },
        [pscustomobject]@{ Name = 'Directory Sync Tool'; AppId = 'demo-5'; Credentials = @((& $cred 'Secret' -90 90)) }
    )
    $D.GraphPerms = @(
        [pscustomobject]@{ App = 'Directory Sync Tool'; Permission = 'Directory.ReadWrite.All' },
        [pscustomobject]@{ App = 'Mail Archiver'; Permission = 'Mail.ReadWrite' },
        [pscustomobject]@{ App = 'HR Sync Connector'; Permission = 'User.Read.All' },
        [pscustomobject]@{ App = 'Ticketing Integration'; Permission = 'Group.Read.All' }
    )
    return $D
}

# ---------------------------------------------------------------------------------------------
#  Derived views used by several checks
# ---------------------------------------------------------------------------------------------
function Get-AdminUsers {
    param($D)
    $ids = @{}
    foreach ($a in @(As-Array $D.Assignments) + @(As-Array $D.Eligible)) {
        if ($a.PrincipalType -eq 'user' -and $Script:PrivilegedRoles -contains $a.RoleName) {
            if (-not $ids.ContainsKey($a.PrincipalId)) { $ids[$a.PrincipalId] = New-Object System.Collections.Generic.List[string] }
            if (-not $ids[$a.PrincipalId].Contains($a.RoleName)) { $ids[$a.PrincipalId].Add($a.RoleName) }
        }
    }
    $byId = @{}; foreach ($u in $D.Users) { $byId[$u.Id] = $u }
    foreach ($k in $ids.Keys) {
        $u = $byId[$k]
        [pscustomobject]@{
            Id = $k; Upn = if ($u) { $u.Upn } else { $k }; User = $u
            Roles = ($ids[$k] | Sort-Object) -join ', '
        }
    }
}

function Get-EnabledCA { param($D) @(As-Array $D.CAPolicies | Where-Object { $_.state -eq 'enabled' }) }
function Test-CAAllUsers { param($p) (As-Array (Get-Prop $p 'conditions.users.includeUsers')) -contains 'All' }
function Test-CAAllApps { param($p) (As-Array (Get-Prop $p 'conditions.applications.includeApplications')) -contains 'All' }
function Test-CAMfa {
    param($p)
    ((As-Array (Get-Prop $p 'grantControls.builtInControls')) -contains 'mfa') -or ($null -ne (Get-Prop $p 'grantControls.authenticationStrength'))
}
function Test-CABlock { param($p) (As-Array (Get-Prop $p 'grantControls.builtInControls')) -contains 'block' }
function Get-CAExclusions {
    param($p)
    $n = (As-Array (Get-Prop $p 'conditions.users.excludeUsers')).Count + (As-Array (Get-Prop $p 'conditions.users.excludeGroups')).Count
    if ($n -gt 0) { " (excludes $n user/group object(s) - confirm these are break-glass accounts)" } else { '' }
}

function Get-StaleUsers {
    param($D, [string]$Type)
    $cut = $Script:Now.AddDays( - $StaleDays)
    @($D.Users | Where-Object {
            $_.Enabled -and $_.UserType -eq $Type -and $_.ExternalState -ne 'PendingAcceptance' -and
            (($null -ne $_.LastSignIn -and $_.LastSignIn -lt $cut) -or ($null -eq $_.LastSignIn -and $_.Created -and $_.Created -lt $cut))
        })
}

# ---------------------------------------------------------------------------------------------
#  Checks
# ---------------------------------------------------------------------------------------------
$Script:Checks = @(

    @{ Id = 'BAS-01'; Category = 'Baseline'; Severity = 'Critical'; Title = 'Security defaults or Conditional Access is enforced'
        Test = {
            param($D)
            $enabled = Get-EnabledCA $D
            if ($D.SecurityDefaults) { return New-Result Pass 'Security defaults are enabled.' 'Consider moving to Conditional Access for granular control as the tenant grows.' }
            if (-not $D.CAAvailable) { return New-Result Skipped 'Conditional Access data could not be read.' }
            if ($enabled.Count -gt 0) { return New-Result Pass "$($enabled.Count) Conditional Access policies are enforced." }
            New-Result Fail 'Neither security defaults nor any enforced Conditional Access policy was found. Sign-ins are protected by password only.' 'Enable security defaults immediately, or deploy Conditional Access policies for MFA and legacy auth blocking.'
        }
    }

    @{ Id = 'MFA-01'; Category = 'MFA'; Severity = 'Critical'; Title = 'All privileged users are registered for MFA'
        Test = {
            param($D)
            if (-not $D.RegistrationAvailable) { return New-Result Skipped 'MFA registration report unavailable (needs Entra ID P1 and AuditLog.Read.All).' }
            $admins = @(Get-AdminUsers $D)
            if ($admins.Count -eq 0) { return New-Result Pass 'No user accounts hold privileged roles.' }
            $missing = @($admins | Where-Object { -not $D.Registration.ContainsKey($_.Id) -or -not $D.Registration[$_.Id].IsMfaRegistered })
            if ($missing.Count -eq 0) { return New-Result Pass "All $($admins.Count) privileged users are registered for MFA." }
            New-Result Fail "$($missing.Count) of $($admins.Count) privileged users have no MFA method registered." 'Require MFA registration for every admin before they can use their role. Block sign-in for admin accounts that cannot register.' ($missing | ForEach-Object { "$($_.Upn) - $($_.Roles)" })
        }
    }

    @{ Id = 'MFA-02'; Category = 'MFA'; Severity = 'High'; Title = 'Members are registered for MFA'
        Test = {
            param($D)
            if (-not $D.RegistrationAvailable) { return New-Result Skipped 'MFA registration report unavailable (needs Entra ID P1 and AuditLog.Read.All).' }
            $members = @($D.Users | Where-Object { $_.Enabled -and $_.UserType -eq 'Member' })
            $missing = @($members | Where-Object { -not $D.Registration.ContainsKey($_.Id) -or -not $D.Registration[$_.Id].IsMfaRegistered })
            $pct = Get-Pct ($members.Count - $missing.Count) $members.Count
            $ev = @($missing | Select-Object -First 25 | ForEach-Object { $_.Upn })
            if ($missing.Count -gt 25) { $ev += "...and $($missing.Count - 25) more (see CSV export)" }
            $text = "$pct% of $($members.Count) enabled members are registered for MFA ($($missing.Count) not registered)."
            $rec = 'Run an MFA registration campaign and enforce registration through Conditional Access or the authentication methods registration campaign.'
            if ($pct -ge 95) { return New-Result Pass $text '' $ev }
            if ($pct -ge 80) { return New-Result Warn $text $rec $ev }
            New-Result Fail $text $rec $ev
        }
    }

    @{ Id = 'MFA-03'; Category = 'MFA'; Severity = 'Medium'; Title = 'Admins use phishing-resistant authentication'
        Test = {
            param($D)
            if (-not $D.RegistrationAvailable) { return New-Result Skipped 'MFA registration report unavailable.' }
            $admins = @(Get-AdminUsers $D)
            if ($admins.Count -eq 0) { return New-Result Pass 'No user accounts hold privileged roles.' }
            $weak = @($admins | Where-Object {
                    $r = $D.Registration[$_.Id]
                    -not $r -or -not (@($r.Methods | Where-Object { $Script:PhishingResistantMethods -contains $_ }).Count)
                })
            $ok = $admins.Count - $weak.Count
            $text = "$ok of $($admins.Count) privileged users have a phishing-resistant method (FIDO2, passkey, Windows Hello for Business or certificate)."
            $rec = 'Issue FIDO2 keys or passkeys to admins and require a phishing-resistant authentication strength for admin roles.'
            $ev = @($weak | ForEach-Object { $_.Upn })
            if ($weak.Count -eq 0) { return New-Result Pass $text }
            if ($ok -gt 0) { return New-Result Warn $text $rec $ev }
            New-Result Fail $text $rec $ev
        }
    }

    @{ Id = 'CA-01'; Category = 'Conditional Access'; Severity = 'Critical'; Title = 'Legacy authentication is blocked'
        Test = {
            param($D)
            if ($D.SecurityDefaults) { return New-Result Pass 'Security defaults block legacy authentication.' }
            if (-not $D.CAAvailable) { return New-Result Skipped 'Conditional Access data could not be read.' }
            $hits = @(Get-EnabledCA $D | Where-Object { (Test-CABlock $_) -and (Test-CAAllUsers $_) })
            $full = @($hits | Where-Object { $t = As-Array (Get-Prop $_ 'conditions.clientAppTypes'); ($t -contains 'exchangeActiveSync') -and ($t -contains 'other') })
            $part = @($hits | Where-Object { $t = As-Array (Get-Prop $_ 'conditions.clientAppTypes'); ($t -contains 'exchangeActiveSync') -or ($t -contains 'other') })
            if ($full.Count) { return New-Result Pass ("Blocked by '" + $full[0].displayName + "'" + (Get-CAExclusions $full[0]) + '.') }
            if ($part.Count) { return New-Result Warn ("'" + $part[0].displayName + "' blocks only some legacy clients.") 'Include both Exchange ActiveSync clients and Other clients in the block policy.' }
            New-Result Fail 'No enforced policy blocks legacy authentication. Legacy protocols cannot do MFA and are the main target of password spray.' 'Create a Conditional Access policy for all users, client apps Exchange ActiveSync and Other clients, grant Block.'
        }
    }

    @{ Id = 'CA-02'; Category = 'Conditional Access'; Severity = 'High'; Title = 'MFA is required for all users'
        Test = {
            param($D)
            if ($D.SecurityDefaults) { return New-Result Warn 'Security defaults prompt for MFA when needed, but not on every sign-in.' 'Move to a Conditional Access policy requiring MFA for all users and all cloud apps.' }
            if (-not $D.CAAvailable) { return New-Result Skipped 'Conditional Access data could not be read.' }
            $hit = @(Get-EnabledCA $D | Where-Object { (Test-CAAllUsers $_) -and (Test-CAAllApps $_) -and (Test-CAMfa $_) -and -not (As-Array (Get-Prop $_ 'conditions.signInRiskLevels')).Count -and -not (As-Array (Get-Prop $_ 'conditions.userRiskLevels')).Count })
            if ($hit.Count) { return New-Result Pass ("Enforced by '" + $hit[0].displayName + "'" + (Get-CAExclusions $hit[0]) + '.') }
            $ro = @(As-Array $D.CAPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' -and (Test-CAAllUsers $_) -and (Test-CAMfa $_) })
            if ($ro.Count) { return New-Result Warn ("'" + $ro[0].displayName + "' exists but is in report-only mode, so it does not enforce MFA.") 'Review the report-only results in sign-in logs, then switch the policy to On.' }
            New-Result Fail 'No enforced policy requires MFA for all users and all cloud apps.' 'Create a Conditional Access policy: all users (exclude break-glass), all cloud apps, grant require MFA or an authentication strength.'
        }
    }

    @{ Id = 'CA-03'; Category = 'Conditional Access'; Severity = 'Critical'; Title = 'MFA is required for administrator roles'
        Test = {
            param($D)
            if ($D.SecurityDefaults) { return New-Result Pass 'Security defaults require MFA for administrators on every sign-in.' }
            if (-not $D.CAAvailable) { return New-Result Skipped 'Conditional Access data could not be read.' }
            $enabled = Get-EnabledCA $D
            $role = @($enabled | Where-Object { (Test-CAMfa $_) -and ((As-Array (Get-Prop $_ 'conditions.users.includeRoles')) -contains $Script:GlobalAdminTemplateId) })
            if ($role.Count) { return New-Result Pass ("Enforced by '" + $role[0].displayName + "'.") }
            $all = @($enabled | Where-Object { (Test-CAAllUsers $_) -and (Test-CAAllApps $_) -and (Test-CAMfa $_) -and -not (As-Array (Get-Prop $_ 'conditions.signInRiskLevels')).Count })
            if ($all.Count) { return New-Result Pass ("Covered by the all-users policy '" + $all[0].displayName + "'.") 'Add a dedicated admin policy with a phishing-resistant authentication strength.' }
            New-Result Fail 'No enforced policy requires MFA for Global Administrator and other admin roles.' 'Create a Conditional Access policy targeting admin directory roles with a phishing-resistant authentication strength.'
        }
    }

    @{ Id = 'CA-04'; Category = 'Conditional Access'; Severity = 'Medium'; Title = 'Risk-based policies are in place'
        Test = {
            param($D)
            if (-not $D.CAAvailable) { return New-Result Skipped 'Conditional Access data could not be read.' }
            $enabled = Get-EnabledCA $D
            $signIn = @($enabled | Where-Object { (As-Array (Get-Prop $_ 'conditions.signInRiskLevels')).Count })
            $user = @($enabled | Where-Object { (As-Array (Get-Prop $_ 'conditions.userRiskLevels')).Count })
            if ($signIn.Count -and $user.Count) { return New-Result Pass 'Both sign-in risk and user risk policies are enforced.' }
            $have = @(); if ($signIn.Count) { $have += 'sign-in risk' }; if ($user.Count) { $have += 'user risk' }
            $text = if ($have.Count) { "Only a $($have[0]) policy is enforced." } else { 'No sign-in risk or user risk policies are enforced.' }
            New-Result Warn $text 'With Entra ID P2, add policies requiring MFA for medium/high sign-in risk and a secure password change for high user risk.'
        }
    }

    @{ Id = 'CA-05'; Category = 'Conditional Access'; Severity = 'Low'; Title = 'No stale report-only or disabled policies'
        Test = {
            param($D)
            if (-not $D.CAAvailable) { return New-Result Skipped 'Conditional Access data could not be read.' }
            $cut = $Script:Now.AddDays(-30)
            $ro = @(As-Array $D.CAPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' -and (ConvertTo-UtcDate $_.modifiedDateTime) -lt $cut })
            $off = @(As-Array $D.CAPolicies | Where-Object { $_.state -eq 'disabled' })
            if (-not $ro.Count -and -not $off.Count) { return New-Result Pass 'Every Conditional Access policy is either enforced or recently changed.' }
            $ev = @($ro | ForEach-Object { "Report-only since " + (Format-Days (ConvertTo-UtcDate $_.modifiedDateTime)) + ": " + $_.displayName }) + @($off | ForEach-Object { 'Disabled: ' + $_.displayName })
            New-Result Warn "$($ro.Count) policies in report-only for 30+ days and $($off.Count) disabled." 'Promote report-only policies after review, and delete disabled policies you no longer need.' $ev
        }
    }

    @{ Id = 'PRV-01'; Category = 'Privileged Access'; Severity = 'High'; Title = 'Global Administrator count is between 2 and 4'
        Test = {
            param($D)
            $gas = @(@(As-Array $D.Assignments) + @(As-Array $D.Eligible) | Where-Object { $_.RoleName -eq 'Global Administrator' } | Sort-Object PrincipalId -Unique)
            $ev = @($gas | ForEach-Object { $_.PrincipalName })
            $text = "$($gas.Count) principals hold Global Administrator (active or eligible)."
            if ($gas.Count -ge 2 -and $gas.Count -le 4) { return New-Result Pass $text '' $ev }
            if ($gas.Count -lt 2) { return New-Result Warn $text 'Keep at least two Global Administrators, including a break-glass account, so you cannot be locked out.' $ev }
            New-Result Fail $text 'Reduce Global Administrators to 4 or fewer. Move day-to-day work to least-privileged roles such as User, Exchange or Security Administrator.' $ev
        }
    }

    @{ Id = 'PRV-02'; Category = 'Privileged Access'; Severity = 'High'; Title = 'Privileged roles use just-in-time access'
        Test = {
            param($D)
            $perm = @(As-Array $D.Assignments | Where-Object { $_.Kind -eq 'Permanent' -and $_.PrincipalType -eq 'user' -and $Script:PrivilegedRoles -contains $_.RoleName })
            $ev = @($perm | ForEach-Object { "$($_.PrincipalName) - $($_.RoleName)" })
            if (-not $D.PimAvailable) {
                if ($perm.Count -eq 0) { return New-Result Pass 'No standing privileged role assignments.' }
                return New-Result Warn "PIM data unavailable, so all $($perm.Count) privileged assignments are standing access." 'With Entra ID P2, convert standing admin assignments to PIM eligible assignments with approval and MFA on activation.' $ev
            }
            $text = "$($perm.Count) permanent active privileged assignments; $(@(As-Array $D.Eligible).Count) eligible (just-in-time) assignments."
            $rec = 'Convert permanent assignments to PIM eligible. Keep permanent Global Administrator only for 2 monitored break-glass accounts.'
            if ($perm.Count -le 2) { return New-Result Pass $text '' $ev }
            if ($perm.Count -le 5) { return New-Result Warn $text $rec $ev }
            New-Result Fail $text $rec $ev
        }
    }

    @{ Id = 'PRV-03'; Category = 'Privileged Access'; Severity = 'Critical'; Title = 'No guest accounts hold privileged roles'
        Test = {
            param($D)
            $g = @(@(As-Array $D.Assignments) + @(As-Array $D.Eligible) | Where-Object { $_.UserType -eq 'Guest' -and $Script:PrivilegedRoles -contains $_.RoleName })
            if ($g.Count -eq 0) { return New-Result Pass 'No guest accounts hold privileged directory roles.' }
            New-Result Fail "$($g.Count) privileged role assignments belong to guest accounts. Their security depends on another organization's controls." 'Remove privileged roles from guests. If an external admin is needed, issue a managed member account with MFA and PIM.' ($g | ForEach-Object { "$($_.PrincipalName) - $($_.RoleName)" })
        }
    }

    @{ Id = 'PRV-04'; Category = 'Privileged Access'; Severity = 'Medium'; Title = 'Privileged accounts are actively used'
        Test = {
            param($D)
            if (-not $D.SignInDataAvailable) { return New-Result Skipped 'Sign-in activity unavailable (needs Entra ID P1 and AuditLog.Read.All).' }
            $cut = $Script:Now.AddDays( - $StaleDays)
            $stale = @(Get-AdminUsers $D | Where-Object { $_.User -and ($null -eq $_.User.LastSignIn -or $_.User.LastSignIn -lt $cut) -and $_.Upn -notmatch 'break.?glass|emergency' })
            if ($stale.Count -eq 0) { return New-Result Pass "Every privileged account signed in within $StaleDays days (break-glass accounts excluded)." }
            New-Result Warn "$($stale.Count) privileged accounts have not signed in for $StaleDays+ days." 'Remove roles from unused admin accounts or disable them. Unused admins are prime takeover targets.' ($stale | ForEach-Object { "$($_.Upn) - last sign-in $(Format-Days $_.User.LastSignIn) - $($_.Roles)" })
        }
    }

    @{ Id = 'ACC-01'; Category = 'Accounts & Guests'; Severity = 'Medium'; Title = 'No stale member accounts'
        Test = {
            param($D)
            if (-not $D.SignInDataAvailable) { return New-Result Skipped 'Sign-in activity unavailable (needs Entra ID P1 and AuditLog.Read.All).' }
            $members = @($D.Users | Where-Object { $_.Enabled -and $_.UserType -eq 'Member' })
            $stale = @(Get-StaleUsers $D 'Member')
            $pct = Get-Pct $stale.Count $members.Count
            $ev = @($stale | Select-Object -First 25 | ForEach-Object { "$($_.Upn) - last sign-in $(Format-Days $_.LastSignIn)" })
            $text = "$($stale.Count) enabled members ($pct%) have not signed in for $StaleDays+ days."
            $rec = 'Review with managers and HR, then disable accounts that are no longer needed. Automate this with access reviews or a joiner-mover-leaver process.'
            if ($stale.Count -eq 0) { return New-Result Pass $text }
            if ($pct -le 5) { return New-Result Warn $text $rec $ev }
            New-Result Fail $text $rec $ev
        }
    }

    @{ Id = 'ACC-02'; Category = 'Accounts & Guests'; Severity = 'Medium'; Title = 'No stale guest accounts'
        Test = {
            param($D)
            if (-not $D.SignInDataAvailable) { return New-Result Skipped 'Sign-in activity unavailable (needs Entra ID P1 and AuditLog.Read.All).' }
            $guests = @($D.Users | Where-Object { $_.Enabled -and $_.UserType -eq 'Guest' })
            $stale = @(Get-StaleUsers $D 'Guest')
            $ev = @($stale | ForEach-Object { "$($_.Upn) - last sign-in $(Format-Days $_.LastSignIn)" })
            $text = "$($stale.Count) of $($guests.Count) guests have not signed in for $StaleDays+ days."
            if ($stale.Count -eq 0) { return New-Result Pass $text }
            New-Result Warn $text 'Set up a recurring guest access review and remove guests who no longer collaborate with you.' $ev
        }
    }

    @{ Id = 'ACC-03'; Category = 'Accounts & Guests'; Severity = 'Low'; Title = 'No long-pending guest invitations'
        Test = {
            param($D)
            $cut = $Script:Now.AddDays(-30)
            $p = @($D.Users | Where-Object { $_.UserType -eq 'Guest' -and $_.ExternalState -eq 'PendingAcceptance' -and $_.Created -and $_.Created -lt $cut })
            if ($p.Count -eq 0) { return New-Result Pass 'No guest invitations have been pending for more than 30 days.' }
            New-Result Warn "$($p.Count) guest invitations have been pending for 30+ days." 'Delete unredeemed invitations. An old invitation link can still be redeemed by whoever holds it.' ($p | ForEach-Object { "$($_.Upn) - invited $(Format-Days $_.Created)" })
        }
    }

    @{ Id = 'ACC-04'; Category = 'Accounts & Guests'; Severity = 'Medium'; Title = 'Guest invitations are restricted'
        Test = {
            param($D)
            if (-not $D.AuthPolicy) { return New-Result Skipped 'Authorization policy could not be read.' }
            $v = Get-Prop $D.AuthPolicy 'allowInvitesFrom'
            switch ($v) {
                'everyone' { return New-Result Fail 'Anyone in the organization, including guests, can invite new guests.' 'Limit invitations to admins and the Guest Inviter role in External collaboration settings.' }
                'adminsGuestInvitersAndAllMembers' { return New-Result Warn 'All members can invite guests.' 'Limit invitations to admins and users with the Guest Inviter role, or route requests through entitlement management.' }
                default { return New-Result Pass "Guest invitations are limited ($v)." }
            }
        }
    }

    @{ Id = 'ACC-05'; Category = 'Accounts & Guests'; Severity = 'Medium'; Title = 'Guest directory access is limited'
        Test = {
            param($D)
            if (-not $D.AuthPolicy) { return New-Result Skipped 'Authorization policy could not be read.' }
            $id = Get-Prop $D.AuthPolicy 'guestUserRoleId'
            $name = $Script:GuestRoleNames[$id]; if (-not $name) { $name = $id }
            if ($id -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970') { return New-Result Fail 'Guests have the same directory access as members and can enumerate users, groups and apps.' 'Set guest user access to Limited or Restricted in External collaboration settings.' }
            New-Result Pass "Guest access level: $name."
        }
    }

    @{ Id = 'APP-01'; Category = 'Applications'; Severity = 'Medium'; Title = 'Users cannot register applications'
        Test = {
            param($D)
            if (-not $D.AuthPolicy) { return New-Result Skipped 'Authorization policy could not be read.' }
            if (Get-Prop $D.AuthPolicy 'defaultUserRolePermissions.allowedToCreateApps') {
                return New-Result Warn 'Any user can create app registrations, which can be used to set up persistence or consent-phishing apps.' "Set 'Users can register applications' to No and grant the Application Developer role to those who need it."
            }
            New-Result Pass 'Only authorized roles can register applications.'
        }
    }

    @{ Id = 'APP-02'; Category = 'Applications'; Severity = 'High'; Title = 'User consent to apps is restricted'
        Test = {
            param($D)
            if (-not $D.AuthPolicy) { return New-Result Skipped 'Authorization policy could not be read.' }
            $p = @(As-Array (Get-Prop $D.AuthPolicy 'defaultUserRolePermissions.permissionGrantPoliciesAssigned'))
            if ($p -match 'microsoft-user-default-legacy') { return New-Result Fail 'Users can consent to any app requesting access to their data, the main enabler of consent phishing.' "Allow user consent only for verified publishers with low-impact permissions, and turn on the admin consent workflow." }
            if ($p -match 'microsoft-user-default-low') { return New-Result Pass 'Users can consent only to verified publishers requesting low-impact permissions.' }
            if ($p.Count -eq 0 -or -not ($p -match 'ManagePermissionGrantsForSelf')) { return New-Result Pass 'User consent is disabled; admins approve all app access.' 'Make sure the admin consent workflow is enabled so users have a way to request apps.' }
            New-Result Warn ('A custom consent policy is assigned: ' + ($p -join ', ')) 'Review the custom permission grant policy.'
        }
    }

    @{ Id = 'APP-03'; Category = 'Applications'; Severity = 'Medium'; Title = 'No expired or expiring app credentials'
        Test = {
            param($D)
            if (-not $D.AppsAvailable) { return New-Result Skipped 'App registrations could not be read.' }
            $soon = $Script:Now.AddDays($SecretExpiryWarningDays)
            $ev = @(); $exp = 0; $exps = 0
            foreach ($a in $D.Apps) {
                foreach ($c in $a.Credentials) {
                    if (-not $c.End) { continue }
                    if ($c.End -lt $Script:Now) { $exp++; $ev += "$($a.Name) - $($c.Type) expired $(Format-Days $c.End)" }
                    elseif ($c.End -lt $soon) { $exps++; $ev += "$($a.Name) - $($c.Type) expires in $([int]($c.End - $Script:Now).TotalDays) days" }
                }
            }
            if (-not $ev.Count) { return New-Result Pass "No app credentials expired or expiring within $SecretExpiryWarningDays days." }
            New-Result Warn "$exps credentials expire within $SecretExpiryWarningDays days and $exp have already expired." 'Rotate expiring credentials before they cause outages, and remove expired ones. Prefer certificates or managed identities over secrets.' $ev
        }
    }

    @{ Id = 'APP-04'; Category = 'Applications'; Severity = 'Low'; Title = 'App secrets are short-lived'
        Test = {
            param($D)
            if (-not $D.AppsAvailable) { return New-Result Skipped 'App registrations could not be read.' }
            $ev = @()
            foreach ($a in $D.Apps) {
                foreach ($c in $a.Credentials) {
                    if ($c.Type -eq 'Secret' -and $c.Start -and $c.End -and $c.End -gt $Script:Now -and ($c.End - $c.Start).TotalDays -gt 366) {
                        $ev += "$($a.Name) - secret valid for $([int](($c.End - $c.Start).TotalDays)) days"
                    }
                }
            }
            if (-not $ev.Count) { return New-Result Pass 'No active client secrets are valid for more than 12 months.' }
            New-Result Warn "$($ev.Count) active client secrets are valid for more than 12 months." 'Limit secret lifetime with an app management policy (for example 6 to 12 months), or switch to certificates or workload identity federation.' $ev
        }
    }

    @{ Id = 'APP-05'; Category = 'Applications'; Severity = 'High'; Title = 'No apps hold high-risk Microsoft Graph permissions'
        Test = {
            param($D)
            if (-not $D.GraphPermsAvailable) { return New-Result Skipped 'Graph application permissions could not be read.' }
            $t0 = @($D.GraphPerms | Where-Object { $Script:Tier0GraphPermissions -contains $_.Permission })
            $sens = @($D.GraphPerms | Where-Object { $Script:SensitiveGraphPermissions -contains $_.Permission })
            $ev = @($t0 | ForEach-Object { "TIER 0: $($_.App) - $($_.Permission)" }) + @($sens | ForEach-Object { "Sensitive: $($_.App) - $($_.Permission)" })
            if ($t0.Count) { return New-Result Fail "$($t0.Count) app permission grants allow a path to full tenant control, plus $($sens.Count) sensitive grants." 'Remove Tier 0 permissions or replace them with narrower ones. Protect these apps like Global Administrators: owners, credentials and sign-in monitoring.' $ev }
            if ($sens.Count) { return New-Result Warn "$($sens.Count) apps hold broad data-access permissions." 'Confirm each grant is still needed and scope it down (for example Sites.Selected or application access policies for mail).' $ev }
            New-Result Pass 'No service principals hold Tier 0 or broad data-access Graph permissions.'
        }
    }
)

# ---------------------------------------------------------------------------------------------
#  Scoring
# ---------------------------------------------------------------------------------------------
function Invoke-Checks {
    param($D)
    foreach ($c in $Script:Checks) {
        try { $r = & $c.Test $D }
        catch { $r = New-Result Skipped ("Check failed to run: " + $_.Exception.Message) }
        [pscustomobject]@{
            Id = $c.Id; Category = $c.Category; Title = $c.Title; Severity = $c.Severity
            Weight = $Script:SeverityWeight[$c.Severity]
            Status = $r.Status; Finding = $r.Finding; Recommendation = $r.Recommendation; Evidence = @($r.Evidence)
        }
    }
}

function Get-Score {
    param($Results)
    $factor = @{ Pass = 1.0; Warn = 0.5; Fail = 0.0 }
    $scored = @($Results | Where-Object { $factor.ContainsKey($_.Status) })
    $max = ($scored | Measure-Object Weight -Sum).Sum
    if (-not $max) { return 0 }
    $got = 0; foreach ($r in $scored) { $got += $r.Weight * $factor[$r.Status] }
    return [int][math]::Round(($got / $max) * 100)
}

function Get-Grade {
    param([int]$Score)
    if ($Score -ge 90) { 'A' } elseif ($Score -ge 80) { 'B' } elseif ($Score -ge 70) { 'C' } elseif ($Score -ge 60) { 'D' } else { 'F' }
}

# ---------------------------------------------------------------------------------------------
#  HTML report
# ---------------------------------------------------------------------------------------------
function ConvertTo-HtmlSafe { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

function New-HtmlReport {
    param($D, $Results, [int]$Score, [string]$Grade)
    $e = { param($s) ConvertTo-HtmlSafe $s }
    $sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $statOrder = @{ Fail = 0; Warn = 1; Pass = 2; Skipped = 3 }
    $sorted = $Results | Sort-Object @{ e = { $statOrder[$_.Status] } }, @{ e = { $sevOrder[$_.Severity] } }, Id

    $count = @{}; foreach ($s in 'Pass', 'Warn', 'Fail', 'Skipped') { $count[$s] = @($Results | Where-Object Status -eq $s).Count }
    $critFail = @($Results | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'Critical' }).Count
    $dash = [math]::Round(2 * [math]::PI * 52 * $Score / 100, 1)
    $ring = if ($Score -ge 80) { 'var(--pass)' } elseif ($Score -ge 60) { 'var(--warn)' } else { 'var(--fail)' }

    $cats = foreach ($cat in ($Results | Select-Object -ExpandProperty Category -Unique)) {
        $cr = @($Results | Where-Object Category -eq $cat)
        $cs = Get-Score $cr
        $p = @($cr | Where-Object Status -eq 'Pass').Count
        "<div class='cat'><div class='cat-h'><span>$(& $e $cat)</span><b>$cs</b></div><div class='trk'><div style='width:$cs%'></div></div><small>$p of $($cr.Count) checks passed</small></div>"
    }

    $rows = foreach ($r in $sorted) {
        $ev = ''
        if ($r.Evidence.Count) {
            $items = ($r.Evidence | Select-Object -First 50 | ForEach-Object { '<li>' + (& $e $_) + '</li>' }) -join ''
            $ev = "<div class='ev'><span class='lbl'>Evidence ($($r.Evidence.Count))</span><ul>$items</ul></div>"
        }
        $rec = if ($r.Recommendation) { "<div class='rec'><span class='lbl'>Recommendation</span><p>$(& $e $r.Recommendation)</p></div>" } else { '' }
        $open = if ($r.Status -eq 'Fail' -and $r.Severity -eq 'Critical') { ' open' } else { '' }
        @"
<details class='f $($r.Status.ToLower())' data-status='$($r.Status)'$open>
<summary><span class='st $($r.Status.ToLower())'>$($r.Status)</span><span class='id'>$($r.Id)</span><span class='t'>$(& $e $r.Title)</span><span class='sev $($r.Severity.ToLower())'>$($r.Severity)</span></summary>
<div class='body'><p class='fd'>$(& $e $r.Finding)</p>$rec$ev</div>
</details>
"@
    }

    $warn = ''
    if ($D.Warnings.Count) { $warn = "<div class='note'><b>Data notes</b><ul>" + (($D.Warnings | ForEach-Object { '<li>' + (& $e $_) + '</li>' }) -join '') + '</ul></div>' }

    $css = @'
:root{--bg:#f3f4f7;--card:#fff;--ink:#151a2c;--mut:#5b6278;--line:#dcdfe7;--acc:#0e8f80;--pass:#17865f;--warn:#b07a00;--fail:#c8432b;--skip:#7a8197;--soft:#eef0f4}
@media (prefers-color-scheme:dark){:root{--bg:#0f1220;--card:#181c2e;--ink:#e9ecf4;--mut:#9ca3ba;--line:#2a3048;--acc:#3cc7b4;--pass:#3fc48d;--warn:#e7b43b;--fail:#f07a62;--skip:#8c93aa;--soft:#1f2438;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif}
.w{max-width:1080px;margin:0 auto;padding:32px 20px 60px}
header{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;align-items:flex-end;margin-bottom:24px}
h1{margin:0;font-size:1.9rem;letter-spacing:-.02em}.sub{color:var(--mut);margin:4px 0 0}
.mono{font-family:Consolas,"Cascadia Mono",ui-monospace,monospace;font-size:.8rem;color:var(--mut)}
.top{display:grid;grid-template-columns:240px 1fr;gap:18px;margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px}
.score{display:flex;flex-direction:column;align-items:center;gap:6px;text-align:center}
.score svg{width:150px;height:150px}.score .g{font-size:.85rem;color:var(--mut)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.kpi{background:var(--soft);border-radius:10px;padding:12px}.kpi b{display:block;font-size:1.7rem;line-height:1.1}.kpi span{font-size:.8rem;color:var(--mut)}
.kpi.fail b{color:var(--fail)}.kpi.warn b{color:var(--warn)}.kpi.pass b{color:var(--pass)}
.cats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.cat-h{display:flex;justify-content:space-between;font-weight:600;font-size:.9rem}.cat small{color:var(--mut);font-size:.75rem}
.trk{height:7px;background:var(--soft);border-radius:4px;margin:6px 0 4px;overflow:hidden}.trk div{height:100%;background:var(--acc)}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin:26px 0 12px;align-items:center}.bar h2{margin:0 auto 0 0;font-size:1.3rem}
.bar button{font:inherit;font-size:.82rem;border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:999px;padding:5px 12px;cursor:pointer}
.bar button.on{background:var(--ink);color:var(--bg);border-color:var(--ink)}
details.f{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--skip);border-radius:10px;margin-bottom:8px}
details.f.fail{border-left-color:var(--fail)}details.f.warn{border-left-color:var(--warn)}details.f.pass{border-left-color:var(--pass)}
summary{display:grid;grid-template-columns:72px 64px 1fr auto;gap:12px;align-items:center;padding:12px 16px;cursor:pointer;list-style:none}
summary::-webkit-details-marker{display:none}
.st{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em}.st.fail{color:var(--fail)}.st.warn{color:var(--warn)}.st.pass{color:var(--pass)}.st.skipped{color:var(--skip)}
.id{font-family:Consolas,ui-monospace,monospace;font-size:.78rem;color:var(--mut)}.t{font-weight:600}
.sev{font-size:.7rem;border:1px solid var(--line);border-radius:6px;padding:2px 8px;color:var(--mut)}.sev.critical{color:var(--fail);border-color:var(--fail)}.sev.high{color:var(--warn);border-color:var(--warn)}
.body{padding:0 16px 16px 164px}.fd{margin:0 0 10px}
.lbl{display:block;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);margin-bottom:2px}
.rec p{margin:0 0 10px}.ev ul{margin:4px 0 0;padding-left:18px;font-family:Consolas,ui-monospace,monospace;font-size:.8rem;color:var(--mut)}
.note{margin-top:22px;font-size:.85rem;color:var(--mut)}.note ul{margin:4px 0 0;padding-left:18px}
footer{margin-top:28px;font-size:.8rem;color:var(--mut)}
@media (max-width:760px){.top{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}.cats{grid-template-columns:1fr}summary{grid-template-columns:60px 1fr;}.id,.sev{display:none}.body{padding:0 16px 16px}}
'@
    $js = @'
document.querySelectorAll('.bar button').forEach(function(b){b.addEventListener('click',function(){
document.querySelectorAll('.bar button').forEach(function(x){x.classList.remove('on')});b.classList.add('on');
var f=b.getAttribute('data-f');document.querySelectorAll('details.f').forEach(function(d){d.style.display=(f==='All'||d.getAttribute('data-status')===f)?'':'none'})})});
'@
    $tenant = & $e $D.TenantName
    $domain = & $e $D.PrimaryDomain
    $stamp = $Script:Now.ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $verdict = if ($critFail) { "$critFail critical issue(s) need attention first." } elseif ($count.Fail) { 'No critical failures. Work through the failed checks next.' } else { 'No failed checks. Keep reviewing warnings.' }

    @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entra Posture - $tenant</title><style>$css</style></head><body><div class="w">
<header><div><div class="mono">ENTRA ID SECURITY POSTURE REPORT</div><h1>$tenant</h1><p class="sub">$domain &middot; $stamp &middot; stale threshold $StaleDays days</p></div>
<div class="mono">Entra Posture Checker v$Script:Version</div></header>
<div class="top">
<div class="card score"><svg viewBox="0 0 120 120" role="img" aria-label="Score $Score of 100"><circle cx="60" cy="60" r="52" fill="none" stroke="var(--soft)" stroke-width="10"/>
<circle cx="60" cy="60" r="52" fill="none" stroke="$ring" stroke-width="10" stroke-linecap="round" stroke-dasharray="$dash 400" transform="rotate(-90 60 60)"/>
<text x="60" y="58" text-anchor="middle" font-size="30" font-weight="700" fill="var(--ink)">$Score</text><text x="60" y="78" text-anchor="middle" font-size="11" fill="var(--mut)">out of 100</text></svg>
<b>Grade $Grade</b><span class="g">$verdict</span></div>
<div class="card"><div class="kpis"><div class="kpi fail"><b>$($count.Fail)</b><span>Failed</span></div><div class="kpi warn"><b>$($count.Warn)</b><span>Warnings</span></div><div class="kpi pass"><b>$($count.Pass)</b><span>Passed</span></div><div class="kpi"><b>$($count.Skipped)</b><span>Skipped</span></div></div>
<div class="cats">$($cats -join '')</div></div></div>
<div class="bar"><h2>Findings</h2><button class="on" data-f="All">All $($Results.Count)</button><button data-f="Fail">Failed</button><button data-f="Warn">Warnings</button><button data-f="Pass">Passed</button><button data-f="Skipped">Skipped</button></div>
$($rows -join "`n")
$warn
<footer>Read-only assessment. Score weights: Critical 10, High 7, Medium 4, Low 2; a warning counts half; skipped checks are excluded. Generated by Entra Posture Checker &middot; github.com/aayyagar/entra-posture-checker</footer>
</div><script>$js</script></body></html>
"@
}

# ---------------------------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host "  Entra ID Security Posture Checker v$Script:Version" -ForegroundColor White
Write-Host '  Read-only assessment - no changes are made to your tenant' -ForegroundColor DarkGray
Write-Host ''

$connected = $false
if ($Demo) {
    Write-Step 'Demo mode: using the built-in sample tenant'
    $data = Get-DemoTenantData
} else {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Module Microsoft.Graph.Authentication is required. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }
    Import-Module Microsoft.Graph.Authentication
    if (-not $UseExistingConnection) {
        $scopes = 'Directory.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'Application.Read.All'
        $params = @{ Scopes = $scopes; NoWelcome = $true }
        if ($TenantId) { $params.TenantId = $TenantId }
        Write-Step 'Signing in to Microsoft Graph (read-only scopes)'
        Connect-MgGraph @params
        $connected = $true
    } elseif (-not (Get-MgContext)) {
        throw 'No existing Microsoft Graph connection found. Run Connect-MgGraph first or omit -UseExistingConnection.'
    }
    try { $data = Get-TenantData }
    finally { if ($connected -and -not $NoDisconnect) { Disconnect-MgGraph | Out-Null } }
}

Write-Step 'Running checks'
$results = @(Invoke-Checks $data)
$score = Get-Score $results
$grade = Get-Grade $score

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$safeName = ($data.TenantName -replace '[^A-Za-z0-9-]', '_')
$base = Join-Path $OutputPath ("EntraPosture_{0}_{1}" -f $safeName, $Script:Now.ToString('yyyyMMdd_HHmm'))
$htmlPath = "$base.html"
New-HtmlReport -D $data -Results $results -Score $score -Grade $grade | Set-Content -Path $htmlPath -Encoding UTF8
[pscustomobject]@{
    Tool = 'Entra Posture Checker'; Version = $Script:Version; GeneratedUtc = $Script:Now.ToString('o')
    Tenant = $data.TenantName; TenantId = $data.TenantId; Score = $score; Grade = $grade; StaleDays = $StaleDays
    DataNotes = $data.Warnings; Results = $results
} | ConvertTo-Json -Depth 6 | Set-Content -Path "$base.json" -Encoding UTF8
$results | Select-Object Id, Category, Title, Severity, Status, Finding, Recommendation, @{ n = 'Evidence'; e = { $_.Evidence -join ' | ' } } |
    Export-Csv -Path "$base.csv" -NoTypeInformation -Encoding UTF8

# Console summary
Write-Host ''
$color = if ($score -ge 80) { 'Green' } elseif ($score -ge 60) { 'Yellow' } else { 'Red' }
Write-Host ("  Score: {0}/100  (Grade {1})" -f $score, $grade) -ForegroundColor $color
foreach ($r in ($results | Where-Object { $_.Status -in 'Fail', 'Warn' } | Sort-Object @{ e = { if ($_.Status -eq 'Fail') { 0 } else { 1 } } }, Id)) {
    $c = if ($r.Status -eq 'Fail') { 'Red' } else { 'Yellow' }
    Write-Host ("  [{0,-4}] {1,-7} {2}" -f $r.Status.ToUpper(), $r.Id, $r.Title) -ForegroundColor $c
}
Write-Host ''
Write-Host "  Report : $htmlPath" -ForegroundColor White
Write-Host "  JSON   : $base.json" -ForegroundColor DarkGray
Write-Host "  CSV    : $base.csv" -ForegroundColor DarkGray
Write-Host ''
