# Entra ID Security Posture Checker

A read-only PowerShell tool that assesses the identity security of a Microsoft Entra ID tenant. It runs 23 checks across MFA, Conditional Access, privileged access, guests and applications, then produces a scored HTML report with evidence and a recommendation for every finding.

**[View the sample report →](https://aayyagar.github.io/entra-posture-checker/sample-report/)**

## Why

Most tenant compromises start with the same few gaps: admins without MFA, legacy authentication left open, too many standing Global Administrators, users consenting to malicious apps, and stale accounts nobody watches. This tool finds those gaps in a few minutes and explains how to fix each one.

## What it checks

| ID | Category | Check | Severity |
|---|---|---|---|
| BAS-01 | Baseline | Security defaults or Conditional Access is enforced | Critical |
| MFA-01 | MFA | All privileged users are registered for MFA | Critical |
| MFA-02 | MFA | Members are registered for MFA (95% target) | High |
| MFA-03 | MFA | Admins use phishing-resistant authentication | Medium |
| CA-01 | Conditional Access | Legacy authentication is blocked | Critical |
| CA-02 | Conditional Access | MFA is required for all users | High |
| CA-03 | Conditional Access | MFA is required for administrator roles | Critical |
| CA-04 | Conditional Access | Sign-in risk and user risk policies are in place | Medium |
| CA-05 | Conditional Access | No stale report-only or disabled policies | Low |
| PRV-01 | Privileged Access | Global Administrator count is between 2 and 4 | High |
| PRV-02 | Privileged Access | Privileged roles use just-in-time (PIM) access | High |
| PRV-03 | Privileged Access | No guest accounts hold privileged roles | Critical |
| PRV-04 | Privileged Access | Privileged accounts are actively used | Medium |
| ACC-01 | Accounts & Guests | No stale member accounts | Medium |
| ACC-02 | Accounts & Guests | No stale guest accounts | Medium |
| ACC-03 | Accounts & Guests | No long-pending guest invitations | Low |
| ACC-04 | Accounts & Guests | Guest invitations are restricted | Medium |
| ACC-05 | Accounts & Guests | Guest directory access is limited | Medium |
| APP-01 | Applications | Users cannot register applications | Medium |
| APP-02 | Applications | User consent to apps is restricted | High |
| APP-03 | Applications | No expired or expiring app credentials | Medium |
| APP-04 | Applications | App secrets are short-lived | Low |
| APP-05 | Applications | No apps hold Tier 0 or broad Microsoft Graph permissions | High |

## Scoring

Each check is weighted by severity: Critical 10, High 7, Medium 4, Low 2. A pass earns the full weight, a warning earns half, and a fail earns nothing. Checks that cannot run (for example, because a license is missing) are marked **Skipped** and left out of the score, so a tenant is never penalized for data it cannot provide.

| Score | Grade |
|---|---|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| below 60 | F |

## Quick start

Try it without a tenant. Demo mode uses a built-in synthetic tenant:

```powershell
.\Invoke-EntraPostureCheck.ps1 -Demo
```

Run it against your tenant:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
.\Invoke-EntraPostureCheck.ps1 -TenantId contoso.onmicrosoft.com
```

You sign in interactively and consent to read-only scopes. The report, a JSON file and a CSV file are written to `.\EntraPostureReport\`.

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-TenantId` | home tenant | Tenant ID or domain |
| `-OutputPath` | `.\EntraPostureReport` | Output folder |
| `-StaleDays` | 90 | Days without sign-in before an account is stale |
| `-SecretExpiryWarningDays` | 30 | Warn about credentials expiring within this window |
| `-Demo` | off | Use the synthetic demo tenant |
| `-UseExistingConnection` | off | Reuse an existing `Connect-MgGraph` session |
| `-NoDisconnect` | off | Stay connected after the run |

## Permissions

The tool only reads. Every Microsoft Graph call is a GET request, and it uses these delegated scopes:

`Directory.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`, `Application.Read.All`

A **Global Reader** or **Security Reader** account is enough to run it.

### License notes

- Sign-in activity and the MFA registration report need **Entra ID P1**.
- PIM schedules and risk-based Conditional Access need **Entra ID P2**.

When data is unavailable, the affected checks are reported as Skipped and listed in the report's data notes.

## Requirements

- PowerShell 5.1 or PowerShell 7+ (Windows, macOS or Linux)
- `Microsoft.Graph.Authentication` module (not needed for `-Demo`)

## Output

- **HTML report**: score, grade, category breakdown and filterable findings with evidence
- **JSON**: full results for automation or trend tracking
- **CSV**: one row per check, for spreadsheets and ticketing

## Roadmap

- Trend comparison between two runs
- Mapping to CIS Microsoft 365 Foundations and NIST SP 800-53 controls
- App-only (certificate) authentication for scheduled runs

## Author

**Akhilesh Ayyagari**, Cloud Infrastructure & Identity Architect · [Portfolio](https://aayyagar.github.io) · [LinkedIn](https://www.linkedin.com/in/akhilesh-ayyagari)

## License

MIT
