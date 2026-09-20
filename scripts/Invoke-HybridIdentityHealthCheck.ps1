[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UsersCsv,

    [Parameter(Mandatory = $true)]
    [string]$SyncErrorsJson,

    [Parameter(Mandatory = $true)]
    [string]$RulesJson,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RuleById {
    param(
        [Parameter(Mandatory = $true)] [object[]]$Rules,
        [Parameter(Mandatory = $true)] [string]$Id
    )

    $match = $Rules | Where-Object { $_.id -eq $Id } | Select-Object -First 1
    if (-not $match) {
        throw "Missing rule definition: $Id"
    }
    return $match
}

function Get-DaysBetween {
    param(
        [Parameter(Mandatory = $true)] [datetime]$Start,
        [Parameter(Mandatory = $true)] [datetime]$End
    )

    return [int]([timespan]($End - $Start)).TotalDays
}

$users = Import-Csv -Path $UsersCsv
$syncErrors = Get-Content -Raw -Path $SyncErrorsJson | ConvertFrom-Json
$policy = Get-Content -Raw -Path $RulesJson | ConvertFrom-Json
$reviewDate = [datetime]$policy.reviewDateUtc
$findings = New-Object System.Collections.Generic.List[object]

foreach ($user in $users) {
    $role = [string]$user.PrivilegedRole
    $isPrivileged = $role -and $role -ne 'None'
    $enabled = [System.Convert]::ToBoolean($user.AccountEnabled)
    $mfaRegistered = [System.Convert]::ToBoolean($user.MfaRegistered)
    $lastSignIn = [datetime]$user.LastInteractiveSignInUtc
    $passwordLastSet = [datetime]$user.PasswordLastSetUtc

    if ($isPrivileged -and -not $mfaRegistered) {
        $rule = Get-RuleById -Rules $policy.rules -Id 'ID-PRIV-MFA'
        $findings.Add([pscustomobject]@{
            Rule = $rule.id
            Severity = $rule.severity
            Title = $rule.title
            Object = $user.UserPrincipalName
            Evidence = "Role: $role; MFA registered: $mfaRegistered"
            Action = $rule.action
        }) | Out-Null
    }

    $passwordAge = Get-DaysBetween -Start $passwordLastSet -End $reviewDate
    if ($isPrivileged -and $passwordAge -gt [int]$policy.thresholds.privilegedPasswordAgeDays) {
        $rule = Get-RuleById -Rules $policy.rules -Id 'ID-PRIV-PASSWORD-AGE'
        $findings.Add([pscustomobject]@{
            Rule = $rule.id
            Severity = $rule.severity
            Title = $rule.title
            Object = $user.UserPrincipalName
            Evidence = "Password age: $passwordAge days; threshold: $($policy.thresholds.privilegedPasswordAgeDays) days"
            Action = $rule.action
        }) | Out-Null
    }

    $staleDays = Get-DaysBetween -Start $lastSignIn -End $reviewDate
    if ($enabled -and $staleDays -gt [int]$policy.thresholds.staleSignInDays) {
        $rule = Get-RuleById -Rules $policy.rules -Id 'ID-STALE-ACTIVE'
        $findings.Add([pscustomobject]@{
            Rule = $rule.id
            Severity = $rule.severity
            Title = $rule.title
            Object = $user.UserPrincipalName
            Evidence = "Last interactive sign-in: $staleDays days ago; threshold: $($policy.thresholds.staleSignInDays) days"
            Action = $rule.action
        }) | Out-Null
    }
}

foreach ($errorItem in $syncErrors) {
    $lastSeen = [datetime]$errorItem.lastSeenUtc
    $age = Get-DaysBetween -Start $lastSeen -End $reviewDate
    if ($age -gt [int]$policy.thresholds.syncErrorAgeDays) {
        $rule = Get-RuleById -Rules $policy.rules -Id 'ID-SYNC-ERROR'
        $findings.Add([pscustomobject]@{
            Rule = $rule.id
            Severity = $rule.severity
            Title = $rule.title
            Object = $errorItem.userPrincipalName
            Evidence = "Error: $($errorItem.errorCode); attribute: $($errorItem.attribute); age: $age days"
            Action = $rule.action
        }) | Out-Null
    }
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# AD Hybrid Identity Healthcheck Report') | Out-Null
$lines.Add('') | Out-Null
$lines.Add("Review date: $($policy.reviewDateUtc)") | Out-Null
$lines.Add('Data classification: synthetic sample data') | Out-Null
$lines.Add('') | Out-Null
$lines.Add('## Summary') | Out-Null
$lines.Add('') | Out-Null
$lines.Add("Findings: $($findings.Count)") | Out-Null
$lines.Add("Users reviewed: $($users.Count)") | Out-Null
$lines.Add("Sync errors reviewed: $($syncErrors.Count)") | Out-Null
$lines.Add('') | Out-Null
$lines.Add('## Findings') | Out-Null
$lines.Add('') | Out-Null

if ($findings.Count -eq 0) {
    $lines.Add('No findings from the supplied sample data.') | Out-Null
} else {
    foreach ($finding in $findings) {
        $lines.Add("### $($finding.Rule): $($finding.Title)") | Out-Null
        $lines.Add('') | Out-Null
        $lines.Add("- Severity: $($finding.Severity)") | Out-Null
        $lines.Add("- Object: $($finding.Object)") | Out-Null
        $lines.Add("- Evidence: $($finding.Evidence)") | Out-Null
        $lines.Add("- Operator action: $($finding.Action)") | Out-Null
        $lines.Add('') | Out-Null
    }
}

$destination = Split-Path -Parent $OutputPath
if ($destination -and -not (Test-Path -Path $destination)) {
    New-Item -ItemType Directory -Path $destination | Out-Null
}

$lines | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Wrote $OutputPath with $($findings.Count) findings."
