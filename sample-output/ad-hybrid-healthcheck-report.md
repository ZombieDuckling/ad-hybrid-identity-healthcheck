# AD Hybrid Identity Healthcheck Report

Review date: 2026-09-20T00:00:00Z
Data classification: synthetic sample data

## Summary

Findings: 7
Users reviewed: 6
Sync errors reviewed: 2

## Findings

### ID-PRIV-MFA: Privileged account without MFA registration

- Severity: High
- Object: alex.admin@example.invalid
- Evidence: Role: Global Administrator; MFA registered: False
- Operator action: Confirm the role assignment is still needed, then require MFA registration before privileged use.

### ID-PRIV-PASSWORD-AGE: Privileged account password older than threshold

- Severity: Medium
- Object: alex.admin@example.invalid
- Evidence: Password age: 140 days; threshold: 90 days
- Operator action: Review the account lifecycle and rotate or move the account to a stronger privileged-access process.

### ID-PRIV-MFA: Privileged account without MFA registration

- Severity: High
- Object: sam.service@example.invalid
- Evidence: Role: Directory Readers; MFA registered: False
- Operator action: Confirm the role assignment is still needed, then require MFA registration before privileged use.

### ID-PRIV-PASSWORD-AGE: Privileged account password older than threshold

- Severity: Medium
- Object: sam.service@example.invalid
- Evidence: Password age: 638 days; threshold: 90 days
- Operator action: Review the account lifecycle and rotate or move the account to a stronger privileged-access process.

### ID-STALE-ACTIVE: Enabled account with stale interactive sign-in

- Severity: Medium
- Object: sam.service@example.invalid
- Evidence: Last interactive sign-in: 311 days ago; threshold: 90 days
- Operator action: Confirm owner and business need before disabling, archiving, or excluding from access.

### ID-STALE-ACTIVE: Enabled account with stale interactive sign-in

- Severity: Medium
- Object: lee.legacy@example.invalid
- Evidence: Last interactive sign-in: 292 days ago; threshold: 90 days
- Operator action: Confirm owner and business need before disabling, archiving, or excluding from access.

### ID-SYNC-ERROR: Directory sync error older than threshold

- Severity: Medium
- Object: sam.service@example.invalid
- Evidence: Error: AttributeValueMustBeUnique; attribute: proxyAddresses; age: 10 days
- Operator action: Resolve the source attribute conflict and confirm the object returns to a clean sync state.
