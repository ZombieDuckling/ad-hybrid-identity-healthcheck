# AD Hybrid Identity Healthcheck

A small review kit for checking common hybrid Active Directory and Entra ID identity risks from exported directory data. It is built for safe portfolio review: it uses synthetic users, synthetic sync errors, and rules that can be inspected without access to a tenant.

## What this demonstrates

This repo maps to practical security engineer work in a Microsoft estate:

- Hybrid identity review across Active Directory, Entra ID, and directory sync signals.
- Risk checks for stale privileged accounts, missing MFA registration, weak sign-in hygiene, and sync failures.
- PowerShell reporting that works from exported CSV and JSON rather than live tenant access.
- Evidence handling: inputs are versioned samples, outputs are deterministic, and the report names each finding source.
- CI validation to catch malformed sample data, weak documentation, and accidental secret-like strings.

## Repository layout

```text
scripts/Invoke-HybridIdentityHealthCheck.ps1  PowerShell healthcheck runner
data/                                      Synthetic directory and sync samples
policies/healthcheck-rules.json            Review thresholds and rule text
tools/generate_sample_report.py            Cross-platform sample report generator
tests/validate_project.py                  CI validation for data, docs, and scripts
sample-output/                             Generated report from the synthetic data
docs/findings-template.md                  Field note template for a real review
```

## Run the checks

PowerShell path:

```powershell
pwsh ./scripts/Invoke-HybridIdentityHealthCheck.ps1 `
  -UsersCsv ./data/synthetic-directory-export.csv `
  -SyncErrorsJson ./data/synthetic-sync-errors.json `
  -RulesJson ./policies/healthcheck-rules.json `
  -OutputPath ./sample-output/ad-hybrid-healthcheck-report.md
```

Cross-platform validation path:

```bash
python3 tests/validate_project.py
python3 tools/generate_sample_report.py \
  --users data/synthetic-directory-export.csv \
  --sync-errors data/synthetic-sync-errors.json \
  --rules policies/healthcheck-rules.json \
  --output sample-output/ad-hybrid-healthcheck-report.md
```

## Review model

The sample report groups findings into four areas:

1. Privileged identity hygiene.
2. Authentication readiness.
3. Stale account and sign-in review.
4. Directory sync health.

Each finding includes severity, evidence, and a recommended operator action. The recommendations are written as review prompts, not as live-remediation commands.

## Safety boundaries

- No tenant identifiers, client names, credentials, or production exports.
- No offensive tooling.
- No live Graph, LDAP, or domain controller calls.
- All identities and sync errors are synthetic.
- The report is intended to support a security review, not to certify compliance.

## VAT IT role relevance

This kit shows the kind of work a security engineer can perform when they need to review identity risk without taking destructive action: collect exports, normalize the evidence, apply transparent rules, write a report, and leave operators with clear next steps.

## License

MIT
