# Finding classification

This kit uses a small severity model so the output can be reviewed without tenant context.

## High

Use high when the condition can block authentication, weaken privileged access, or cause directory sync drift.

Examples:

- stale directory sync
- duplicate user principal names
- privileged account without MFA registration in the supplied snapshot
- federation certificate expiry within 30 days
- pass-through authentication with fewer than two active agents

## Medium

Use medium when the condition may complicate recovery, onboarding, or change control but does not directly show a current outage.

Examples:

- password hash sync disabled without documented reason
- enabled synced account missing immutable ID
- writeback feature mismatch that needs owner confirmation

## Low

Use low for hygiene items that should enter a cleanup queue.

Examples:

- stale registered device
- disabled account present in sync scope
- old sign-in timestamp needing owner review

## Review rule

The script output is not an approval to change production. Treat it as a triage list, confirm in the tenant, and route changes through the normal change process.
