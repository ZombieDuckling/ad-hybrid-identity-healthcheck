#!/usr/bin/env python3
import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def parse_dt(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)


def load_rule(policy, rule_id):
    for rule in policy['rules']:
        if rule['id'] == rule_id:
            return rule
    raise KeyError(f'Missing rule definition: {rule_id}')


def days_between(start, end):
    return (end - start).days


def main():
    parser = argparse.ArgumentParser(description='Generate a sample hybrid identity healthcheck report.')
    parser.add_argument('--users', required=True)
    parser.add_argument('--sync-errors', required=True)
    parser.add_argument('--rules', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()

    with open(args.users, newline='', encoding='utf-8') as handle:
        users = list(csv.DictReader(handle))
    with open(args.sync_errors, encoding='utf-8') as handle:
        sync_errors = json.load(handle)
    with open(args.rules, encoding='utf-8') as handle:
        policy = json.load(handle)

    review_date = parse_dt(policy['reviewDateUtc'])
    thresholds = policy['thresholds']
    findings = []

    for user in users:
        role = user['PrivilegedRole']
        privileged = role and role != 'None'
        enabled = user['AccountEnabled'].lower() == 'true'
        mfa_registered = user['MfaRegistered'].lower() == 'true'
        last_sign_in = parse_dt(user['LastInteractiveSignInUtc'])
        password_last_set = parse_dt(user['PasswordLastSetUtc'])

        if privileged and not mfa_registered:
            rule = load_rule(policy, 'ID-PRIV-MFA')
            findings.append({
                'rule': rule['id'],
                'severity': rule['severity'],
                'title': rule['title'],
                'object': user['UserPrincipalName'],
                'evidence': f'Role: {role}; MFA registered: {mfa_registered}',
                'action': rule['action'],
            })

        password_age = days_between(password_last_set, review_date)
        if privileged and password_age > thresholds['privilegedPasswordAgeDays']:
            rule = load_rule(policy, 'ID-PRIV-PASSWORD-AGE')
            findings.append({
                'rule': rule['id'],
                'severity': rule['severity'],
                'title': rule['title'],
                'object': user['UserPrincipalName'],
                'evidence': f'Password age: {password_age} days; threshold: {thresholds["privilegedPasswordAgeDays"]} days',
                'action': rule['action'],
            })

        stale_days = days_between(last_sign_in, review_date)
        if enabled and stale_days > thresholds['staleSignInDays']:
            rule = load_rule(policy, 'ID-STALE-ACTIVE')
            findings.append({
                'rule': rule['id'],
                'severity': rule['severity'],
                'title': rule['title'],
                'object': user['UserPrincipalName'],
                'evidence': f'Last interactive sign-in: {stale_days} days ago; threshold: {thresholds["staleSignInDays"]} days',
                'action': rule['action'],
            })

    for error in sync_errors:
        last_seen = parse_dt(error['lastSeenUtc'])
        age = days_between(last_seen, review_date)
        if age > thresholds['syncErrorAgeDays']:
            rule = load_rule(policy, 'ID-SYNC-ERROR')
            findings.append({
                'rule': rule['id'],
                'severity': rule['severity'],
                'title': rule['title'],
                'object': error['userPrincipalName'],
                'evidence': f'Error: {error["errorCode"]}; attribute: {error["attribute"]}; age: {age} days',
                'action': rule['action'],
            })

    lines = [
        '# AD Hybrid Identity Healthcheck Report',
        '',
        f'Review date: {policy["reviewDateUtc"]}',
        'Data classification: synthetic sample data',
        '',
        '## Summary',
        '',
        f'Findings: {len(findings)}',
        f'Users reviewed: {len(users)}',
        f'Sync errors reviewed: {len(sync_errors)}',
        '',
        '## Findings',
        '',
    ]

    if not findings:
        lines.append('No findings from the supplied sample data.')
    else:
        for finding in findings:
            lines.extend([
                f'### {finding["rule"]}: {finding["title"]}',
                '',
                f'- Severity: {finding["severity"]}',
                f'- Object: {finding["object"]}',
                f'- Evidence: {finding["evidence"]}',
                f'- Operator action: {finding["action"]}',
                '',
            ])

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')
    print(f'Wrote {output} with {len(findings)} findings.')


if __name__ == '__main__':
    main()
