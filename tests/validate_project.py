#!/usr/bin/env python3
import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    'README.md',
    'LICENSE',
    '.github/workflows/ci.yml',
    'scripts/Invoke-HybridIdentityHealthCheck.ps1',
    'data/synthetic-directory-export.csv',
    'data/synthetic-sync-errors.json',
    'policies/healthcheck-rules.json',
    'docs/findings-template.md',
    'tools/generate_sample_report.py',
]
FORBIDDEN_TERMS = [
    'Microsoft ' + 'Sentinel',
    'AI-' + 'powered',
    'AI ' + 'Powered',
    'revo' + 'lutionary',
    'sea' + 'mless',
    'cutting-' + 'edge',
]
SECRET_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'gh[pousr]_[A-Za-z0-9_]{20,}'),
    re.compile(r'(?i)(client_secret|password|private_key)\s*[:=]\s*[^\s]+'),
]


def read(path):
    return (ROOT / path).read_text(encoding='utf-8')


def fail(message):
    raise SystemExit(f'validation failed: {message}')


def check_required_files():
    missing = [path for path in REQUIRED if not (ROOT / path).exists()]
    if missing:
        fail(f'missing files: {missing}')


def check_copy_hygiene():
    for path in ROOT.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.md', '.ps1', '.py', '.json', '.csv', '.yml', '.yaml'}:
            text = path.read_text(encoding='utf-8')
            if '\u2014' in text:
                fail(f'em dash found in {path.relative_to(ROOT)}')
            for term in FORBIDDEN_TERMS:
                if term in text:
                    fail(f'forbidden wording "{term}" found in {path.relative_to(ROOT)}')
            for pattern in SECRET_PATTERNS:
                if pattern.search(text):
                    fail(f'secret-like string found in {path.relative_to(ROOT)}')


def check_users_csv():
    with open(ROOT / 'data/synthetic-directory-export.csv', newline='', encoding='utf-8') as handle:
        rows = list(csv.DictReader(handle))
    expected = {
        'UserPrincipalName', 'DisplayName', 'Department', 'AccountEnabled',
        'PrivilegedRole', 'MfaRegistered', 'LastInteractiveSignInUtc',
        'PasswordLastSetUtc', 'Source', 'SyncStatus'
    }
    if set(rows[0].keys()) != expected:
        fail('unexpected CSV columns')
    if len(rows) < 5:
        fail('sample user set is too small')
    for row in rows:
        if not row['UserPrincipalName'].endswith('@example.invalid'):
            fail('sample identity must use example.invalid')
        if row['AccountEnabled'] not in {'true', 'false'}:
            fail('AccountEnabled must be true or false')
        if row['MfaRegistered'] not in {'true', 'false'}:
            fail('MfaRegistered must be true or false')


def check_json_files():
    policy = json.loads(read('policies/healthcheck-rules.json'))
    errors = json.loads(read('data/synthetic-sync-errors.json'))
    if 'thresholds' not in policy or 'rules' not in policy:
        fail('policy file missing thresholds or rules')
    rule_ids = {rule['id'] for rule in policy['rules']}
    required_rule_ids = {'ID-PRIV-MFA', 'ID-PRIV-PASSWORD-AGE', 'ID-STALE-ACTIVE', 'ID-SYNC-ERROR'}
    if rule_ids != required_rule_ids:
        fail(f'unexpected rule ids: {rule_ids}')
    if not errors:
        fail('sync error sample is empty')
    for error in errors:
        if not error['userPrincipalName'].endswith('@example.invalid'):
            fail('sync error sample identity must use example.invalid')


def check_readme():
    text = read('README.md')
    needed = [
        'Hybrid identity review',
        'synthetic',
        'Run the checks',
        'VAT IT role relevance',
        'No tenant identifiers',
    ]
    for needle in needed:
        if needle not in text:
            fail(f'README missing {needle}')


def main():
    check_required_files()
    check_copy_hygiene()
    check_users_csv()
    check_json_files()
    check_readme()
    print('validation passed')


if __name__ == '__main__':
    main()
