#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def replace_once(path, old, new, label):
    file = ROOT / path
    text = file.read_text(encoding='utf-8')
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected exactly one marker in {path}, found {count}')
    file.write_text(text.replace(old, new, 1), encoding='utf-8')

replace_once(
    'src/test/java/io/rbvm/postgres/PostgresV23FormulaResultLiveSelfTest.java',
    'require(schemaVersion == 25, "expected schema version 25, found " + schemaVersion);',
    'require(schemaVersion >= 23, "V23 Formula live test requires schema version 23 or newer, found " + schemaVersion);',
    'V23 minimum schema'
)
replace_once(
    'src/test/java/io/rbvm/postgres/PostgresV23FormulaResultLiveSelfTest.java',
    '"PostgresV23FormulaResultLiveSelfTest: PASS schema=25 decision_history=PASS "',
    '"PostgresV23FormulaResultLiveSelfTest: PASS schema=" + schemaVersion + " decision_history=PASS "',
    'V23 dynamic schema output'
)
replace_once(
    'src/test/java/io/rbvm/postgres/PostgresV24DerivedRiskLiveSelfTest.java',
    'require(new PostgresMigrator(ownerConnections).installedVersion() == 25,\n                "V24 derived-risk live test requires latest schema version 25");',
    'require(new PostgresMigrator(ownerConnections).installedVersion() >= 24,\n                "V24 derived-risk live test requires schema version 24 or newer");',
    'V24 minimum schema'
)
replace_once(
    'src/test/java/io/rbvm/postgres/PostgresV24DerivedRiskLiveSelfTest.java',
    '"PostgresV24DerivedRiskLiveSelfTest: PASS schema=25 methodologies=2 "',
    '"PostgresV24DerivedRiskLiveSelfTest: PASS schema>=24 methodologies=2 "',
    'V24 schema output'
)
replace_once(
    'src/test/java/io/rbvm/postgres/PostgresV25RiskMethodSelectionPolicyLiveSelfTest.java',
    'require(new PostgresMigrator(ownerConnections).installedVersion() == 25,\n                "V25 risk method selection live test requires schema version 25");',
    'require(new PostgresMigrator(ownerConnections).installedVersion() >= 25,\n                "V25 risk method selection live test requires schema version 25 or newer");',
    'V25 minimum schema'
)
replace_once(
    'src/test/java/io/rbvm/postgres/PostgresV25RiskMethodSelectionPolicyLiveSelfTest.java',
    'require(store.schemaVersion() == 25,\n                "risk method selection store must bind schema version 25");',
    'require(store.schemaVersion() >= 25,\n                "risk method selection store must bind schema version 25 or newer");',
    'V25 store minimum schema'
)
replace_once(
    'src/test/java/io/rbvm/postgres/PostgresV25RiskMethodSelectionPolicyLiveSelfTest.java',
    '"PostgresV25RiskMethodSelectionPolicyLiveSelfTest: PASS schema=25 "',
    '"PostgresV25RiskMethodSelectionPolicyLiveSelfTest: PASS schema>=25 "',
    'V25 schema output'
)
replace_once(
    'src/test/java/io/rbvm/postgres/PostgresMigratorSelfTest.java',
    'private static final int LATEST_SCHEMA_VERSION = 25;',
    'private static final int LATEST_SCHEMA_VERSION = 26;',
    'migrator latest schema'
)
replace_once(
    '.github/workflows/postgres-integration.yml',
    'Run live V18-V25 persistence, Decision Input V3, Formula, derived-risk, and risk-method policy integration',
    'Run live V18-V26 persistence, Decision Input V3, Formula, derived-risk, policy, and activation integration',
    'workflow step label'
)
replace_once(
    '.github/workflows/postgres-integration.yml',
    '          java -ea -cp "$classpath" io.rbvm.postgres.PostgresV25RiskMethodSelectionPolicyLiveSelfTest\n',
    '          java -ea -cp "$classpath" io.rbvm.postgres.PostgresV25RiskMethodSelectionPolicyLiveSelfTest\n'
    '          java -ea -cp "$classpath" io.rbvm.postgres.PostgresV26RiskMethodSelectionActivationLiveSelfTest\n',
    'workflow V26 live test'
)
replace_once(
    'scripts/verify-risk-method-selection-policy.py',
    "assert 'V18-V25' in workflow",
    "assert 'V18-V26' in workflow",
    'V25 verifier workflow label'
)

path = ROOT / 'scripts/verify-decision-input-v3.py'
text = path.read_text(encoding='utf-8')
if 'V18-V25' not in text:
    raise SystemExit('Decision Input V3 verifier lacks expected V18-V25 marker')
path.write_text(text.replace('V18-V25', 'V18-V26'), encoding='utf-8')

print('V26 live-version alignment: PATCHED')
