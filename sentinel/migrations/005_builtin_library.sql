ALTER TABLE test_suites ADD COLUMN builtin_key TEXT;
ALTER TABLE test_cases ADD COLUMN builtin_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_suites_org_builtin ON test_suites(organization_id, builtin_key);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_suite_builtin ON test_cases(test_suite_id, builtin_key);
