package main

import (
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"gitlab.com/gitlab-org/security-products/analyzers/report/v4"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/rules"
)

func TestConvert(t *testing.T) {
	rules.DefaultRulesetPath = path.Join("testdata", "sampledist")
	vulnFile := "tests/test_simple.py"
	// setting CI_PROJECT_DIR containing [location.file]'s prefix to confirm if old behaviour
	// is removed
	t.Setenv("CI_PROJECT_DIR", "tests")

	fixture, err := os.Open("testdata/reports/semgrep.sarif")
	require.NoError(t, err)
	defer fixture.Close()

	sastReport, err := convert(fixture, "" /* unused input */)
	require.NoError(t, err)

	vuln := sastReport.Vulnerabilities[0]

	// Test Semgrep ID
	want := report.Identifier{
		Type:  "semgrep_id",
		Name:  "bandit.B101",
		Value: "bandit.B101",
		URL:   "https://semgrep.dev/r/gitlab.bandit.B101",
	}
	require.Contains(t, vuln.Identifiers, want)

	// Test Bandit ID
	want = report.Identifier{
		Type:  "bandit_test_id",
		Name:  "Bandit Test ID B101",
		Value: "B101",
	}
	require.Contains(t, vuln.Identifiers, want)

	// Test if prefix trim made in the vuln file path
	require.Equal(t, vulnFile, vuln.Location.File)
	require.Equal(t, 7, vuln.Location.LineStart)
	require.Equal(t, 7, vuln.Location.LineEnd)
}

func TestCompareKey(t *testing.T) {
	revertFunc := overrideDefaultRulesetPath(path.Join("testdata", "sampledist"))
	defer revertFunc()

	t.Setenv("CI_PROJECT_DIR", "tests")

	fixture, err := os.Open("testdata/reports/semgrep.sarif")
	require.NoError(t, err)
	defer fixture.Close()

	sastReport, err := convert(fixture, "")
	require.NoError(t, err)

	vuln := sastReport.Vulnerabilities[0]
	require.Equal(t, "semgrep_id:bandit.B101:7:7", vuln.CompareKey)
}

func TestScanPrimaryIdentifiers(t *testing.T) {
	revertFunc := overrideDefaultRulesetPath(path.Join("testdata", "sampledist"))
	defer revertFunc()

	t.Setenv("CI_PROJECT_DIR", "tests")
	t.Setenv("GITLAB_FEATURES", "sast_fp_reduction")

	fixture, err := os.Open("testdata/reports/semgrep.sarif")
	require.NoError(t, err)
	defer fixture.Close()

	sastReport, err := convert(fixture, "" /* unused input */)
	require.NoError(t, err)

	require.True(t, scanNameAndValueExist(sastReport.Scan.PrimaryIdentifiers, "eslint.detect-non-literal-require", "eslint.detect-non-literal-require"))
}

func TestGenerateIDs(t *testing.T) {
	testcases := map[string][]report.Identifier{
		"find_sec_bugs.DMI_EMPTY_DB_PASSWORD-1.HARD_CODE_PASSWORD-2": {
			{
				Type:  "find_sec_bugs_type",
				Name:  "Find Security Bugs-DMI_EMPTY_DB_PASSWORD",
				Value: "DMI_EMPTY_DB_PASSWORD",
			},
			{
				Type:  "find_sec_bugs_type",
				Name:  "Find Security Bugs-HARD_CODE_PASSWORD",
				Value: "HARD_CODE_PASSWORD",
			},
		},
		"bandit.B303-1": {
			{
				Type:  "bandit_test_id",
				Name:  "Bandit Test ID B303",
				Value: "B303",
			},
		},
		"eslint.detect-no-csrf-before-method-override-1": {
			{
				Type:  "eslint_rule_id",
				Name:  "ESLint rule ID/detect-no-csrf-before-method-override",
				Value: "detect-no-csrf-before-method-override",
			},
		},
		"flawfinder.char-1.TCHAR-1.wchar_t-1": {
			{
				Type:  "flawfinder_func_name",
				Name:  "Flawfinder - char",
				Value: "char",
			},
			{
				Type:  "flawfinder_func_name",
				Name:  "Flawfinder - TCHAR",
				Value: "TCHAR",
			},
			{
				Type:  "flawfinder_func_name",
				Name:  "Flawfinder - wchar_t",
				Value: "wchar_t",
			},
		},
		"gosec.G107-1": {
			{
				Type:  "gosec_rule_id",
				Name:  "Gosec Rule ID G107",
				Value: "G107",
			},
		},
		"security_code_scan.SCS0005-1": {
			{
				Type:  "security_code_scan_rule_id",
				Name:  "SCS0005",
				Value: "SCS0005",
			},
		},
		"security_code_scan.SCS0026-1.SCS0031-1": {
			{
				Type:  "security_code_scan_rule_id",
				Name:  "SCS0026",
				Value: "SCS0026",
			},
			{
				Type:  "security_code_scan_rule_id",
				Name:  "SCS0031",
				Value: "SCS0031",
			},
		},
	}

	revertFunc := overrideDefaultRulesetPath(path.Join("testdata", "sampledist"))
	defer revertFunc()

	ruleMap, err := buildRuleMap(rules.DefaultRulesetPath)
	if err != nil {
		t.Fatal(err)
	}

	for ruleid, want := range testcases {
		_, sIDs := ruleToIDs(ruleid, ruleMap)
		got := sIDs
		if !reflect.DeepEqual(want, got) {
			t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
		}
	}
}

// TestComputeCompareKey ensures the generated `cve` value is stable for occurrences of the same vulnerability, and
// unique for different vulnerabilities.
func TestComputeCompareKey(t *testing.T) {
	v1 := report.Vulnerability{
		Identifiers: []report.Identifier{
			{
				Type:  "myIdentifierType",
				Value: "myIdentifierValue",
			},
		},
		Location: report.Location{
			LineStart: 10,
			LineEnd:   10,
		},
	}

	v2 := report.Vulnerability{
		Identifiers: []report.Identifier{
			{
				Type:  "myIdentifierType2",
				Value: "myIdentifierValue2",
			},
		},
		Location: report.Location{
			LineStart: 15,
			LineEnd:   15,
		},
	}

	assert.Equal(t, computeCompareKey(v1), computeCompareKey(v1), "same key for same vulnerability")
	assert.NotEqual(t, computeCompareKey(v1), computeCompareKey(v2), "different keys for different vulnerabilities")

	assert.Equal(t, computeCompareKey(v1), "myIdentifierType:myIdentifierValue:10:10")
	assert.Equal(t, computeCompareKey(v2), "myIdentifierType2:myIdentifierValue2:15:15")
}

func scanNameAndValueExist(identifiers []report.Identifier, name string, value string) bool {
	found := false
	for _, pid := range identifiers {
		if pid.Name == name && pid.Value == value {
			found = true
		}
	}
	return found
}

func overrideDefaultRulesetPath(path string) func() {
	prev := rules.DefaultRulesetPath

	rules.DefaultRulesetPath = path // override

	return func() { rules.DefaultRulesetPath = prev } // revert func
}
