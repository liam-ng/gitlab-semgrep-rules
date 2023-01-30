package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"gitlab.com/gitlab-org/security-products/analyzers/report/v3"
)

func TestConvert(t *testing.T) {
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

func TestGenerateBanditID(t *testing.T) {
	want := report.Identifier{
		Type:  "bandit_test_id",
		Name:  "Bandit Test ID B303",
		Value: "B303",
	}
	got := generateBanditID("B303-2")
	assert.Equal(t, want, got)
}

func TestGenerateFindSecBugsID(t *testing.T) {
	id := "LDAP_INJECTION"
	want := report.Identifier{
		Type:  "find_sec_bugs_type",
		Name:  fmt.Sprintf("Find Security Bugs-%s", id),
		Value: id,
	}
	got := generateFindSecBugsID(id + "-2")
	assert.Equal(t, want, got)
}

func TestGenerateIDs(t *testing.T) {
	testcases := map[string][]report.Identifier{
		"find_sec_bugs.HARD_CODE_PASSWORD-1.HARD_CODE_KEY-1": {
			{
				Type:  "find_sec_bugs_type",
				Name:  "Find Security Bugs-HARD_CODE_PASSWORD",
				Value: "HARD_CODE_PASSWORD",
			},
			{
				Type:  "find_sec_bugs_type",
				Name:  "Find Security Bugs-HARD_CODE_KEY",
				Value: "HARD_CODE_KEY",
			},
		},
		"bandit.B502.B503": {
			{
				Type:  "bandit_test_id",
				Name:  "Bandit Test ID B502",
				Value: "B502",
			},
			{
				Type:  "bandit_test_id",
				Name:  "Bandit Test ID B503",
				Value: "B503",
			},
		},
		"eslint.detect-no-csrf-before-method-override": {
			{
				Type:  "eslint_rule_id",
				Name:  "ESLint rule ID security/detect-no-csrf-before-method-override",
				Value: "security/detect-no-csrf-before-method-override",
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
		"gosec.G104-1.G107-1": {
			{
				Type:  "gosec_rule_id",
				Name:  "Gosec Rule ID G104",
				Value: "G104",
			}, {
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

	for ruleid, want := range testcases {
		got := ruleToIDs(ruleid)
		assert.Equal(t, want, got)
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
