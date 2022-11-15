package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	report "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
)

func TestConvert(t *testing.T) {
	err := buildCache("testdata/sampledist")
	assert.NoError(t, err)

	for name, identifiers := range map[string][]report.Identifier{
		"bandit.B101-1": {
			{
				Type:  "semgrep_id",
				Name:  "bandit.B101",
				Value: "bandit.B101",
				URL:   "",
			}, {
				Type:  "bandit_test_id",
				Name:  "Bandit Test ID: B101",
				Value: "B101",
				URL:   "",
			},
		},
		"eslint.detect-buffer-noassert-1": {
			{
				Type:  "semgrep_id",
				Name:  "eslint.detect-buffer-noassert",
				Value: "eslint.detect-buffer-noassert",
				URL:   ""},
			{
				Type:  "eslint_rule_id",
				Name:  "ESLint rule ID security/detect-buffer-noassert",
				Value: "security/detect-buffer-noassert",
				URL:   "",
			},
		},
		"find_sec_bugs.HTTPONLY_COOKIE-1": {
			{
				Type:  "semgrep_id",
				Name:  "find_sec_bugs.HTTPONLY_COOKIE-1",
				Value: "find_sec_bugs.HTTPONLY_COOKIE-1",
				URL:   ""},
			{
				Type:  "find_sec_bugs_type",
				Name:  "Find Security Bugs-HTTPONLY_COOKIE",
				Value: "HTTPONLY_COOKIE",
				URL:   "",
			},
		},
		"flawfinder.umask-1": {
			{
				Type:  "semgrep_id",
				Name:  "flawfinder.umask-1",
				Value: "flawfinder.umask-1",
				URL:   "",
			},
			{
				Type:  "flawfinder_func_name",
				Name:  "Flawfinder - umask",
				Value: "umask",
				URL:   "",
			},
		},
		"flawfinder.char-1.TCHAR-1.wchar_t-1": {
			{
				Type:  "semgrep_id",
				Name:  "flawfinder.char-1.TCHAR-1.wchar_t-1",
				Value: "flawfinder.char-1.TCHAR-1.wchar_t-1",
				URL:   "",
			},
			{
				Type:  "flawfinder_func_name",
				Name:  "Flawfinder - char",
				Value: "char",
				URL:   "",
			},
			{
				Type:  "flawfinder_func_name",
				Name:  "Flawfinder - TCHAR",
				Value: "TCHAR",
				URL:   "",
			},
			{
				Type:  "flawfinder_func_name",
				Name:  "Flawfinder - wchar_t",
				Value: "wchar_t",
				URL:   "",
			},
		},
		"gosec.G504-1": {
			{
				Type:  "semgrep_id",
				Name:  "gosec.G504-1",
				Value: "gosec.G504-1",
				URL:   "",
			},
			{
				Type:  "gosec_rule_id",
				Name:  "Gosec Rule ID G504",
				Value: "G504",
				URL:   "",
			},
		},
		"security_code_scan.SCS0019-1": {
			{
				Type:  "semgrep_id",
				Name:  "security_code_scan.SCS0019-1",
				Value: "security_code_scan.SCS0019-1",
				URL:   "",
			}, {
				Type:  "security_code_scan_rule_id",
				Name:  "SCS0019",
				Value: "SCS0019",
				URL:   "",
			},
		},
	} {
		expected, err := ruleIDToIdentifier(name, []report.Identifier{})
		assert.NoError(t, err)
		assert.Equal(t, expected, identifiers)
	}

}
