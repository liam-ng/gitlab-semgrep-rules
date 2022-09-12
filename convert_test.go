package main

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
)

func TestConvert(t *testing.T) {
	fixture, err := os.Open("testdata/reports/semgrep.sarif")
	if err != nil {
		t.Fatal(err)
	}

	sastReport, err := convert(fixture, "/tmp/app/")
	if err != nil {
		t.Fatal(err)
	}

	// Test Semgrep ID
	want := report.Identifier{
		Type:  "semgrep_id",
		Name:  "bandit.B303-1",
		Value: "bandit.B303-1",
		URL:   "https://semgrep.dev/r/gitlab.bandit.B303-1",
	}
	got := sastReport.Vulnerabilities[0].Identifiers[0]
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}

	// Test Bandit ID
	want = report.Identifier{
		Type:  "bandit_test_id",
		Name:  "Bandit Test ID B303",
		Value: "B303",
	}
	got = sastReport.Vulnerabilities[0].Identifiers[3]
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}

func TestGenerateBanditID(t *testing.T) {
	want := report.Identifier{
		Type:  "bandit_test_id",
		Name:  "Bandit Test ID B303",
		Value: "B303",
	}
	got, err := generateBanditID("B303-2")
	assert.NoError(t, err)

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}

func TestGenerateFindSecBugsID(t *testing.T) {
	id := "LDAP_INJECTION"
	want := report.Identifier{
		Type:  "find_sec_bugs_type",
		Name:  fmt.Sprintf("Find Security Bugs-%s", id),
		Value: id,
	}
	got, err := generateFindSecBugsID(id + "-2")
	assert.NoError(t, err)

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
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
		"eslint.security/detect-no-csrf-before-method-override-1": {
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
	}

	for ruleid, want := range testcases {
		got := ruleToIDs(ruleid)
		if !reflect.DeepEqual(want, got) {
			t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
		}
	}
}
