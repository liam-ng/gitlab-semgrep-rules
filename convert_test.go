package main

import (
	"os"
	"reflect"
	"testing"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v2"
)

func TestConvert(t *testing.T) {
	fixture, err := os.Open("sarif/test_fixtures/semgrep.sarif")
	if err != nil {
		t.Fatal(err)
	}

	want := report.Identifier{Type: "bandit_test_id", Name: "Bandit Test ID B303", Value: "B303"}
	sastReport, err := convert(fixture, "/tmp/app/")
	if err != nil {
		t.Fatal(err)
	}

	got := sastReport.Vulnerabilities[0].Identifiers[3]

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}

func TestGenerateBanditID(t *testing.T) {
	want := report.Identifier{Type: "bandit_test_id", Name: "Bandit Test ID B303", Value: "B303"}
	got := generateBanditID("B303-2")

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}

func TestBanditIdentifiersFor(t *testing.T) {
	want := []report.Identifier{
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
	}

	got := ruleToIDs("rules.bandit.B502.B503")

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}
