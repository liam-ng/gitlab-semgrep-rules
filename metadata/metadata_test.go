package metadata

import (
	"reflect"
	"testing"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v2"
)

func TestReportScanner(t *testing.T) {
	want := report.ScannerDetails{
		ID:      "semgrep",
		Name:    "Semgrep",
		Version: ScannerVersion,
		Vendor: report.Vendor{
			Name: "GitLab",
		},
		URL: "https://github.com/returntocorp/semgrep",
	}
	got := ReportScanner

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}
