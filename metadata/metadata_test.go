package metadata

import (
	"reflect"
	"testing"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
)

func TestReportScanner(t *testing.T) {
	want := issue.ScannerDetails{
		ID:      "semgrep",
		Name:    "Semgrep",
		Version: ScannerVersion,
		Vendor: issue.Vendor{
			Name: "GitLab",
		},
		URL: "https://github.com/returntocorp/semgrep",
	}
	got := ReportScanner

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}
