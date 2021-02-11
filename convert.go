package main

import (
	"io"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v2"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/sarif"
)

func convert(reader io.Reader, prependPath string) (*report.Report, error) {
	return sarif.TransformToGLSASTReport(reader, prependPath)
}
