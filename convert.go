package main

import (
	"io"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/sarif"
)

func convert(reader io.Reader, prependPath string) (*issue.Report, error) {
	return sarif.TransformToGLSASTReport(reader, prependPath)
}
