package plugin

import (
	"os"
	"path/filepath"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/plugin"
)

// Match checks if the file extension is .py
func Match(path string, info os.FileInfo) (bool, error) {
	if filepath.Ext(info.Name()) == ".py" {
		return true, nil
	}
	return false, nil
}

func init() {
	plugin.Register("semgrep", Match)
}
