package plugin

import (
	"os"
	"path/filepath"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/plugin"
)

// supported languages' file extensions
var supportedExt = []string{".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".go", ".java"}

// Match checks if any file extensions match existing supported languages
func Match(path string, info os.FileInfo) (bool, error) {
	ext := filepath.Ext(info.Name())
	for _, lang := range supportedExt {
		if ext == lang {
			return true, nil
		}
	}
	return false, nil
}

func init() {
	plugin.Register("semgrep", Match)
}
