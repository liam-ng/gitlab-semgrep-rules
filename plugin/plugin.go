package plugin

import (
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v3/plugin"
	ruleset "gitlab.com/gitlab-org/security-products/analyzers/ruleset/v2"
)

// supported languages' file extensions
var supportedExt = []string{".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".go", ".java", ".cs", ".scala", ".sc"}

// isRulesetCheckDone keeps track of whether ruleset check is already done
// so that when the ruleset file is not present, the same information is reused
// instead of rechecking for every file's walk func
var isRulesetCheckDone bool

// custRulesEnabled determines if the ruleset feature flag is enabled in the current session
var custRulesEnabled = customRulesetFeatEnabled()

// Match checks if any file extensions match existing supported languages
func Match(path string, info os.FileInfo) (bool, error) {

	if isRulesetCheckDone || !custRulesEnabled {
		return matchByLangExt(path, info)
	}

	// check for existence of semgrep rules in the custom ruleset,
	// if present then skip language-based matching filter
	rulesetPath := filepath.Join(path, ruleset.PathSAST)
	if _, e := ruleset.LoadRelative(rulesetPath, "semgrep"); e != nil {
		switch e.(type) {
		case *ruleset.ConfigNotFoundError:
			log.Debug("no semgrep rules found in the custom ruleset, matching via language-based filter..")
		default:
			log.Debug("could not check for semgrep rules in the custom ruleset, choosing language-based matching filter as a fallback")
		}
		isRulesetCheckDone = true
		return matchByLangExt(path, info)
	}

	log.Debug("semgrep rules found in the custom ruleset, skipping language-based matching filter")
	return true, nil
}

func matchByLangExt(path string, info os.FileInfo) (bool, error) {
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

// customRulesetFeatEnabled returns true if "sast_custom_rulesets" feature flag
// is present in the "GITLAB_FEATURES" env variable
func customRulesetFeatEnabled() bool {
	features := os.Getenv(ruleset.EnvVarGitlabFeatures)
	return strings.Contains(features, ruleset.GitlabFeatureCustomRulesetsSAST)
}
