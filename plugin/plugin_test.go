package plugin

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/gitlab-org/security-products/analyzers/ruleset"
)

func TestMatch_BypassPluginDetection(tt *testing.T) {
	base := filepath.Join("..", "testdata", "match-projects")
	usecases := []struct {
		usecase          string
		projDir          string
		rulesetCheckDone bool // indicates that ruleset check info is reused by other files' match func
		enableFeature    bool
	}{
		{
			usecase:       "custom ruleset *with* semgrep rules",
			projDir:       filepath.Join(base, "custom-ruleset-w-semgrep"),
			enableFeature: true,
		},
		{
			usecase:          "custom ruleset *without* semgrep rules",
			projDir:          filepath.Join(base, "custom-ruleset-wo-semgrep"),
			rulesetCheckDone: true,
			enableFeature:    true,
		},
		{
			usecase:          "no custom ruleset present with feature enabled",
			projDir:          filepath.Join(base, "wo-custom-ruleset"),
			rulesetCheckDone: true,
			enableFeature:    true,
		},
		{
			usecase:          "no custom ruleset present with feature disabled",
			projDir:          filepath.Join(base, "wo-custom-ruleset"),
			rulesetCheckDone: false,
			enableFeature:    false,
		},
	}
	var errDone = errors.New("walk abort")
	for _, uc := range usecases {
		tt.Run(uc.usecase, func(t *testing.T) {
			// prepare
			isRulesetCheckDone = false          // reset global var
			custRulesEnabled = uc.enableFeature // reset global var
			if uc.enableFeature {
				t.Setenv(ruleset.EnvVarGitlabFeatures,
					ruleset.GitlabFeatureCustomRulesetsSAST) // enable customruleset feature
			}

			var matched bool
			err := filepath.Walk(uc.projDir, func(path string, info fs.FileInfo, err error) error {
				matches, err := Match(path, info)
				if err != nil {
					return err
				}
				if matches {
					matched = true
					return errDone
				}
				return nil
			})
			if err != nil && !errors.Is(err, errDone) {
				require.NoError(t, err)
			}
			require.True(t, matched)
			require.Equal(t, uc.rulesetCheckDone, isRulesetCheckDone)
		})
	}
}
