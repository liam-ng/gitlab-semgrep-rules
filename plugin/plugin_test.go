package plugin

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ruleset "gitlab.com/gitlab-org/security-products/analyzers/ruleset/v2"
)

func TestMatch_LangExt(t *testing.T) {
	folderPath := filepath.Join("..", "testdata", "match-projects", "lang-match")
	t.Setenv(ruleset.EnvVarGitlabFeatures, "")
	err := filepath.Walk(folderPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		got, matchErr := Match(path, info)
		if matchErr != nil {
			return matchErr
		}
		filename := filepath.Base(path)
		want := strings.HasPrefix(filename, "match")
		require.Equalf(t, want, got, "expectation mismatch for file: %s", filename)
		return nil
	})
	require.NoError(t, err)
}

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
