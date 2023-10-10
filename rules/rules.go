package rules

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	log "github.com/sirupsen/logrus"
)

var (
	// DefaultRulesetPath is the directory path where the default SAST rulesets are stored.
	// By default, it is set to '/tmp/sast-rules/dist'
	DefaultRulesetPath = filepath.Join(targetCloneDir, "dist") // /tmp/sast-rules/dist

	targetCloneDir  = filepath.Join("/", "tmp", "sast-rules")
	tagVersionRegex = regexp.MustCompile(`^v\d{1,3}(\.\d{1,3})?(\.\d{1,3})?(-.*)?$`)
	sastRulesGit    = "https://gitlab.com/gitlab-org/security-products/sast-rules.git"
)

// Pull clones sast rules for the given git branch/tag and returns
// the directory path where the distribution rules are stored.
func Pull(ctx context.Context, gitBranchOrTag string) (string, error) {

	// reuse rulesets if they're already pulled into the ruleset path
	if _, e := os.Stat(DefaultRulesetPath); e == nil {
		log.Debugf("reusing SAST rules from %s", DefaultRulesetPath)
		return DefaultRulesetPath, nil
	}

	if log.GetLevel() == log.DebugLevel {
		log.Debugf("pulling SAST rules - repository: %s, ref: %s, target-dir: %s",
			sastRulesGit, gitBranchOrTag, targetCloneDir)
	} else {
		log.Infof("pulling SAST rules - version: %s", gitBranchOrTag)
	}
	// create clone repo directory if not created
	if e := os.MkdirAll(targetCloneDir, os.ModePerm); e != nil {
		return "", e
	}

	var refName plumbing.ReferenceName
	if plumbing.IsHash(gitBranchOrTag) {
		return "", errors.New("commit hash not supported")
	} else if tagVersionRegex.MatchString(gitBranchOrTag) {
		refName = plumbing.NewTagReferenceName(gitBranchOrTag)
	} else {
		refName = plumbing.NewBranchReferenceName(gitBranchOrTag)
	}

	_, err := git.PlainCloneContext(ctx, targetCloneDir, false, &git.CloneOptions{
		URL:           sastRulesGit,
		Depth:         1,
		ReferenceName: refName,
		SingleBranch:  true,
	})
	if err != nil {
		return "", err
	}

	quietCleanup(targetCloneDir)

	return DefaultRulesetPath, nil
}

// quietCleanup removes all the files and directories in the given
// `path` arg except ruleset directory(rules.DefaultRulesetPath).
// This op does not fail on error since it is an auxillary operation.
func quietCleanup(path string) {
	log.Debugf("Cleaning up %q excluding ruleset dir(%s)", targetCloneDir, DefaultRulesetPath)

	fs, err := os.Open(path)
	if err != nil {
		log.Debugf("Failed to open %q, skipping rules cleanup", err)
		return
	}

	dirs, err := fs.Readdirnames(-1)
	if err != nil {
		log.Debugf("Failed to read directories in %q, skipping rules cleanup", err)
		return
	}

	for _, dir := range dirs {
		absPath := filepath.Join(path, dir)
		if absPath == DefaultRulesetPath {
			continue
		}
		_ = os.RemoveAll(absPath) // let it fail silently and continue with other dirs
	}
}

// func filterRulesetsByTier(rulesetPath string) {

// }
