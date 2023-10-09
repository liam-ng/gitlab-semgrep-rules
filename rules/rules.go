package rules

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

var (
	tagVerRegex       = regexp.MustCompile(`^v\d{1,3}(\.\d{1,3})?(\.\d{1,3})?(-.*)?$`)
	sastRulesRepoPath = "https://gitlab.com/gitlab-org/security-products/sast-rules.git"
)

// Pull pulls sast rules for the given git branch/tag and copies
// rulesets into the `targetDir` path
func Pull(ctx context.Context, gitBranchOrTagRef, targetDir string) error {
	repoDir := "/tmp/sast-rules"

	if e := os.MkdirAll(repoDir, os.ModePerm); e != nil {
		return e
	}

	if e := os.MkdirAll(targetDir, os.ModePerm); e != nil {
		return e
	}

	var refName plumbing.ReferenceName
	if plumbing.IsHash(gitBranchOrTagRef) {
		return errors.New("commit hash not supported")
	} else if tagVerRegex.MatchString(gitBranchOrTagRef) {
		refName = plumbing.NewTagReferenceName(gitBranchOrTagRef)
	} else {
		refName = plumbing.NewBranchReferenceName(gitBranchOrTagRef)
	}

	cloneOpts := git.CloneOptions{
		URL:           sastRulesRepoPath,
		Depth:         1,
		ReferenceName: refName,
		SingleBranch:  true,
	}

	if _, err := git.PlainCloneContext(ctx, repoDir, false, &cloneOpts); err != nil {
		return err
	}

	distDir := filepath.Join(repoDir, "dist")
	return copyRulesets(distDir, targetDir)
}

// copies rulesets from source directory to target directory
func copyRulesets(srcDir, targetDir string) error {
	return filepath.Walk(srcDir, func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yml") {
			return nil
		}
		targetFile := filepath.Join(targetDir, filepath.Base(path))
		return copy(path, targetFile)
	})
}

// copies the ruleset content from `src` file to `target` file
func copy(src, target string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(target)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
