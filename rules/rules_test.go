package rules

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/stretchr/testify/require"
)

func TestPullRules(t *testing.T) {
	testdata := []struct {
		usecase   string
		refName   string
		fail      bool
		noCleanup bool
	}{
		{
			usecase: "when using a branch",
			refName: "main", // branch
		},
		{
			usecase: "when using a tag",
			refName: "v1.3.39", // tag
		},
		{
			usecase: "when using a non-existent branch",
			refName: "blah", // non existent
			fail:    true,
		},
	}

	for i := range testdata {
		test := testdata[i]
		t.Run(test.usecase, func(t *testing.T) {
			path, err := Pull(context.Background(), test.refName)
			if test.fail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, DefaultRulesetPath, path)
			require.DirExists(t, path)
			fs, err := os.Open(path)
			require.NoError(t, err)
			fileDirs, err := fs.Readdirnames(-1)
			require.NoError(t, err)
			require.True(t, len(fileDirs) > 0)
			t.Cleanup(func() { os.RemoveAll(targetCloneDir) })
		})
	}
}

func TestReusePulledRulesets(t *testing.T) {
	_, err := Pull(context.Background(), "main")
	require.NoError(t, err)

	var buf bytes.Buffer
	log.SetLevel(log.DebugLevel)
	log.SetOutput(&buf)

	// invoke Pull(...) again
	path, err := Pull(context.Background(), "main")
	require.NoError(t, err)

	want := fmt.Sprintf("reusing SAST rules from %s", DefaultRulesetPath)
	got := buf.String()
	require.Contains(t, got, want)

	require.Equal(t, DefaultRulesetPath, path)
	require.DirExists(t, path)
	fs, err := os.Open(path)
	require.NoError(t, err)
	fileDirs, err := fs.Readdirnames(-1)
	require.NoError(t, err)
	require.True(t, len(fileDirs) > 0)

	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		os.RemoveAll(targetCloneDir)
	})

}
