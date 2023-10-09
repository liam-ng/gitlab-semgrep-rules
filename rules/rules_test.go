package rules

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPullRules(t *testing.T) {
	err := Pull(context.Background(), "v1.3.39", "ruledata")
	require.NoError(t, err)

}
