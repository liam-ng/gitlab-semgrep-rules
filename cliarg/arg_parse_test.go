package cliarg

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseFlags(t *testing.T) {
	testCases := []struct {
		testCase        string
		input           string
		wantFlags       []Arg
		wantInvalidArgs []string
	}{

		{
			testCase: "flags with a space separated value prefixed with a -/--",
			input:    "-flag1 value1 --flag2 value2",
			wantFlags: []Arg{
				{"-flag1", "value1", false},
				{"--flag2", "value2", false},
			},
		},
		{
			testCase: "flags with/without a space separated value prefixed with --",
			input:    "--flag1 value1 --flag2 --flag3 ",
			wantFlags: []Arg{
				{"--flag1", "value1", false},
				{"--flag2", "", true},
				{"--flag3", "", true},
			},
		},
		{
			testCase: "flags with a equal(=) separated value prefixed with a -/--",
			input:    "-flag1=value1 --flag2=value2",
			wantFlags: []Arg{
				{"-flag1", "value1", false},
				{"--flag2", "value2", false},
			},
		},
		{
			testCase: "flags with/without a space/= separated value prefixed with --",
			input:    "--flag1 value1 --flag2=value2 --flag3 -flag4:test=value4",
			wantFlags: []Arg{
				{"--flag1", "value1", false},
				{"--flag2", "value2", false},
				{"--flag3", "", true},
				{"-flag4:test", "value4", false},
			},
		},
		{
			testCase:        "invalid value2 with valid flag1",
			input:           "-flag1=value1 value2",
			wantFlags:       []Arg{{"--flag1", "value1", false}},
			wantInvalidArgs: []string{"value2"},
		},
		{
			testCase:        "invalid value1 and value2",
			input:           "value1 value2",
			wantInvalidArgs: []string{"value1", "value2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testCase, func(t *testing.T) {
			t.Parallel()
			gotFlags, gotInvalid := Parse(tc.input)
			require.Len(t, gotFlags, len(tc.wantFlags))
			require.Len(t, gotInvalid, len(tc.wantInvalidArgs))
			require.EqualValues(t, tc.wantInvalidArgs, gotInvalid)
			for _, got := range gotFlags {
				var foundEqual bool
				for _, want := range tc.wantFlags {
					if reflect.DeepEqual(got, want) {
						foundEqual = true
						break
					}
				}
				require.True(t, foundEqual)
			}
		})
	}
}
