package cliarg

import (
	"regexp"
	"strings"
)

// argNameRegex is the regexp for CLI arg name along with optional value separated by =.
// arg name should start with either -- or -
// arg name should have alphanumeric but optionally underscore(_) and hyphen(-)
var argNameRegex = regexp.MustCompile(`^(--|-)(\w+(.\w+)?)(=.+)?$`)

// Arg represents a CLI arg and its corresponding value
type Arg struct {
	Name, Value string
	IsFlag      bool
}

// Parse parses `argStr` to CLI args/flags separated by spaces and returns it in a slice of CLIArg.
// An arg name is represented with a prefix of `-` or `--`. An arg without value is treated as "flag".
// Arg's value is represented by placing right after its arg name separated by a space or equals(=).
//
// NOTE: If any char is used as value separator other than space or equal(=), the string will be treated as flag.
//
// Some of the input to output examples:
//
// 1. "--arg1"                        >> CLIArg {name: --arg1, flag: true}
// 2. "--arg1 val"                    >> CLIArg {name: --arg1, value: val, flag: false}
// 3. "--arg1=val"                    >> CLIArg {name: --arg1, value: val, flag: false}
// 4. "-a"                            >> CLIArg {name: -a, flag: true}
// 5. "-a val"                        >> CLIArg {name: -a, value: val, flag: false}
// 6. "-a=val"                        >> CLIArg {name: -a, value: val, flag: false}
func Parse(argStr string) (args []Arg, invalidArgs []string) {
	var currArgName string
	for _, arg := range strings.Split(argStr, " ") {
		arg = strings.TrimSpace(arg)
		if argNameRegex.MatchString(arg) {
			if currArgName != "" {
				args = append(args, Arg{Name: currArgName, IsFlag: true})
				currArgName = ""
			}
			name, value, hasValue := extractArgFragments(arg)
			if hasValue {
				args = append(args, Arg{Name: name, Value: value})
			} else {
				currArgName = name
			}
		} else {
			if currArgName == "" {
				invalidArgs = append(invalidArgs, arg) // value with no arg name
				continue
			}
			args = append(args, Arg{Name: currArgName, Value: arg})
			currArgName = ""
		}
	}
	if currArgName != "" {
		args = append(args, Arg{Name: currArgName, IsFlag: true})
	}
	return
}

// extractArgFragments extracts arg fragments i.e., name, value(if exists) from the "--arg=value" format
func extractArgFragments(val string) (name, value string, hasValue bool) {
	segs := strings.SplitN(val, "=", 2)
	name = segs[0]
	if hasValue = len(segs) > 1; hasValue {
		value = segs[1]
	}
	return
}
