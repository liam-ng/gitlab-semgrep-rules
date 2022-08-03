Semgrep analyzer changelog

## v3.3.0
- Disables high-FP rules when `SAST_EXPERIMENTAL_FEATURES` is `true` (!135)

## v3.2.1
- upgrade [`Semgrep`](https://github.com/returntocorp/semgrep) version [`0.98.0` => [`0.104.0`](https://github.com/returntocorp/semgrep/releases/tag/v0.104.0)] (!133)
- upgrade `github.com/stretchr/testify` version [`v1.7.0` => [`v1.8.0`](https://github.com/stretchr/testify/releases/tag/v1.8.0)] (!133)
- upgrade `github.com/urfave/cli/v2` version [`v2.3.0` => [`v2.11.0`](https://github.com/urfave/cli/releases/tag/v2.11.0)] (!133)
- upgrade `gitlab.com/gitlab-org/security-products/analyzers/report/v3` version [`v3.11.0` => [`v3.12.2`](https://gitlab.com/gitlab-org/security-products/analyzers/report/-/releases/v3.12.2)] (!133)

## v3.2.0
- Upgrade the `common` and `command` packages, and remove no-op commands from the Dockerfile (!130)
  + Adds support for globstar patterns.
  + Resolves an issue using custom CA certs with the FIPS image
  + Removes commands from the Dockerfile that set up the `semgrep` user and assigns permissions to the `.pem` cert bundle, as they didn't have an effect

## v3.1.1
- Bypass language-based matching filter when custom ruleset contains Semgrep rules (!127)

## v3.1.0
- Bump semgrep version to [0.98.0](https://github.com/returntocorp/semgrep/releases/tag/v0.98.0) (!120)
    + Fixed: Fixed a non-deterministic crash when matching a large number of regexes
    + Changed: If a metrics event request times out, we no longer retry the request. This avoids Semgrep waiting 10-20 seconds before exiting if these requests are slow.
    + Changed: The metrics collection timeout has been raised from 2 seconds to 3 seconds.
    + Fixed: Handle utf-8 decoding errors without crashing
    + Changed: Parsing: fail fast on in semgrep-core if rules fail to validate

## v3.0.3
- Trim whitespace from values in `SAST_EXCLUDED_PATHS` (!123)
- Match `SAST_EXCLUDED_PATHS` values relative to the project root (!124)

## v3.0.2
- Fix dependencies conflict resolution via `--best --allowerasing` yum flags (!122)
- Remove redundant `yum update` operation in favor of `yum upgrade` (!122)

## v3.0.1
- Bumping gosec ruleset to v1.0.47 (!119)
    - Remove incorrect mapping to Gosec rule G104, which is not currently implemented
    - Add rule G402 to detect TLS versions before 1.2

## v3.0.0
- Bumping to `v3.0.0` (!114)

## v2.21.0
- Adding Java support (!111)

## v2.20.2
- Add custom CA support for FIPS docker image (!112)

## v2.20.1
- Add `Dockerfile.fips` and include FIPS image releases (!108)

## v2.20.0
- Update semgrep to [0.86.5](https://github.com/returntocorp/semgrep/releases/tag/v0.86.5) (!109)
    + 0.86.2 Notable Changes
      + Fixed: Some finding fingerprints were not matching what semgrep-agent would return.
    + 0.86.1 Notable Changes
      + Changed: --timeout-threshold default set to 3 instead of 0
    + 0.86.0 Notable Changes
      + Added: Go: use latest tree-sitter-go with support for Go 1.18 generics
      + Changed: Findings are now considered identical between baseline and current scans based on the same logic as Semgrep CI uses, which means:
        + Two findings are now identical after whitespace changes such as re-indentation
        + Two findings are now identical after a nosemgrep comment is added
      + Changed: Findings are now different if the same code triggered them on different lines
      + Fixed: Symlinks found in directories are skipped from being scanned again. This is a fix for a regression introduced in 0.85.0.
      + Fixed: Go: fix unicode parsing bugs by switching to latest tree-sitter-go
      + Fixed: Constant propagation: A conditional expression where both alternatives are constant will also be considered constant
      + Fixed: Constant propagation now recognizes operators ++ and -- as side-effectful
    + 0.85.0 Notable Changes
      + Added: When scanning multiple languages, Semgrep will now print a table of how many rules and files are used for each language.
      + Fixed: Fixed Deep expression matching and metavariables interaction. Semgrep will not stop anymore at the first match and will enumarate all possible matchings if a metavariable is used in a deep expression pattern (e.g., <... $X ...>). This can introduce some performance regressions.
      + Fixed: JSX: ellipsis in JSX body (e.g., <div>...</div>) now matches any children (#4678 and #4717)
      + Changed: When git ls-files is unavailable or --disable-git-ignore is set, Semgrep walks the file system to find all target files. Semgrep now walks the file system 30% faster compared to previous versions.

## v2.19.1
- Fixed Docker build issue (!107)

## v2.19.0 (Unreleased due to build issues)
- Update semgrep to [0.84.0](https://github.com/returntocorp/semgrep/releases/tag/v0.84.0) (!106)
    + 0.84.0 Notable Changes
      + Fixed: Report parse errors even when invoked with --strict
      + Fixed: SARIF output formatter not handling lists of OWASP or CWE metadata
      + Fixed: Scan yarn.lock dependencies that do not specify a hash
    + 0.83.0 Notable Changes
      + Fixed: Treat Go raw string literals like ordinary string literals
      + Changed: Improved constant propagation for global constants

## v2.18.1
- Update `report` module containing fix for the issue: [#344616](https://gitlab.com/gitlab-org/gitlab/-/issues/344616) (!105)

## v2.18.0
- Update semgrep to [0.82.0](https://github.com/returntocorp/semgrep/releases/tag/v0.82.0) (!98)
    + 0.82.0 Notable Changes
      + Changed: Performance: send all rules directly to semgrep-core instead of invoking semgrep-core
      + Changed: Scans now report a breakdown of how many target paths were skipped for what reason.
      + Changed: Performance: send all rules directly to semgrep-core instead of invoking semgrep-core for each rule, reducing the overhead significantly. Other changes resulting from this: Sarif output now includes all rules run. Error messages use full path of rules. Progress bar reports by file instead of by rule
      + Changed: Bloom filter optimization now considers import module file names, thus speeding up matching of patterns like import { $X } from 'foo'
    + 0.81.0 Notable Changes
      + Fixed: Gracefully handle timeout errors with missing rule_id
    + 0.80.0 Notable Changes
      + Changed: Ruby: a metavariable matching an atom can also be used to match an identifier with the same name
      + Fixed: Handle missing target files without raising an exception
    + 0.79.0 Notable Changes
      + None for GitLab users
    + 0.78.0 Notable Changes
      + Added: Semgrep is now able to symbolically propagate simple definitions. E.g., given an assignment x = foo.bar() followed by a call x.baz(), Semgrep will keep track of x's definition, and it will successfully match x.baz() with a pattern like foo.bar().baz(). This feature should help writing simple yet powerful rules, by letting the dataflow engine take care of any intermediate assignments. Symbolic propagation is still experimental and it is disabled by default, it must be enabled in a per-rule basis using options: and setting symbolic_propagation: true. (#2783, #2859, #3207)
      + Added: metavariable-comparison now handles metavariables that bind to arbitrary constant expressions (instead of just code variables)
      + Fixed: Python: return statement can contain tuple expansions
      + Fixed: metavariable-comparison: do not throw a Not_found exn anymore
      + Fixed: better ordering of match results with respect to captured metavariables
      + Fixed: Go, JavaScript, Java, Python, TypeScript: correct matching of multibyte characters
    + 0.77.0 Notable Changes
      + Fixed: Go: fixed bug where using an ellipsis to stand for a list of key-value pairs would sometimes cause a parse error
      + Fixed: Allow name resolution on imported packages named just vN, where N is a number
      + Fixed: Python: get the correct range when matching comprehension
      + Fixed: Python and other languages: allow matches of patterns containing non-ascii characters, but still with possibly many false positives
      + Changed: Constant propagation is now a proper must-analysis, if a variable is undefined in some path then it will be considered as non-constant
      + Changed: semgrep-core will log a warning when a worker process is consuming above 400 MiB of memory, or reached 80% of the specified memory limit, whatever happens first. This is meant to help diagnosing OOM-related crashes.

## v2.17.0
- Update ruleset, report, and command modules to support ruleset overrides (!102)

## v2.16.1
- Update to gosec rulset v1.0.28 to fix [this issue](https://gitlab.com/gitlab-org/gitlab/-/issues/348952) (!96)

## v2.16.0
- Update semgrep to [0.76.2](https://github.com/returntocorp/semgrep/releases/tag/v0.76.2) (!#)
    + 0.76.2 Notable Changes
      + Fixed: Python: set the right scope for comprehension variables
      + Fixed: Fixed bug where the presence of .semgrepignore would cause reported targets to have absolute instead of relative file paths
    + 0.76.1 Notable Changes
      + Fixed: Fixed bug where the presence of .semgrepignore would cause runs to fail on files that were not subpaths of the directory where semgrep was being run
    + 0.76.0 Notable Changes
      + Added: Improved filtering of rules based on file content (important speedup for nodejsscan rules notably)
      + Fixed: TS: parse correctly type definitions
      + Fixed: taint-mode: Findings are now reported when the LHS of an access operator is a sink (e.g. as in $SINK->method), and the LHS operand is a tainted variable
      + Fixed: metavariable-comparison: do not throw a NotHandled exn anymore
      + Fixed: Python: generate proper lexical exn for unbalanced braces
      + Fixed: Python: generate proper lexical exn for unbalanced braces
      + Fixed: Matching "$MVAR" patterns against string literals computed by constant folding no longer causes a crash
      + Changed: semgrep-core: Log messages are now tagged with the process id
      + Changed: Optimization: change bloom filters to use sets, move location of filter
      + Changed: Reduced the size of --debug dumps
      + Changed: Given --output Semgrep will no longer print search results to stdout, but it will only save/post them to the specified file/URL
    + 0.75.0 Notable Changes
      + Fixed: semgrep-ci relies on --disable-nosem still tagging findings with is_ignored correctly. Reverting optimization in 0.74.0 that left this field None when said flag was used
    + 0.74.0 Notable Changes
      + Added: Support for method chaining patterns in Python, Golang, Ruby, and C#, so all GA languages now have method chaining
      + Changed: Constant propagation: Any kind of Python string (raw, byte, or unicode) is now evaluated to a string literal and can be matched by "..."
      + Fixed: Apply generic filters excluding large files and binary files to 'generic' and 'regex' targets as it was already done for the other languages.
      + Fixed: Fix some Stack_overflow when using -filter_irrelevant_rules
    + 0.73.0 Notable Changes
      + Changed: cli: if an invalid config is passed to semgrep, it will fail immediately, even if valid configs are also passed
      + Fixed: Performance: Deduplicate rules by rule-id + behavior so rules are not being run twice
      + Fixed: Catch PCRE errors
      + Fixed: Constant propagation: Avoid "Impossible" errors due to unhandled cases

## v2.15.0
- Update ruleset module to include rule pack synthesis + corresponding test cases/expectations (!93)

## v2.14.0
- Update semgrep to [0.72.0](https://github.com/returntocorp/semgrep/releases/tag/v0.72.0) (!92)
    + 0.72.0 Notable Changes
      + Added: Dataflow: Add partial support for await, yield, &, and other expressions
      + Added: Field-definition-as-assignemnt equivalence that allows matching expression patterns against field definitions. It is disabled by default but can be enabled via rule options: with flddef_assign: true
      + Added: Arrows (a.k.a short lambdas) patterns used to match also regular function definitions. This can now be disabled via rule options: with arrow_is_function: false
      + Added: Javascript variable patterns using the 'var' keyword used to also match variable declarations using 'let' or 'const'. This can now be disabled via rule options: with let_is_var: false
      + Fixed: Constant propagation: In a method call x.f(y), if x is a constant then it will be recognized as such
      + Fixed: Go: match correctly braces in composite literals for autofix
      + Fixed: Go: match correctly parens in cast for autofix
      + Fixed: Go: support ellipsis in return type parameters
      + Fixed: pattern-regex: Hexadecimal notation of Unicode code points is now supported and assumes UTF-8
      + Fixed: pattern-regex: Update documentation, specifying we use PCRE
      + Fixed: metavariable-comparison: if a metavariable binds to a code variable that is known to be constant, then we use that constant value in the comparison
    + 0.71.0 Notable Changes
      + Added: Metavariable equality is enforced across sources/sanitizers/sinks in taint mode, and these metavariables correctly appear in match messages
      + Added: semgrep --validate runs metachecks on the rule
      + Fixed: text_wrapping defaults to MAX_TEXT_WIDTH if get_terminal_size reports width < 1
      + Fixed: Metrics report the error type of semgrep core errors (Timeout, MaxMemory, etc.)
      + Fixed: Prevent bad settings files from crashing Semgrep
      + Fixed: Constant propagation: Tuple/Array destructuring assignments now correctly prevent constant propagation
      + Fixed: JS: Correctly parse metavariables in template strings
      + Fixed: Go: support method interface pattern
      + Changed: Report CI environment variable in metrics for better environment determination
      + Changed: Bash: a simple expression pattern can now match any command argument rather than having to match the whole command
    + 0.70.0 Notable Changes
      + Fixed: Go: support ... in import list, for example import (... "error" ...)

## v2.13.7
- chore: Update go to v1.17 (!91)

## v2.13.6
- fix: Return only on exitcode 4 or 7, rely on sarif module for runtime exceptions (!88)

## v2.13.5
- chore: Use ruleset.TransformToGLSASTReport (!89)

## v2.13.4
- fix: Return non-zero exit codes when executed through entrypoint script (!84)

## v2.13.3
- chore: Use ruleset.ProcessPassthrough helper (!81)

## v2.13.2
- fix: Return non-zero exit codes (!80)
- chore: suppress `--disable-version-check` warning if outdated version (!80)

## v2.13.1
- Update semgrep to [0.69.1](https://github.com/returntocorp/semgrep/releases/tag/v0.69.1) (!83)
    + 0.69.1 Notable Changes
      + Fixed: The --enable-metrics flag is now always a flag, does not optionally take an argument

## v2.13.0
- Update semgrep to [0.69.0](https://github.com/returntocorp/semgrep/releases/tag/v0.69.0) (!82)
    + 0.69.0 Notable Changes
      + Added: C: support ... in parameters and sizeof arguments
      + Added: C: support declaration and function patterns
      + Fixed: Reverted change to exclude minified files from the scan (see changelog for 0.66.0)
      + Fixed: Python: fix range of tuples
      + Fixed: C: fix some wrong typedef inference
      + Fixed: Ruby: put back equivalence on old syntax for keyword arguments
      + Changed: taint-mode: Introduce a new kind of not conflicting sanitizer that must be declared with not_conflicting: true. This affects the change made in 0.68.0 that allowed a sanitizer like - pattern: $F(...) to work, but turned out to affect our ability to specify sanitization by side-effect. Now the default semantics of sanitizers is reverted back to the same as before 0.68.0, and - pattern: $F(...) is supported via the new not-conflicting sanitizers.
    + 0.68.2 Notable Changes
      + Fixed: taint-mode: Fixed (another) bug where a tainted sink could go unreported when the sink is a specific argument in a function call
    + 0.68.1 Notable Changes
      + Added: Added support for raise/throw expressions in the dataflow engine and improved existing support for try-catch-finally
      + Fixed: Respect rule level path filtering
    + 0.68.0 Notable Changes
      + Changed: taint-mode: Sanitizers that match exactly a source or a sink are filtered out, making it possible to use - pattern: $F(...) for declaring that any other function is a sanitizer
      + Changed: taint-mode: Remove built-in source source(...) and built-in sanitizer sanitize(...) used for convenience during early development, this was causing some unexpected behavior in real code that e.g. had a function called source!
      + Changed: Resolution of rulesets (i.e. p/ci) use new rule cdn and do client-side hydration
      + Changed: Set pcre recursion limit so it will not vary with different installations of pcre
      + Changed: Better pcre error handling in semgrep-core
      + Fixed: taint-mode: Fixed bug where a tainted sink could go unreported when the sink is a specific argument in a function call
    + 0.67.0 Notable Changes
      + Added: Added support for break and continue in the dataflow engine
      + Added: Added support for switch statements in the dataflow engine
      + Changed: Taint no longer analyzes dead/unreachable code
      + Changed: Improve error message for segmentation faults/stack overflows
      + Changed: Attribute-expression equivalence that allows matching expression patterns against attributes, it is enabled by default but can be disabled via rule options: with attr_expr: false
      + Fixed: Fix CFG dummy nodes to always connect to exit node
      + Fixed: Deep ellipsis <... x ...> now matches sub-expressions of statements
      + Fixed: Ruby: treat 'foo' as a function call when alone on its line
      + Fixed: Fixed bug in semgrep-core's -filter_irrelevant_rules causing Semgrep to incorrectly skip a file
    + 0.66.0 Notable Changes
      + Changed: Constant propagation now assumes that void methods may update the callee
      + Changed: Various changes to error messages
      + Changed: Minified files are now automatically excluded from the scan, which may result in shorter scanning times for some projects.
      + Fixed: Dataflow: Recognize "concat" method and interpret it in a language-dependent manner

## v2.12.0
- gosec rule-set (!76)

## v2.11.0
- Update semgrep to [0.65.0](https://github.com/returntocorp/semgrep/releases/tag/v0.65.0) (!79)
    + 0.65.0 Notable Changes
      + Fixed: Taint detection with ternary ifs
      + Fixed: Fixed corner-case crash affecting the pattern: $X optimization ("empty And; no positive terms in And")
      + Fixed: Fix semgrep-core crash when a cache file exceeds the file size limit
      + Fixed: Sped up Semgrep interface with tree-sitter parsing
    + 0.64.0 Notable Changes
      + Added: Enable associative matching for string concatenation
      + Changed: Add logging on failure to git ls-files
      + Changed: Ignore files whose contents look minified
      + Changed: Display semgrep-core errors in a better way
      + Fixed: Taint mode will now benefit from semgrep-core's -filter_irrelevant_rules
      + Fixed: Taint mode should no longer report duplicate matches
      + Fixed: Only change source directory when running in docker context
    + 0.63.0 Notable Changes
      + Fixed: Dataflow: Disregard type arguments but not the entire instruction
      + Changed: Optimize ending ... in pattern-insides to simply match anything left
    + 0.62.0 Notable Changes
      + Added: Add help text to sarif formatter output if defined in metadata field.
      + Added: Update shortDescription in sarif formatter output if defined in metadata field.
      + Added: Add tags as defined in metadata field in addition to the existing tags.
      + Fixed: core: Fix parsing of numeric literals in rule files
      + Fixed: Generic mode scanner no longer tries to open submodule folders as files
      + Fixed: pattern-regex with completely empty files
      + Fixed: --sarif exit code with suppressed findings
      + Fixed: Fixed fatal errors when a pattern results in a large number of matches
      + Fixed: Better error message when rule contains empty pattern
      + Changed: Add backtrace to fatal errors reported by semgrep-core
      + Changed: Report errors during rule evaluation to the user
      + Changed: When anded with other patterns, pattern: $X will not be evaluated on its own, but will look at the context and find $X within the metavariables bound, which should be significantly faster
    + 0.61.0 Notable Changes
      + Changed: Run version check and print upgrade message after scan instead of before
      + Changed: Memoize range computation for expressions and speed up taint mode
      + Changed: Report semgrep-core's message upon a parse error
      + Changed: Deprecated the following experimental features:
          + pattern-where-python
          + taint-mode
          + equivalences
          + step-by-step evaluation output
      + Changed: Deduplicate findings that fire on the same line ranges and have the same message.
      + Fixed: core: Do not crash when is not possible to compute range info
      + Fixed: eliminate 6x slowdown when using the '--max-memory' option

## v2.10.1
- update tracking calculator (!78)

## v2.10.0
- flawfinder rule-set (!74)

## v2.9.4
- Update semgrep to [0.60.0](https://github.com/returntocorp/semgrep/releases/tag/v0.60.0) (!72)
    + 0.60.0 Notable Changes
      + Added: Detect duplicate keys in YAML dictionaries in semgrep rules when parsing a rule (e.g., detect multiple 'metavariable' inside one 'metavariable-regex')
      + Fixed: JS: Fixed stack overflows (segmentation faults) when processing very large files
      + Fixed: JS: Detect numeric object keys 1 and 0x1 as equal
      + Fixed: taint-mode: Check nested functions
      + Fixed: taint-mode: foo.x is now detected as tainted if foo is a source of taint
      + Fixed: taint-mode: Do not crash when is not possible to compute range info
      + Changed: Added precise error location for the semgrep metachecker, to detect for example duplicate patterns in a rule
    + 0.59.0 Notable Changes
      + Fixed: Improve location reporting of errors metavariable-pattern: pattern-not-regex now works
      + Fixed: Python: imports are unsugared correctly

## v2.9.3
- Update tracking calculator (!71)

## v2.9.2
- Update semgrep to [0.58.2](https://github.com/returntocorp/semgrep/releases/tag/v0.58.2) (!68)
    + 0.58.2 Notable Changes
      + Fixed: Significant speed improvements, but the binary is now 95MB (from 47MB in 0.58.1, but it was 170MB in 0.58.0)
    + 0.58.1 Notable Changes
      + Changed: Switch from OCaml 4.10.0 to OCaml 4.10.2 (and later to OCaml 4.12.0) resulted in smaller semgrep-core binaries (from 170MB to 47MB) and a smaller docker image (from 95MB to 40MB).
    + 0.58.0 Notable Changes
      + Added: New iteration of taint-mode that allows to specify sources/sanitizers/sinks using arbitrary pattern formulas. This provides plenty of flexibility. Note that we breaks compatibility with the previous taint-mode format, e.g. source(...) must now be written as - pattern: source(...).
      + Added: HTML experimental support. This does not rely on the "generic" mode but instead really parses the HTML using tree-sitter-html. This allows some semantic matching (e.g., matching attributes in any order).
      + Added: Vue.js alpha support
      + Added: New matching option implicit_ellipsis that allows disabling the implicit ... that are added to record patterns, plus allow matching "spread fields" (JS ...x) at any position
      + Added: Support globstar (**) syntax in path include/exclude
      + Fixed: Ruby command shells are distinguished from strings (#3343)
      + Fixed: Java varargs are now correctly matched (#3455)
      + Fixed: Support for partial statements (e.g., try { ... }) for Java (#3417)
      + Fixed: Java generics are now correctly stored in the AST (#3505)
      + Fixed: Constant propagation now works inside Python with statements (#3402)
      + Fixed: Metavariable value replacement in message/autofix no longer mixes up short and long names like $X vs $X2 (#3458)
      + Fixed: Fixed metavariable name collision during interpolation of message / autofix (#3483)
      + Fixed: Revert pattern: $X optimization (#3476)
      + Fixed: metavariable-pattern: Allow filtering using a single pattern or pattern-regex
      + Fixed: Dataflow: Translate call chains into IL
      + Changed: Faster matching times for generic mode

## v2.9.1
- Update semgrep to [0.57.0](https://github.com/returntocorp/semgrep/releases/tag/v0.57.0) (!67)
  + 0.57.0 Changes:
    + Add: new options: field in a YAML rule to enable/disable certain features (e.g., constant propagation).
    + Add: capture groups in pattern-regex: in $1, $2, etc.
    + Add: support metavariables inside atoms (e.g., foo(:$ATOM))
    + Add: support metavariables and ellipsis inside regexp literals (e.g., foo(/.../))
    + Add: associative-commutative matching for bitwise OR, AND, and XOR operations
    + Add: support for $...MVAR in generic patterns.
    + Add: metavariable-pattern: Add support for nested Spacegrep/regex/Comby patterns
    + Add: C#: support ellipsis in method parameters
    + Fixed: C#: parse \_\_makeref, \_\_reftype, \_\_refvalue
    + Fixed: Java: parsing of dots inside function annotations with brackets
    + Fixed: Do not pretend that short-circuit Boolean AND and OR operators are commutative
    + Fixed: metavariable-pattern: Fix crash when nesting a non-generic pattern within a generic rule
    + Fixed: metavariable-pattern: Fix parse info when matching content of a metavariable under a different language
    + Fixed: metavariable-comparison: Fix crash when comparing integers and floats
    + Fixed: generic mode on Markdown files with very long lines will now work
    + Changed: generic mode: files that don't look like nicely-indented programs are no longer ignored, which may cause accidental slowdowns in setups where excessively large files are not excluded explicitly
    + Changed: Do not filter findings with the same range but different metavariable bindings
    + Changed: Set parsing_state.have_timeout when a timeout occurs
    + Changed: Set a timeout of 10s per file
    + Changed: Memoize getting ranges to speed up rules with large ranges
    + Changed: When anded with other patterns, pattern: $X will not be evaluated on its own, but will look at the context and find $X within the metavariables bound, which should be significantly faster
  + 0.56.0 Changes:
    + Add: associative-commutative matching for Boolean AND and OR operations
    + Add: support metavariables inside strings (e.g., foo("$VAR"))
    + Add: support metavariables inside atoms (e.g., foo(:$ATOM))
    + Add: metavariable-pattern: Allow matching the content of a metavariable under a different language.
    + Fixed: C#: Parse attributes for local functions
    + Fixed: Go: Recognize other common package naming conventions
    + Changed: Upgrade TypeScript parser

## v2.9.0
- Add identifier URLs to reports (!65 @mschwager)

## v2.8.2
- Fix False Positive in eslint.detect-non-literal-regexp (!63 @colleend)

## v2.8.1
- Fixed typo in ruleid (!60)

## v2.8.0
- Add [tracking calculator](https://gitlab.com/gitlab-org/security-products/post-analyzers/tracking-calculator) to semgrep (!56)

## v2.7.0
- Update semgrep to [0.55.1](https://github.com/returntocorp/semgrep/releases/tag/v0.55.1) (!53 @brendongo)
  + Add helpUri to sarif output if rule source metadata is defined
  + Fixed wrong line numbers for multi line generic mode
  + Support ellisis in try-except in Python
  + Run with optimizations on by default
  + Other fixes and additions described in https://github.com/returntocorp/semgrep/releases/tag/v0.55.1
- Use helpUri field in sarif output to attach URL to rule primary identifier

## v2.6.0
- Update Semgrep to [0.54.0](https://github.com/returntocorp/semgrep/releases/tag/v0.54.0) (!48 @mschwager)
  + Changed JSON and SARIF outputs sort keys for predictable results
  + Moved some debug logging to verbose logging
  + Added Per rule parse times and per rule-file parse and match times added to opt-in metrics
  + Some fixes and additions described in https://github.com/returntocorp/semgrep/releases/tag/v0.54.0

## v2.5.1
- Set SEMGREP_USER_AGENT_APPEND to GitLab SAST (!49 @brendongo)

## v2.5.0
- SAST_EXCLUDED_PATHS is passed to semgrep to exclude as semgrep runs (!47)

## v2.4.2
- Add `git` to docker image for Semgrep internals to use (!40 @chmccreery)

## v2.4.1
- Upgrade the `command` package to `v1.1.1` to enable better log messages (!39)

## v2.4.0
- Enable semgrep telemetry (!37)

## v2.3.1
- Fix: Enable bandit rules B301-2/B307 (!34 @underyx)

## v2.3.0
- Speed up eslint.detect-object-injection (!32 @r2c_nathan @mschwager)
- Upgrade semgrep to 0.50.1 (!32)
    + JS/TS: Infer global constants even if the const qualifier is missing (#2978)
    + Support for matching multiple arguments with a metavariable (#3009) This is done with a 'spread metavariable' operator that looks like $...ARGS. This used to be available only for JS/TS and is now available for the other languages (Python, Java, Go, C, Ruby, PHP, and OCaml).
    + JS/TS: Support '...' inside JSX text to match any text, as in <a href="foo">...</a> (#2963)
    + JS/TS: Support metavariables for JSX attribute values, as in <a href=$X>some text</a> (#2964)
    + Python: correctly parsing fstring with multiple colons
    + Remove jsx and tsx from languages, just use javascript or typescript (#3000)
    + Capturing functions when used as both expressions and statements in JS (#1007)
    + Ability to match lambdas or functions in Javascript with ellipsis after the function keyword, (e.g., function ...(...) { ... })
    + support for utf-8 code with non-ascii chars (#2944)
    + JSX/TSX: fixed the range of matched JSX elements (#2685)
    + Javascript: allow ellipsis in arrow body (#2802)
    + Official Python 3.9 support
    + Added basic typed metavariables for javascript and typescript (#2588)
    + ability to process a whole rule in semgrep-core; this will allow whole-rule optimisations and avoid some fork and communication with the semgrep Python wrapper
    + Caching improvements for semgrep-core
    + Matching performance improvements
    + Typescript grammar upgraded
    + Import statements for CommonJS Typescript modules now supported. (#2234)

## v2.2.0
- Support semgrep rule override via the custom ruleset passthrough property (!30)

## v2.1.1
- Fix major version in .gitlab-ci.yml so that the major docker release tag is 2 (!28)

## v2.1.0
- Add `strict`, `no-git-ignore`, and `--no-rewrite-rules` to semgrep flags (!27)

## v2.0.0
- Bump to version 2 so we can support semgrep in the GitLab config UI while we're waiting to remove
  `SAST_ANALYZER_IMAGE_TAG` (!22)

## v0.10.1
- No change patch to allow release pipelines to pass (!26)

## v0.10.0
- Add Description field to vulnerabilities (!24)

## v0.9.0
- Update Dockerfile to support OpenShift (!23)

## v0.8.0
- Add eslint identifiers and update identifier helpers in convert.go (!19)

## v0.7.0
- Update report dependency in order to use the report schema version 14.0.0 (!17)

## v0.6.1
- Add react-dangerouslysetinnerhtml semgrep rule (!16)
- Add detect-non-literal-regexp semgrep rule (!16)
- Add detect-non-literal-fs-filename (!16)
- Add detect-object-injection (!16)

## v0.6.0
- Add eslint and react rule-sets (!12)

## v0.5.0
- Add bandit identifier to `Report.Vulnerabilities` (!10)

## v0.4.0
- Fix paths in report to be relative to project root (!6)
- Update Dockerfile to give us control over base image (!6)
- Update sarif package to support multiple runs and locations (!6)

## v0.3.0
- OWASP metadata added to bandit rule-set (!9)

## v0.2.0
- Bandit rule-set (!2)

## v0.0.1
- First pass at things (!1)
