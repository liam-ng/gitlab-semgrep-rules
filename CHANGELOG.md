Semgrep analyzer changelog

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
