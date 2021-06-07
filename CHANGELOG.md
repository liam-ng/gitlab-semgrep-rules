Semgrep analyzer changelog

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
