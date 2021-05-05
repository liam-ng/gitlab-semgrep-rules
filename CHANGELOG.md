Semgrep analyzer changelog

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
