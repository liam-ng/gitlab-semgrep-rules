# When updating version make sure to check on semgrepignore file as well
ARG SCANNER_VERSION=0.115.0
ARG POST_ANALYZER_SCRIPTS_VERSION=0.0.5
ARG TRACKING_CALCULATOR_VERSION=2.2.5

FROM registry.gitlab.com/security-products/post-analyzers/scripts:${POST_ANALYZER_SCRIPTS_VERSION} AS scripts
FROM registry.gitlab.com/security-products/post-analyzers/tracking-calculator:${TRACKING_CALCULATOR_VERSION} AS tracking

FROM golang:1.17-alpine AS build
ARG SAST_RULES_VERSION=1.1.3
ARG SAST_RULES_URL=https://gitlab.com/gitlab-org/secure/gsoc-sast-vulnerability-rules/playground/sast-rules/-/archive

ENV CGO_ENABLED=0 GOOS=linux

WORKDIR /go/src/buildapp
COPY . .

RUN apk add --no-cache tar curl && \
    mkdir -p /archive && \
    curl -o rules.tar.gz ${SAST_RULES_URL}/v${SAST_RULES_VERSION}/sast-rules-v${SAST_RULES_VERSION}.tar.gz && tar --strip-components=1 -xf rules.tar.gz -C /archive

# variable to the most recent version from the CHANGELOG.md file
RUN CHANGELOG_VERSION=$(grep -m 1 '^## v.*$' "CHANGELOG.md" | sed 's/## v//') && \
        PATH_TO_MODULE=`go list -m` && \
        go build -ldflags="-X '$PATH_TO_MODULE/metadata.AnalyzerVersion=$CHANGELOG_VERSION'" -o /analyzer-semgrep

FROM python:3.9-alpine

ARG SCANNER_VERSION
ENV SCANNER_VERSION ${SCANNER_VERSION}
ENV SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE "/semgrepignore"

RUN mkdir -p /etc/ssl/certs/ && \
    touch /etc/ssl/certs/ca-certificates.crt && \
    chmod g+w /etc/ssl/certs/ca-certificates.crt

COPY --from=build /analyzer-semgrep /analyzer-binary
COPY --from=build /archive/dist /rules
COPY semgrepignore /semgrepignore
RUN mkdir /.cache && \
    chmod -R g+rw /.cache

RUN apk add --no-cache git && \
    pip install ruamel.yaml==0.16.12 semgrep==$SCANNER_VERSION



COPY --from=tracking /analyzer-tracking /analyzer-tracking
COPY --from=scripts /start.sh /analyzer

ENTRYPOINT []
CMD ["/analyzer", "run"]
