# When updating version make sure to check on semgrepignore file as well
ARG SCANNER_VERSION=1.17.1
ARG POST_ANALYZER_SCRIPTS_VERSION=0.2.0
ARG TRACKING_CALCULATOR_VERSION=2.2.8
ARG VET_VERSION=0.17.5
ARG STENCILS_VERSION=0.2.0

FROM registry.gitlab.com/security-products/post-analyzers/scripts:${POST_ANALYZER_SCRIPTS_VERSION} AS scripts
FROM registry.gitlab.com/security-products/post-analyzers/tracking-calculator:${TRACKING_CALCULATOR_VERSION} AS tracking
FROM registry.gitlab.com/gitlab-org/security-products/vet/vet:${VET_VERSION} AS vet
FROM registry.gitlab.com/gitlab-org/security-products/vet/stencils:${STENCILS_VERSION} AS recipes

FROM golang:1.18-alpine AS build

ENV CGO_ENABLED=0 GOOS=linux

WORKDIR /go/src/buildapp
COPY . .

# variable to the most recent version from the CHANGELOG.md file
RUN CHANGELOG_VERSION=$(grep -m 1 '^## v.*$' "CHANGELOG.md" | sed 's/## v//') && \
        PATH_TO_MODULE=`go list -m` && \
        go build -ldflags="-X '$PATH_TO_MODULE/metadata.AnalyzerVersion=$CHANGELOG_VERSION'" -o /analyzer-semgrep

FROM python:3.9-alpine

ARG SCANNER_VERSION
ENV SCANNER_VERSION ${SCANNER_VERSION}
ENV SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE "/semgrepignore"
ENV PIP_NO_CACHE_DIR=off
ENV VET_CONFIGURATION_FILE="/verify/semgrep.toml"
ENV SAST_RULES_VERSION=1.3.12

# Run VET FP reduction only on Go files
ENV VET_LANG_EXT=".go"

RUN mkdir -p /etc/ssl/certs/ && \
    touch /etc/ssl/certs/ca-certificates.crt && \
    chmod g+w /etc/ssl/certs/ca-certificates.crt

COPY --from=build /analyzer-semgrep /analyzer-binary
COPY rules /rules
COPY semgrepignore /semgrepignore
RUN mkdir /.cache && \
    chmod -R g+rw /.cache && \
    \
    # Configure CA Certificates
    mkdir -p /etc/ssl/certs/ && \
    touch /etc/ssl/certs/ca-certificates.crt && \
    chmod g+w /etc/ssl/certs/ca-certificates.crt && \
    \
    # Install semgrep and additional tools
    apk add --no-cache git && \
    apk add --no-cache --virtual=.build-only-deps gcc musl-dev && \
    pip install semgrep==$SCANNER_VERSION && \
    apk del .build-only-deps

RUN git clone \
    --depth 1 \
    --branch "v${SAST_RULES_VERSION}" \
    --no-checkout \
    https://gitlab.com/gitlab-org/security-products/sast-rules.git \
    /sast-rules

RUN cd sast-rules && \
    # pull only `dist` folder when checking out
    git sparse-checkout set dist && \
    git checkout "v${SAST_RULES_VERSION}" && \
    cp dist/eslint.yml /rules && \
    cp dist/find_sec_bugs_scala.yml /rules && \
    cp dist/flawfinder.yml /rules

ADD https://gitlab.com/gitlab-org/security-products/sast-rules/-/raw/drop-detect-object-injection-rule/dist/eslint.yml /rules/eslint.yml

COPY --from=tracking /analyzer-tracking /analyzer-tracking
COPY --from=scripts /start.sh /analyzer
COPY --from=vet /usr/bin/analyzer /vet
COPY --from=recipes /config/verify /verify

ENTRYPOINT []
CMD ["/analyzer", "run"]
