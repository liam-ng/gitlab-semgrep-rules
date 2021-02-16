ARG SCANNER_VERSION=0.39.1

FROM golang:1.15-alpine AS build

ENV CGO_ENABLED=0 GOOS=linux

WORKDIR /go/src/buildapp
COPY . .

# variable to the most recent version from the CHANGELOG.md file
RUN CHANGELOG_VERSION=$(grep -m 1 '^## v.*$' "CHANGELOG.md" | sed 's/## v//') && \
        PATH_TO_MODULE=`go list -m` && \
        go build -ldflags="-X '$PATH_TO_MODULE/metadata.AnalyzerVersion=$CHANGELOG_VERSION'" -o /analyzer

# Allow the semgrep user to add custom ca certificates to the system.
RUN addgroup -g 1000 semgrep && \
    adduser -u 1000 -D -h /home/semgrep -G semgrep semgrep && \
    touch /ca-cert-additional-gitlab-bundle.pem && \
    chown root:semgrep /ca-cert-additional-gitlab-bundle.pem && \
    chmod g+w /ca-cert-additional-gitlab-bundle.pem

FROM returntocorp/semgrep:$SCANNER_VERSION

ARG SCANNER_VERSION
ENV SCANNER_VERSION ${SCANNER_VERSION}

COPY --from=build /analyzer /analyzer
COPY --from=build /ca-cert-additional-gitlab-bundle.pem /etc/ssl/certs/ca-cert-additional-gitlab-bundle.pem
COPY rules /rules

ENTRYPOINT []
CMD ["/analyzer", "run"]