build.image:
	docker build -t semgrep .

build.image-fips:
	docker build -t semgrep-fips .

test.integration: build.image
	docker run -it --rm -v "${PWD}:${PWD}" -w "${PWD}" \
		-e TMP_IMAGE=semgrep \
		-v /var/run/docker.sock:/var/run/docker.sock \
		registry.gitlab.com/gitlab-org/security-products/analyzers/integration-test:stable rspec

test.integration-fips: build.image-fips
	docker run -it --rm -v "${PWD}:${PWD}" -w "${PWD}" \
		-e TMP_IMAGE=semgrep-fips \
		-v /var/run/docker.sock:/var/run/docker.sock \
		registry.gitlab.com/gitlab-org/security-products/analyzers/integration-test:stable rspec
