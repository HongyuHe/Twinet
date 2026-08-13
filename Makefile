# Twinet build and test targets.
GO      ?= go
BIN     ?= bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/HongyuHe/twinet/internal/cli.Version=$(VERSION) \
	-X github.com/HongyuHe/twinet/internal/cli.Commit=$(COMMIT) \
	-X github.com/HongyuHe/twinet/internal/cli.Date=$(DATE) \
	-X github.com/HongyuHe/twinet/internal/agent.Version=$(VERSION)

# Docker may need privilege depending on how the host is set up; overriding one
# variable is better than every recipe guessing.
DOCKER  ?= docker
IMAGES  := router host switch svc
REGISTRY?= hyhe
TAG     ?= 0.1
# Every image is also published under the commit it was built from. The moving
# tag is what a manifest refers to day to day; the immutable one is what makes a
# grade reproducible, because "0.1" rebuilt in three months is different
# software under an unchanged name and a regrade against it is not comparable
# with the first.
BUILD_TAG ?= $(TAG)-$(COMMIT)
# Must match .github/workflows/ci.yml, or local lint and CI can disagree.
GOLANGCI_VERSION ?= v2.5.0

.PHONY: all build test lint fmt vet images push digests clean install e2e ci ci-tools tidy-check naming

all: build

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet ./cmd/twinet
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinetd ./cmd/twinetd
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-rtr ./cmd/twinet-rtr
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-dhcpd ./cmd/twinet-dhcpd
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-mcast ./cmd/twinet-mcast

test:
	$(GO) test -race -count=1 ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

# Mirrors the CI lint job exactly, including the config schema check that the
# GitHub action performs but `golangci-lint run` does not. Skipping it once cost
# a red build for a config that ran perfectly well locally.
lint: fmt vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint config verify && golangci-lint run --timeout=5m; \
	else \
		echo "golangci-lint not installed; ran go vet only. Install $(GOLANGCI_VERSION) to match CI."; \
	fi

# Files are snake_case and folders are this-kind-of-format.
naming:
	./scripts/check_naming.sh

# Everything CI checks, runnable before pushing.
# `make ci` is the release gate, so it must fail when it cannot check something
# rather than report success for the subset of gates that happened to be
# installed. A tool that is missing is an unrun gate, and an unrun gate that
# prints "passed" is worse than no gate at all: it is a gate that lies.
ci: ci-tools naming lint test build tidy-check
	./bin/twinet validate -m examples/demo
	./bin/twinet validate -m examples/cos461
	./bin/twinet validate -m examples/advnet
	./bin/twinet grade validate examples/cos461/rubric/cos461.yaml
	# The schema is generated, so it can only be trusted if something checks it
	# still describes the manifests that exist -- the root labs and every AS
	# template, since a template ships unvalidated otherwise.
	./bin/twinet schema > /tmp/twinet-lab.schema.json
	@for m in examples/demo examples/cos461 examples/advnet examples/scale; do \
		python3 scripts/check_schema.py /tmp/twinet-lab.schema.json $$m/twinet.yaml || exit 1; \
		for t in $$m/templates/*.yaml; do \
			[ -e "$$t" ] || continue; \
			python3 scripts/check_schema.py --def ASTemplate /tmp/twinet-lab.schema.json $$t || exit 1; \
		done; \
	done
	shellcheck scripts/*.sh
	@echo "all CI gates passed"

# ci-tools refuses to start a release check that cannot be completed.
ci-tools:
	@missing=""; \
	for t in golangci-lint shellcheck; do \
		command -v $$t >/dev/null 2>&1 || missing="$$missing $$t"; \
	done; \
	python3 -c "import jsonschema" >/dev/null 2>&1 || missing="$$missing python3-jsonschema"; \
	if [ -n "$$missing" ]; then \
		echo "make ci cannot run: missing$$missing"; \
		echo "these gates run in CI, so skipping them here would report a pass"; \
		echo "that CI will not agree with. Install golangci-lint $(GOLANGCI_VERSION)"; \
		echo "and shellcheck, pip install jsonschema, or run the individual"; \
		echo "targets you want."; \
		exit 1; \
	fi

# tidy-check fails when go.mod or go.sum do not match the imports in the tree.
# A missing sum breaks any build that starts from a clean module cache, which is
# every CI build and every new contributor's first one.
tidy-check:
	$(GO) mod tidy -diff

# The service image ships the RTR validator, which is built from this module
# rather than downloaded, so the lab's trust anchor is the code in this
# repository and not a binary from somewhere else.
images: build
	@cp $(BIN)/twinet-rtr images/svc/twinet-rtr
	@cp $(BIN)/twinet-dhcpd images/router/twinet-dhcpd
	@cp $(BIN)/twinet-mcast images/host/twinet-mcast
	@cp $(BIN)/twinet-mcast images/router/twinet-mcast
	@for i in $(IMAGES); do \
		echo "building $(REGISTRY)/twinet-$$i:$(TAG)"; \
		$(DOCKER) build -q -t $(REGISTRY)/twinet-$$i:$(TAG) images/$$i || exit 1; \
	done

push: images
	@for i in $(IMAGES); do \
		$(DOCKER) tag $(REGISTRY)/twinet-$$i:$(TAG) $(REGISTRY)/twinet-$$i:$(BUILD_TAG); \
		echo "pushing $(REGISTRY)/twinet-$$i:$(TAG) and :$(BUILD_TAG)"; \
		$(DOCKER) push -q $(REGISTRY)/twinet-$$i:$(TAG) >/dev/null || exit 1; \
		$(DOCKER) push -q $(REGISTRY)/twinet-$$i:$(BUILD_TAG) >/dev/null || exit 1; \
	done
	@$(MAKE) --no-print-directory digests

# digests records what was actually published, so a report naming an image can
# be traced to the exact bytes rather than to a tag that has since moved.
digests:
	@echo "# published $(shell date -u +%Y-%m-%dT%H:%M:%SZ) from $(COMMIT)" > images/published.txt
	@for i in $(IMAGES); do \
		d=$$($(DOCKER) image inspect $(REGISTRY)/twinet-$$i:$(TAG) --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}'); \
		echo "$(REGISTRY)/twinet-$$i:$(TAG) $$d" >> images/published.txt; \
	done
	@cat images/published.txt

install: build
	install -m 0755 $(BIN)/twinet /usr/local/bin/twinet
	install -m 0755 $(BIN)/twinetd /usr/local/bin/twinetd

# The test binary is version-stamped exactly like the real one. Without this it
# reports itself as "dev" and every test that talks to a cluster refuses on
# version skew -- against agents built from this very tree.
#
# The timeout is set explicitly because the suite deploys labs, injects
# forty-odd faults and grades a system against a live cluster; Go's ten-minute
# default kills it partway through, and a killed run leaves a grading hold
# behind that refuses the next thing anybody does to the lab.
e2e: build
	$(GO) test -count=1 -tags e2e -timeout 40m -ldflags '$(LDFLAGS)' ./test/e2e/...

clean:
	rm -rf $(BIN)
