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

IMAGES  := router host switch svc
REGISTRY?= hyhe
TAG     ?= 0.1
# Must match .github/workflows/ci.yml, or local lint and CI can disagree.
GOLANGCI_VERSION ?= v2.5.0

.PHONY: all build test lint fmt vet images push clean install e2e ci naming

all: build

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet ./cmd/twinet
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinetd ./cmd/twinetd
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-rtr ./cmd/twinet-rtr

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
ci: naming lint test build
	./bin/twinet validate -m examples/demo
	./bin/twinet validate -m examples/cos461
	./bin/twinet grade validate examples/cos461/rubric/cos461.yaml
	@command -v shellcheck >/dev/null 2>&1 && shellcheck scripts/*.sh || \
		echo "shellcheck not installed; skipped"
	@echo "all CI gates passed"

# The service image ships the RTR validator, which is built from this module
# rather than downloaded, so the lab's trust anchor is the code in this
# repository and not a binary from somewhere else.
images: build
	@cp $(BIN)/twinet-rtr images/svc/twinet-rtr
	@for i in $(IMAGES); do \
		echo "building $(REGISTRY)/twinet-$$i:$(TAG)"; \
		docker build -q -t $(REGISTRY)/twinet-$$i:$(TAG) images/$$i || exit 1; \
	done

push: images
	@for i in $(IMAGES); do docker push $(REGISTRY)/twinet-$$i:$(TAG) || exit 1; done

install: build
	install -m 0755 $(BIN)/twinet /usr/local/bin/twinet
	install -m 0755 $(BIN)/twinetd /usr/local/bin/twinetd

e2e: build
	$(GO) test -count=1 -tags e2e ./test/e2e/...

clean:
	rm -rf $(BIN)
