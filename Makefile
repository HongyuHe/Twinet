# Twinet build and test targets.
GO      ?= go
BIN     ?= bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/HongyuHe/twinet/internal/cli.Version=$(VERSION) \
	-X github.com/HongyuHe/twinet/internal/cli.Commit=$(COMMIT) \
	-X github.com/HongyuHe/twinet/internal/cli.Date=$(DATE)

IMAGES  := router host switch svc
REGISTRY?= hyhe
TAG     ?= 0.1

.PHONY: all build test lint fmt vet images push clean install e2e

all: build

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet ./cmd/twinet
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinetd ./cmd/twinetd

test:
	$(GO) test -race -count=1 ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

lint: fmt vet
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || \
		echo "golangci-lint not installed; ran go vet only"

images:
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
