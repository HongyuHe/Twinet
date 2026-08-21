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
IMAGES  := router host switch svc bird p4 controller
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

.PHONY: all build test lint fmt vet images push digests clean install e2e ci ci-tools tidy-check naming \
	script-tests benchmark chaos soak-short soak-24h nos-images substrate-images substrate-integration \
	fault-integration k8s-fault-integration fault-stress fault-stress-release o12-integration

all: build

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet ./cmd/twinet
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinetd ./cmd/twinetd
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-rtr ./cmd/twinet-rtr
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-dhcpd ./cmd/twinet-dhcpd
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-mcast ./cmd/twinet-mcast
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-traffic ./cmd/twinet-traffic
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-openflow-controller ./cmd/twinet-openflow-controller

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
	# Every lab and every rubric that ships, found rather than listed.
	#
	# The list was written out, so three labs and two rubrics were added and the
	# gate went on checking the original two -- a release gate that does not
	# cover what is being released.
	@for m in examples/*/; do \
		./bin/twinet validate -m "$$m" || exit 1; \
	done
	@for r in examples/*/rubric/*.yaml; do \
		./bin/twinet grade validate "$$r" || exit 1; \
	done
	# The schema is generated, so it can only be trusted if something checks it
	# still describes the manifests that exist -- the root labs and every AS
	# template, since a template ships unvalidated otherwise.
	./bin/twinet schema > /tmp/twinet-lab.schema.json
	@for m in examples/*/; do \
		python3 scripts/check_schema.py /tmp/twinet-lab.schema.json $${m}twinet.yaml || exit 1; \
		for t in $${m}templates/*.yaml; do \
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
	@cp $(BIN)/twinet-traffic images/svc/twinet-traffic
	@cp $(BIN)/twinet-openflow-controller images/controller/twinet-openflow-controller
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

# These argument-level tests deliberately need no controller, token, Docker
# daemon, or cluster. They make a missing destructive acknowledgement a
# testable contract rather than a convention hidden in release instructions.
script-tests:
	shellcheck scripts/*.sh
	bash scripts/test_release_runners.sh

# Cluster evidence is never part of ordinary CI: it mutates a real cluster and
# must be run by an explicitly configured self-hosted runner. Every target
# requires an operator acknowledgement instead of quietly turning destructive
# coverage into a no-op.
benchmark:
	@test "$${TWINET_BENCHMARK_ALLOW_DESTRUCTIVE:-}" = "1" || \
		{ echo "make benchmark requires TWINET_BENCHMARK_ALLOW_DESTRUCTIVE=1"; exit 2; }
	@$(MAKE) --no-print-directory build
	@set --; \
	if [ -n "$${TWINET_BENCHMARK_SUBMISSIONS:-}" ]; then \
		set -- --submissions "$${TWINET_BENCHMARK_SUBMISSIONS}"; \
	fi; \
	./scripts/scale_benchmark.sh --allow-destructive --binary ./bin/twinet \
		--manifest "$${TWINET_SCALE_MANIFEST:-examples/scale}" "$$@"

chaos:
	@test "$${TWINET_CHAOS_ALLOW_DESTRUCTIVE:-}" = "1" || \
		{ echo "make chaos requires TWINET_CHAOS_ALLOW_DESTRUCTIVE=1"; exit 2; }
	@$(MAKE) --no-print-directory build
	@TWINET_CHAOS_ALLOW_DESTRUCTIVE=1 ./scripts/chaos_e2e.sh --allow-destructive \
		--binary ./bin/twinet --manifest "$${TWINET_SCALE_MANIFEST:-examples/scale}"

soak-short:
	@test "$${TWINET_SOAK_ALLOW_DESTRUCTIVE:-}" = "1" || \
		{ echo "make soak-short requires TWINET_SOAK_ALLOW_DESTRUCTIVE=1"; exit 2; }
	@$(MAKE) --no-print-directory build
	@TWINET_SOAK_ALLOW_DESTRUCTIVE=1 ./scripts/scale_soak.sh --allow-destructive --short \
		--binary ./bin/twinet --manifest "$${TWINET_SCALE_MANIFEST:-examples/scale}"

soak-24h:
	@test "$${TWINET_SOAK_ALLOW_DESTRUCTIVE:-}" = "1" || \
		{ echo "make soak-24h requires TWINET_SOAK_ALLOW_DESTRUCTIVE=1"; exit 2; }
	@$(MAKE) --no-print-directory build
	@TWINET_SOAK_ALLOW_DESTRUCTIVE=1 ./scripts/scale_soak.sh --allow-destructive \
		--binary ./bin/twinet --manifest "$${TWINET_SCALE_MANIFEST:-examples/scale}"

# This is deliberately not a skip-on-missing-Docker target. A dedicated image
# acceptance command that reports green without starting both NOSes proves
# nothing, so it fails clearly when its required engine is unavailable.
nos-images: images
	@command -v $(DOCKER) >/dev/null 2>&1 || \
		{ echo "make nos-images requires $(DOCKER)"; exit 2; }
	@$(DOCKER) info >/dev/null 2>&1 || \
		{ echo "make nos-images requires a reachable Docker daemon"; exit 2; }
	REGISTRY="$(REGISTRY)" TAG="$(TAG)" DOCKER="$(DOCKER)" \
		$(GO) test -count=1 -tags nosimages ./test/integration/...

# O12 is intentionally a dedicated non-vacuous Docker/root gate. The test
# fails rather than skips when its explicit acknowledgement or Docker daemon is
# absent, so a release cannot claim sidecar/PID/capability isolation from a
# unit-only run.
o12-integration:
	@test "$${TWINET_O12_INTEGRATION_ALLOW_DESTRUCTIVE:-}" = "1" || \
		{ echo "make o12-integration requires TWINET_O12_INTEGRATION_ALLOW_DESTRUCTIVE=1"; exit 2; }
	@$(DOCKER) info >/dev/null 2>&1 || \
		{ echo "make o12-integration requires a reachable Docker daemon"; exit 2; }
	@$(MAKE) --no-print-directory images
	REGISTRY="$(REGISTRY)" TAG="$(TAG)" TWINET_O12_INTEGRATION_ALLOW_DESTRUCTIVE=1 \
		$(GO) test -count=1 -tags o12integration ./test/integration/... -run '^TestO12Docker'

# O16 images are explicit because they pull a large pinned BMv2 base and may
# need a privileged Docker daemon. This target never reports a green result
# merely because the daemon is unavailable.
substrate-images: images
	@command -v $(DOCKER) >/dev/null 2>&1 || \
		{ echo "make substrate-images requires $(DOCKER)"; exit 2; }
	@$(DOCKER) info >/dev/null 2>&1 || \
		{ echo "make substrate-images requires a reachable Docker daemon"; exit 2; }
	@echo "P4/BMv2 and OpenFlow controller images built"

# Docker/root gated native round trips. The test itself refuses missing
# prerequisites rather than using t.Skip, so a release job cannot accidentally
# claim that all registered native faults ran.
fault-integration:
	@test "$${TWINET_FAULT_INTEGRATION_ALLOW_DESTRUCTIVE:-}" = "1" || \
		{ echo "make fault-integration requires TWINET_FAULT_INTEGRATION_ALLOW_DESTRUCTIVE=1"; exit 2; }
	@$(DOCKER) info >/dev/null 2>&1 || \
		{ echo "make fault-integration requires a reachable Docker daemon"; exit 2; }
	@$(MAKE) --no-print-directory images
	TWINET_BIN="$(CURDIR)/bin/twinet" \
		TWINET_FAULT_INTEGRATION_ALLOW_DESTRUCTIVE=1 \
		$(GO) test -count=1 -tags faultintegration -timeout 45m ./test/integration/...

# Short locally, release-sized when TWINET_FAULT_STRESS_EPISODES=100 is set.
fault-stress:
	$(GO) test -count=1 -run TestConcurrentEpisodeIsolation ./internal/fault/...

fault-stress-release:
	TWINET_FAULT_STRESS_EPISODES=100 $(GO) test -race -count=1 -run TestConcurrentEpisodeIsolation ./internal/fault/...

# Kubernetes is delegated to NIKA rather than emulated in Docker. This is an
# opt-in real-backend gate; its tag never turns an unconfigured cluster into a
# skip or a green result.
k8s-fault-integration:
	@test -n "$${TWINET_NIKA_KUBERNETES_ENDPOINT:-}" && \
		test -n "$${TWINET_NIKA_KUBERNETES_CONTEXT:-}" && \
		test -n "$${TWINET_NIKA_KUBERNETES_BRIDGE:-}" || \
		{ echo "make k8s-fault-integration requires NIKA endpoint, context, and bridge"; exit 2; }
	$(GO) test -count=1 -tags k8sbackend ./internal/cli/...

substrate-integration: substrate-images fault-integration

clean:
	rm -rf $(BIN)
