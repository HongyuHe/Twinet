# Twinet build and test targets.
GO      ?= go
BIN     ?= bin
KUBECTL ?= kubectl
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# The grader identity is content-addressed, not Git-addressed: it captures
# modified and untracked compiled source, works from a release tarball, and
# ignores non-build inputs such as documentation and reports. Commit and
# Version remain separate signed audit provenance.
SOURCE_DIGEST_REQUESTED := $(strip $(SOURCE_DIGEST))
SOURCE_DIGEST_COMPUTED := $(shell python3 "$(CURDIR)/scripts/source_digest.py" --root "$(CURDIR)" 2>/dev/null)
override SOURCE_DIGEST := $(SOURCE_DIGEST_COMPUTED)
# Build metadata must not depend on when the build ran. Stamping the wall clock
# meant two builds of one tree produced different bytes, so a release could
# only assert its provenance and never let anyone check it: the obvious test --
# rebuild and compare -- failed by construction. SOURCE_DATE_EPOCH is the
# cross-ecosystem convention for this; the commit's own timestamp is the next
# deterministic answer, and a tree with no Git metadata at all falls back to
# the epoch rather than to "now".
#
# The date is provenance, not identity. What a binary was built from is
# SourceDigest, which is content-addressed over the build inputs and remains
# exact for a dirty worktree and for a source tarball.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)
DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
	date -u -r "$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
LDFLAGS := -s -w \
	-X github.com/HongyuHe/twinet/internal/cli.Version=$(VERSION) \
	-X github.com/HongyuHe/twinet/internal/cli.Commit=$(COMMIT) \
	-X github.com/HongyuHe/twinet/internal/cli.SourceDigest=$(SOURCE_DIGEST) \
	-X github.com/HongyuHe/twinet/internal/grade.GraderSource=$(SOURCE_DIGEST) \
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
IMAGE_LOCK ?= images/lock.json
# The bundled manifests retain 0.1 development references. A release lock
# maps those authored references to the remotely verified release digest; set
# these when producing a lock for a differently authored manifest.
IMAGE_LOCK_SOURCE_REGISTRY ?= hyhe
IMAGE_LOCK_SOURCE_TAG ?= 0.1
PODMAN_ROOT ?= sudo -n podman
# The image targets build and inspect with $(DOCKER), so the lock and its
# verification read the same engine. The bundled manifests declare containerd
# for the cluster; this states the engine for these Docker-side flows rather
# than depending on whatever a manifest happens to say.
LOCK_RUNTIME ?= docker
# Must match .github/workflows/ci.yml, or local lint and CI can disagree.
GOLANGCI_VERSION ?= v2.5.0
TWINET_NIKA_KUBERNETES_CONTEXT ?= $(shell $(KUBECTL) config current-context 2>/dev/null)
TWINET_NIKA_KUBERNETES_ENDPOINT ?= $(shell $(KUBECTL) --context "$(TWINET_NIKA_KUBERNETES_CONTEXT)" config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
TWINET_K8S_HELPER_IMAGE ?= docker.io/nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b
TWINET_K8S_WORKLOAD_IMAGE ?= docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
TWINET_NIKA_KUBERNETES_BRIDGE ?= python3 $(CURDIR)/contrib/nika/kubernetes_bridge.py --kubectl $(KUBECTL)$(if $(strip $(KUBECONFIG)), --kubeconfig $(abspath $(KUBECONFIG)),) --helper-image $(TWINET_K8S_HELPER_IMAGE) --workload-image $(TWINET_K8S_WORKLOAD_IMAGE)

.PHONY: all build release-build source-identity-stamp source-identity-check test-source-identity test lint fmt vet images push digests image-lock image-verify podman-images podman-integration containerd-integration clean install e2e ci ci-tools tidy-check naming fixture-sync \
	script-tests benchmark chaos soak-short soak-24h nos-images substrate-images substrate-integration \
	fault-integration k8s-fault-integration fault-stress fault-stress-release o12-integration

all: build

build: source-identity-stamp
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet ./cmd/twinet
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinetd ./cmd/twinetd
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '-s -w' -o $(BIN)/twinet-init ./cmd/twinet-init
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-rtr ./cmd/twinet-rtr
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-dhcpd ./cmd/twinet-dhcpd
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-mcast ./cmd/twinet-mcast
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-traffic ./cmd/twinet-traffic
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/twinet-openflow-controller ./cmd/twinet-openflow-controller

# Never let a caller stamp a Git SHA or arbitrary value in place of the
# canonical content digest. A matching explicit value is harmless and supports
# release tooling that records the computed digest before invoking make.
source-identity-stamp:
	@actual="$(SOURCE_DIGEST)"; requested="$(SOURCE_DIGEST_REQUESTED)"; \
	if ! printf '%s' "$$actual" | grep -Eq '^[0-9a-f]{64}$$'; then \
		echo "could not compute a valid SHA-256 source digest" >&2; \
		exit 2; \
	fi; \
	if [ -n "$$requested" ] && [ "$$requested" != "$$actual" ]; then \
		echo "SOURCE_DIGEST is computed from build inputs and cannot be overridden" >&2; \
		exit 2; \
	fi

# Kept as the release entry point: content identity is valid from a clean
# checkout, a dirty worktree, or a source release tarball.
source-identity-check: source-identity-stamp
	@printf 'source digest: %s\n' "$(SOURCE_DIGEST)"

release-build: source-identity-check build

# Proves source edits and untracked compiled files change identity while
# documentation-only changes do not, and that attestation verification binds
# the exact resulting digest.
test-source-identity:
	bash scripts/test_source_digest.sh
	$(GO) test ./internal/cli ./internal/harness \
		-run 'TestGraderSourceIdentityRequiresSHA256|TestAttestationUsesStableCompactContractAndExactBuild'

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

# The scale fixture is the production-size instance of the same COS461
# assignment. Letting its copied rubric drift creates a weaker large-class
# grading contract that ordinary per-file validation cannot detect.
fixture-sync:
	@cmp -s examples/scale/rubric/cos461.yaml examples/cos461/rubric/cos461.yaml || { \
		diff -u examples/scale/rubric/cos461.yaml examples/cos461/rubric/cos461.yaml; \
		echo "scale COS461 rubric differs from the canonical course rubric" >&2; \
		exit 1; \
	}

# Everything CI checks, runnable before pushing.
# `make ci` is the release gate, so it must fail when it cannot check something
# rather than report success for the subset of gates that happened to be
# installed. A tool that is missing is an unrun gate, and an unrun gate that
# prints "passed" is worse than no gate at all: it is a gate that lies.
ci: ci-tools naming fixture-sync lint test build tidy-check
	# Every lab and every rubric that ships, found rather than listed.
	#
	# The list was written out, so three labs and two rubrics were added and the
	# gate went on checking the original two -- a release gate that does not
	# cover what is being released.
	@for m in examples/*/; do \
		./bin/twinet validate -m "$$m" || exit 1; \
	done
	# One runtime contract for the whole bundle. Six of seven labs once defaulted
	# to Docker while the documented cluster ran containerd, so following the
	# guide produced a cluster that could deploy one of its own examples. Each
	# lab must declare the cluster runtime, and must still validate when an
	# operator overrides it for a Docker or Podman machine.
	@for m in examples/*/; do \
		grep -Eq '^[[:space:]]*runtime:[[:space:]]*containerd[[:space:]]*$$' $${m}twinet.yaml || { \
			echo "$${m}twinet.yaml does not declare placement.runtime: containerd" >&2; exit 1; }; \
		./bin/twinet --runtime docker validate -m "$$m" >/dev/null || exit 1; \
		./bin/twinet --runtime podman validate -m "$$m" >/dev/null || exit 1; \
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
	@rm -f images/svc/twinet-rtr images/router/twinet-dhcpd images/host/twinet-mcast \
		images/router/twinet-mcast images/svc/twinet-traffic images/controller/twinet-openflow-controller
	@cp $(BIN)/twinet-rtr images/svc/twinet-rtr
	@cp $(BIN)/twinet-dhcpd images/router/twinet-dhcpd
	@cp $(BIN)/twinet-mcast images/host/twinet-mcast
	@cp $(BIN)/twinet-mcast images/router/twinet-mcast
	@cp $(BIN)/twinet-traffic images/svc/twinet-traffic
	@cp $(BIN)/twinet-openflow-controller images/controller/twinet-openflow-controller
	@for i in $(IMAGES); do \
		echo "building $(REGISTRY)/twinet-$$i:$(TAG) and :$(BUILD_TAG)"; \
		$(DOCKER) build -q -t $(REGISTRY)/twinet-$$i:$(TAG) images/$$i || exit 1; \
		$(DOCKER) tag $(REGISTRY)/twinet-$$i:$(TAG) $(REGISTRY)/twinet-$$i:$(BUILD_TAG) || exit 1; \
	done

push:
	@missing=""; \
	for i in $(IMAGES); do \
		$(DOCKER) image inspect "$(REGISTRY)/twinet-$$i:$(BUILD_TAG)" >/dev/null 2>&1 || missing="$$missing $$i"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "building missing immutable image tag(s):$$missing"; \
		$(MAKE) --no-print-directory REGISTRY="$(REGISTRY)" TAG="$(TAG)" DOCKER="$(DOCKER)" images; \
	fi
	bash scripts/push_images.sh "$(REGISTRY)" "$(TAG)" "$(BUILD_TAG)" $(IMAGES) -- $(DOCKER)
	@$(MAKE) --no-print-directory image-lock

# image-lock records only registry-inspected immutable manifests. A local
# image config ID is deliberately rejected by `twinet images lock`: it cannot
# prove the bytes were pushed and another node can pull them.
image-lock: build
	@args=""; \
	for i in $(IMAGES); do \
		authored="$(IMAGE_LOCK_SOURCE_REGISTRY)/twinet-$$i:$(IMAGE_LOCK_SOURCE_TAG)"; \
		channel="$(REGISTRY)/twinet-$$i:$(TAG)"; \
		immutable="$(REGISTRY)/twinet-$$i:$(BUILD_TAG)"; \
		d=$$(bash scripts/remote_image_digest.sh "$$immutable" $(DOCKER)) || exit 1; \
		channel_d=$$(bash scripts/remote_image_digest.sh "$$channel" $(DOCKER)) || exit 1; \
		test "$$channel_d" = "$$d" || { echo "$$channel does not match immutable $$immutable" >&2; exit 1; }; \
		args="$$args --pin $$authored=$$authored@$$d"; \
	done; \
	./$(BIN)/twinet --runtime $(LOCK_RUNTIME) --manifest examples/mixed-substrate images lock --output "$(CURDIR)/$(IMAGE_LOCK)" $$args

image-verify: build
	@test -f "$(IMAGE_LOCK)" || { echo "missing $(IMAGE_LOCK); run make push or make image-lock"; exit 2; }
	sudo -n env PATH="$$PATH" ./$(BIN)/twinet --runtime $(LOCK_RUNTIME) --manifest examples/mixed-substrate images verify --lock "$(CURDIR)/$(IMAGE_LOCK)"

# Compatibility alias retained for release scripts that used the old target.
digests: image-lock

# Build the exact same source images with Podman so the real-Podman lifecycle
# gate cannot claim success from Docker-built artifacts. PODMAN_ROOT defaults
# to a non-interactive rootful service because host netlink wiring needs that
# substrate; set it explicitly for another supported rootful installation.
podman-images: build
	@rm -f images/svc/twinet-rtr images/router/twinet-dhcpd images/host/twinet-mcast \
		images/router/twinet-mcast images/svc/twinet-traffic images/controller/twinet-openflow-controller
	@cp $(BIN)/twinet-rtr images/svc/twinet-rtr
	@cp $(BIN)/twinet-dhcpd images/router/twinet-dhcpd
	@cp $(BIN)/twinet-mcast images/host/twinet-mcast
	@cp $(BIN)/twinet-mcast images/router/twinet-mcast
	@cp $(BIN)/twinet-traffic images/svc/twinet-traffic
	@cp $(BIN)/twinet-openflow-controller images/controller/twinet-openflow-controller
	@for i in $(IMAGES); do \
		echo "building $(REGISTRY)/twinet-$$i:$(TAG) with Podman"; \
		$(PODMAN_ROOT) build -q -t $(REGISTRY)/twinet-$$i:$(TAG) images/$$i || exit 1; \
	done

# This is intentionally an explicit, non-vacuous rootful Podman gate. The
# test deploys, wires, configures, executes, saves, consumes agent events, and
# destroys a source-built routed lab; it fails rather than skips if prerequisites
# or the acknowledgement are absent.
podman-integration:
	@test "$${TWINET_PODMAN_INTEGRATION_ALLOW_DESTRUCTIVE:-}" = "1" || \
		{ echo "make podman-integration requires TWINET_PODMAN_INTEGRATION_ALLOW_DESTRUCTIVE=1"; exit 2; }
	@$(PODMAN_ROOT) info >/dev/null 2>&1 || \
		{ echo "make podman-integration requires a reachable rootful Podman service"; exit 2; }
	@$(MAKE) --no-print-directory PODMAN_ROOT="$(PODMAN_ROOT)" podman-images
	sudo -n env PATH="$$PATH" \
	TWINET_BIN="$(CURDIR)/bin/twinet" \
	TWINET_PODMAN_INTEGRATION=1 \
	TWINET_PODMAN_HOST="$${TWINET_PODMAN_HOST:-unix:///run/podman/podman.sock}" \
	REGISTRY="$(REGISTRY)" TAG="$(TAG)" \
	$(GO) test -count=1 -tags=podman_integration -timeout 15m ./test/integration/ -run '^TestPodmanRoutedLabLifecycle$$'

containerd-integration: build
	sudo -n env PATH="$$PATH" \
	TWINET_CONTAINERD_INTEGRATION=1 \
	TWINET_CONTAINERD_HOST="$${TWINET_CONTAINERD_HOST:-unix:///run/containerd/containerd.sock}" \
	TWINET_INIT_BINARY="$(CURDIR)/bin/twinet-init" \
	$(GO) test -count=1 -tags=containerd_integration -timeout 10m ./test/integration/ -run '^TestContainerdRuntimeLifecycle$$'

install: build
	install -m 0755 $(BIN)/twinet /usr/local/bin/twinet
	install -m 0755 $(BIN)/twinetd /usr/local/bin/twinetd
	install -m 0755 $(BIN)/twinet-init /usr/local/bin/twinet-init

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
	bash scripts/test_remote_image_digest.sh
	bash scripts/test_push_images.sh
	bash scripts/test_deploy_agents_source.sh
	bash scripts/test_source_digest.sh
	bash scripts/test_reproducible_build.sh
	python3 contrib/nika/test_kubernetes_bridge.py

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
		$(GO) test -count=1 -tags o12integration ./test/integration/... -run '^TestO12'

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

# Kubernetes is delegated through the bundled strict kubectl bridge. The bridge
# accepts only a transiently marked disposable cluster, installs owner-tagged
# node filters through capability-scoped helper pods, and restores the fixture
# objects and worker dataplanes exactly. Never point this target at production.
k8s-fault-integration:
	@test "$${TWINET_K8S_FAULT_INTEGRATION_ALLOW_DESTRUCTIVE:-}" = "1" || \
		{ echo "make k8s-fault-integration requires TWINET_K8S_FAULT_INTEGRATION_ALLOW_DESTRUCTIVE=1"; exit 2; }
	@test "$${TWINET_K8S_DISPOSABLE_CLUSTER:-}" = "1" || \
		{ echo "make k8s-fault-integration requires TWINET_K8S_DISPOSABLE_CLUSTER=1 and must never target production"; exit 2; }
	@command -v $(KUBECTL) >/dev/null 2>&1 || \
		{ echo "make k8s-fault-integration requires $(KUBECTL)"; exit 2; }
	@command -v python3 >/dev/null 2>&1 || \
		{ echo "make k8s-fault-integration requires python3"; exit 2; }
	@printf '%s\n' "$(TWINET_K8S_HELPER_IMAGE)" | grep -Eq '@sha256:[0-9a-f]{64}$$' || \
		{ echo "TWINET_K8S_HELPER_IMAGE must be an immutable @sha256 reference"; exit 2; }
	@printf '%s\n' "$(TWINET_K8S_WORKLOAD_IMAGE)" | grep -Eq '@sha256:[0-9a-f]{64}$$' || \
		{ echo "TWINET_K8S_WORKLOAD_IMAGE must be an immutable @sha256 reference"; exit 2; }
	@test -n "$(TWINET_NIKA_KUBERNETES_ENDPOINT)" && \
		test -n "$(TWINET_NIKA_KUBERNETES_CONTEXT)" && \
		test -n "$(TWINET_NIKA_KUBERNETES_BRIDGE)" || \
		{ echo "make k8s-fault-integration could not discover a Kubernetes endpoint/context/bridge"; exit 2; }
	TWINET_NIKA_KUBERNETES_ENDPOINT="$(TWINET_NIKA_KUBERNETES_ENDPOINT)" \
		TWINET_NIKA_KUBERNETES_CONTEXT="$(TWINET_NIKA_KUBERNETES_CONTEXT)" \
		TWINET_NIKA_KUBERNETES_BRIDGE="$(TWINET_NIKA_KUBERNETES_BRIDGE)" \
		TWINET_K8S_KUBECTL="$(KUBECTL)" \
		TWINET_K8S_KUBECONFIG="$(KUBECONFIG)" \
		TWINET_K8S_HELPER_IMAGE="$(TWINET_K8S_HELPER_IMAGE)" \
		TWINET_K8S_WORKLOAD_IMAGE="$(TWINET_K8S_WORKLOAD_IMAGE)" \
		TWINET_K8S_FAULT_INTEGRATION_ALLOW_DESTRUCTIVE=1 \
		TWINET_K8S_DISPOSABLE_CLUSTER=1 \
		$(GO) test -count=1 -tags k8sbackend -timeout 40m ./internal/cli/... \
		-run '^TestRealNIKAKubernetesBackendLifecycle$$'

substrate-integration: substrate-images fault-integration

clean:
	rm -rf $(BIN)
