# ============================================================================
# ScopePilot Makefile
# ============================================================================
# Targets:
#   doctor   — Check toolchain availability (go, podman, podman compose)
#   build    — Build all containers and Go binaries
#   test     — Run all Go tests with race detection
#   test-unit— Run unit tests only
#   up       — Start all services with podman compose
#   down     — Stop all services
#   status   — Show container status
#   logs     — Tail container logs
#   clean    — Stop and remove containers and orphans
#   remove   — Clean AND remove volumes (requires confirmation)
#   shell    — Open a shell in the scopepilot container
#   rebuild  — Build images and recreate containers
# ============================================================================

SHELL := /bin/bash
.PHONY: doctor build test test-unit up down status logs clean remove shell rebuild

# --------------------------------------------------------------------------
# Tool detection
# --------------------------------------------------------------------------
GOCMD       := $(shell command -v go 2>/dev/null)
PODMAN      := $(shell command -v podman 2>/dev/null)

# podman compose subcommand (compose plugin or standalone podman-compose)
PODMAN_COMPOSE := $(shell podman compose version >/dev/null 2>&1 && echo "podman compose" || (command -v podman-compose 2>/dev/null && echo "podman-compose" || true))

.PHONY: _require_go _require_podman _require_compose

_require_go:
ifndef GOCMD
	$(error "go is not installed. Install Go from https://go.dev/dl/")
endif

_require_podman:
ifndef PODMAN
	$(error "podman is not installed. Install Podman from https://podman.io/")
endif

_require_compose:
	@$(MAKE) _require_podman
ifndef PODMAN_COMPOSE
	$(error "podman compose is not available. Install podman-compose or the podman-compose plugin.")
endif

# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

## doctor — Check that go, podman, and podman compose are available
doctor:
	@echo "=== ScopePilot Toolchain Check ==="
	@if [ -n "$(GOCMD)" ]; then \
		echo "[OK] go           : $(shell go version)"; \
	else \
		echo "[FAIL] go           : not found"; \
	fi
	@if [ -n "$(PODMAN)" ]; then \
		echo "[OK] podman       : $(shell podman version --format '{{.Client.Version}}')"; \
	else \
		echo "[FAIL] podman       : not found"; \
	fi
	@if [ -n "$(PODMAN_COMPOSE)" ]; then \
		echo "[OK] compose      : $(PODMAN_COMPOSE) available"; \
	else \
		echo "[WARN] compose      : not available (podman compose plugin or podman-compose)"; \
	fi
	@echo "================================="

## build — Build all container images and Go binaries
build: _require_podman _require_go
	@echo "=== Building Go binary ==="
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/pentest ./cmd/pentest/
	@echo "=== Building container images ==="
	podman build --platform=linux/arm64 -t scopepilot:latest -f containers/scopepilot/Containerfile .
	podman build --platform=linux/arm64 -t scopepilot-fixture:latest -f containers/fixture/Containerfile .
	@echo "[DONE] Build complete"

## test — Run all Go tests with race detection
test: _require_go
	CGO_ENABLED=1 go test -race -v ./...

## test-unit — Run unit tests only (no integration)
test-unit: _require_go
	go test -v -short ./internal/...

## up — Start all services (detached)
up: _require_compose
	$(PODMAN_COMPOSE) up -d

## down — Stop all services
down: _require_compose
	$(PODMAN_COMPOSE) down

## status — Show container status
status: _require_compose
	$(PODMAN_COMPOSE) ps

## logs — Tail container logs
logs: _require_compose
	$(PODMAN_COMPOSE) logs -f

## clean — Stop and remove containers, networks, and orphans
clean: _require_compose
	$(PODMAN_COMPOSE) down --remove-orphans

## remove — Clean + remove volumes (requires confirmation)
remove: _require_compose
	@echo "WARNING: This will remove all containers, networks, AND volumes!"
	@read -p "Are you sure? [y/N] " -r confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		$(PODMAN_COMPOSE) down --remove-orphans --volumes; \
		echo "Volumes removed."; \
	else \
		echo "Aborted."; \
	fi

## shell — Open a shell in the scopepilot container
shell: _require_compose
	$(PODMAN_COMPOSE) exec scopepilot sh

## rebuild — Build images and recreate containers (force)
rebuild: _require_compose
	$(PODMAN_COMPOSE) down --remove-orphans
	$(PODMAN_COMPOSE) build --no-cache
	$(PODMAN_COMPOSE) up -d --force-recreate
	@echo "[DONE] Services rebuilt and started"
