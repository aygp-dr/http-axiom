.PHONY: all build build-dev build-all install test test-race test-cover lint fmt clean help version-info quickstart doctor run fetch-owasp haxgoat juice-shop juice-shop-stop smoke diagram

BINARY  := hax
MODULE  := github.com/aygp-dr/http-axiom
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

GO      ?= go
LDFLAGS := -ldflags "-s -w \
	-X main.Version=$(VERSION) \
	-X main.GitCommit=$(COMMIT) \
	-X main.BuildDate=$(BUILD_DATE)"

PLATFORMS := linux-amd64 linux-arm64 darwin-amd64 darwin-arm64

# Default
all: build

# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

build: ## Build with version info
	$(GO) build $(LDFLAGS) -trimpath -o $(BINARY) .

build-dev: ## Fast build without version info
	$(GO) build -o $(BINARY) .

build-all: $(PLATFORMS) ## Cross-compile for all platforms

linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -trimpath -o dist/$(BINARY)-linux-amd64 .

linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -trimpath -o dist/$(BINARY)-linux-arm64 .

darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -trimpath -o dist/$(BINARY)-darwin-amd64 .

darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -trimpath -o dist/$(BINARY)-darwin-arm64 .

# --------------------------------------------------------------------------
# Install
# --------------------------------------------------------------------------

install: build ## Install to ~/.local/bin
	@mkdir -p $(HOME)/.local/bin
	cp $(BINARY) $(HOME)/.local/bin/$(BINARY)
	@echo "installed $(BINARY) to $(HOME)/.local/bin/$(BINARY)"

# --------------------------------------------------------------------------
# Test
# --------------------------------------------------------------------------

test: ## Run tests
	$(GO) test ./...

test-race: ## Run tests with race detector
	$(GO) test -race ./...

test-cover: ## Run tests with coverage
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

# --------------------------------------------------------------------------
# Lint & Format
# --------------------------------------------------------------------------

lint: ## Run linters
	$(GO) vet ./...
	@if command -v gofmt >/dev/null 2>&1; then \
		test -z "$$(gofmt -l .)" || { echo "gofmt needed on:"; gofmt -l .; exit 1; }; \
	fi
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	fi

fmt: ## Auto-format Go files
	gofmt -w .

# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------

run: build-dev ## Build and run
	./$(BINARY) $(ARGS)

quickstart: build-dev ## Run quickstart
	./$(BINARY) quickstart

doctor: build-dev ## Run doctor
	./$(BINARY) doctor

# --------------------------------------------------------------------------
# Test Targets
# --------------------------------------------------------------------------

JUICE_SHOP_PORT ?= 3000
JUICE_SHOP_URL  := http://localhost:$(JUICE_SHOP_PORT)
HAXGOAT_PORT    ?= 9999
HAXGOAT_URL     := http://localhost:$(HAXGOAT_PORT)

haxgoat: ## Run haxgoat (built-in vulnerable server)
	$(GO) run ./cmd/haxgoat

juice-shop: ## Start OWASP Juice Shop in Docker (port 3000)
	@docker run --rm -d --name juice-shop -p $(JUICE_SHOP_PORT):3000 bkimminich/juice-shop
	@echo "Juice Shop running at $(JUICE_SHOP_URL)"
	@echo "  API docs: $(JUICE_SHOP_URL)/api-docs"
	@echo "  Scoreboard: $(JUICE_SHOP_URL)/#/score-board"
	@echo "Stop with: make juice-shop-stop"

juice-shop-stop: ## Stop Juice Shop container
	@docker stop juice-shop 2>/dev/null || true

smoke: build ## Smoke test against haxgoat or Juice Shop
	@echo "=== hax smoke test ==="
	@if curl -sf $(HAXGOAT_URL)/health >/dev/null 2>&1; then \
		echo "Target: haxgoat ($(HAXGOAT_URL))"; \
		./$(BINARY) audit $(HAXGOAT_URL) || true; \
		echo; \
		./$(BINARY) audit $(HAXGOAT_URL)/secure || true; \
		echo; \
		./$(BINARY) audit $(HAXGOAT_URL)/api/user || true; \
		echo; \
		./$(BINARY) audit $(HAXGOAT_URL)/api/transfer || true; \
		echo; \
		./$(BINARY) audit $(HAXGOAT_URL)/cached || true; \
		echo; \
		./$(BINARY) audit $(HAXGOAT_URL)/cached-ok || true; \
	elif curl -sf $(JUICE_SHOP_URL) >/dev/null 2>&1; then \
		echo "Target: Juice Shop ($(JUICE_SHOP_URL))"; \
		./$(BINARY) audit $(JUICE_SHOP_URL) || true; \
		echo; \
		./$(BINARY) audit $(JUICE_SHOP_URL)/api/Products/1 || true; \
		echo; \
		./$(BINARY) audit $(JUICE_SHOP_URL)/rest/products/search?q=apple || true; \
	else \
		echo "No target running. Start one with:"; \
		echo "  make haxgoat    # lightweight Go server (port 9999)"; \
		echo "  make juice-shop # OWASP Juice Shop Docker (port 3000)"; \
		exit 1; \
	fi

# --------------------------------------------------------------------------
# Research
# --------------------------------------------------------------------------

OWASP_PDF := docs/owasp-top10-agentic-2026.pdf
OWASP_URL := https://genai.owasp.org/download/52117/?tmstv=1765059207

fetch-owasp: $(OWASP_PDF) ## Download OWASP Top 10 for Agentic Applications (gitignored)

$(OWASP_PDF):
	@mkdir -p docs
	curl -sL -o $@ "$(OWASP_URL)"
	@echo "downloaded $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# --------------------------------------------------------------------------
# Diagrams
# --------------------------------------------------------------------------

diagram: model-architecture.svg ## Regenerate architecture diagram from mermaid source

model-architecture.svg: model-architecture.mmd
	mmdc -i $< -o $@ -b transparent
	@echo "regenerated $@ from $<"

# --------------------------------------------------------------------------
# Utility
# --------------------------------------------------------------------------

version-info: ## Show build variables
	@echo "VERSION:    $(VERSION)"
	@echo "COMMIT:     $(COMMIT)"
	@echo "BUILD_DATE: $(BUILD_DATE)"

clean: ## Remove build artifacts
	rm -f $(BINARY)
	rm -rf dist/
	rm -f coverage.out

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
