.PHONY: all build build-dev build-all install test test-race test-cover lint fmt clean help version-info quickstart doctor run fetch-owasp

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
