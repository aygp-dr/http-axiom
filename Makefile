.PHONY: all build build-dev build-all install test test-race test-cover lint fmt clean help version-info quickstart doctor run fetch-owasp haxgoat juice-shop juice-shop-stop smoke diagram images images-all images-clean setup-ollama

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
# Images: setup
# --------------------------------------------------------------------------

setup-ollama: ## Install/upgrade ollama with MLX support for image gen
	brew unpin ollama 2>/dev/null || true
	brew install ollama || brew upgrade ollama
	brew services restart ollama
	@sleep 3
	@echo "ollama $$(ollama --version 2>&1 | tail -1)"
	@echo "pulling image models..."
	ollama pull x/flux2-klein:4b
	ollama pull x/z-image-turbo
	@echo "ready: make images"

# --------------------------------------------------------------------------
# Images (ollama local generation + imagemagick post-processing)
# --------------------------------------------------------------------------
#
# Models output square (1024x1024). Non-square derived via imagemagick.
# Idempotent: only regenerates when source/prompt changes.
#
# Workflow:
#   make images           — generate square sources via ollama
#   make images-all       — sources + all derived sizes
#   make images-clean     — remove all generated images

.PHONY: images images-all images-clean

OLLAMA_MODEL ?= x/flux2-klein:4b
OLLAMA_SEED  ?= 42
IMGOUT       := images/output
IMGPROMPTS   := images/prompts
OLLAMA_SLUG  := $(subst /,_,$(subst :,_,$(OLLAMA_MODEL)))

# Prompt basenames: 01-pipeline-hero 02-owasp-coverage ...
PROMPT_NAMES := $(basename $(notdir $(wildcard $(IMGPROMPTS)/*.txt)))

# Source images (square, from ollama)
SOURCE_IMGS  := $(foreach n,$(PROMPT_NAMES),$(IMGOUT)/$(n)_$(OLLAMA_SLUG)_s$(OLLAMA_SEED).png)

# Derived suffixes and their sizes
DERIVED_SUFFIXES := _banner _og _twitter _thumb _favicon
DERIVED_IMGS := $(foreach src,$(SOURCE_IMGS),$(foreach sfx,$(DERIVED_SUFFIXES),$(basename $(src))$(sfx).png))

# The README banner: tight center crop from pipeline hero (no text)
BANNER := $(IMGOUT)/01-pipeline-hero_banner.png
HERO   := $(IMGOUT)/01-pipeline-hero_$(OLLAMA_SLUG)_s$(OLLAMA_SEED).png

$(BANNER): $(HERO)
	magick $< -gravity center -crop 1024x250+0+0 +repage $@

# --- Derived size rules (pattern rules on existing source files) ---

$(IMGOUT)/%_banner.png: $(IMGOUT)/%.png
	convert $< -resize 1024x300^ -gravity center -extent 1024x300 $@

$(IMGOUT)/%_og.png: $(IMGOUT)/%.png
	convert $< -resize 1200x630^ -gravity center -extent 1200x630 $@

$(IMGOUT)/%_twitter.png: $(IMGOUT)/%.png
	convert $< -resize 800x418^ -gravity center -extent 800x418 $@

$(IMGOUT)/%_thumb.png: $(IMGOUT)/%.png
	convert $< -resize 256x256 $@

$(IMGOUT)/%_favicon.png: $(IMGOUT)/%.png
	convert $< -resize 64x64 $@

# --- Source generation (ollama) ---

images: ## Generate all source images via ollama (idempotent via generate.py)
	@mkdir -p $(IMGOUT)
	python3 images/generate.py --model $(OLLAMA_MODEL) --seed $(OLLAMA_SEED)

images-all: images ## Generate sources + all derived sizes
	@command -v convert >/dev/null || { echo "imagemagick required: brew install imagemagick"; exit 1; }
	@for src in $(IMGOUT)/*_s$(OLLAMA_SEED).png; do \
		[ -f "$$src" ] || continue; \
		base=$$(basename "$$src" .png); \
		for sfx in banner og twitter thumb favicon; do \
			tgt="$(IMGOUT)/$${base}_$${sfx}.png"; \
			[ -f "$$tgt" ] && [ "$$tgt" -nt "$$src" ] && continue; \
			$(MAKE) --no-print-directory "$$tgt"; \
		done; \
	done

images-clean: ## Remove all generated images
	rm -rf $(IMGOUT)/*.png $(IMGOUT)/*.txt

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
