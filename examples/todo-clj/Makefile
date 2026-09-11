.DEFAULT_GOAL := help

.PHONY: help dev test lint fmt check clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

dev: ## Run the app (Jetty on port 8080)
	clj -M:run

test: ## Run tests
	bb test

lint: ## Lint with clj-kondo
	bb lint

fmt: ## Check formatting (bb fmt:fix to repair)
	bb fmt

check: ## lint + fmt + test (what CI runs)
	bb check

clean: ## Remove database file
	rm -f todos.db
