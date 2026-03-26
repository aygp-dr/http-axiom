.DEFAULT_GOAL := help

.PHONY: help dev test clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

dev: ## Run the app (Jetty on port 8080)
	clj -M:dev -m todo.main

test: ## Run tests (placeholder)
	@echo "No tests yet (epoch 0)"

clean: ## Remove database file
	rm -f todos.db
