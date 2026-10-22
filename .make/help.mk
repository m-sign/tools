HELP_SEL= \033[36m
HELP_NORM= \033[0m

.PHONY: help list

help: ## this help
	@awk 'BEGIN {FS = ":.*?## "} /^[.a-zA-Z_-]+:.*?## / {printf "$(HELP_SEL)%-15s$(HELP_NORM)%s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort | cat

_empty:
list: ## show available targets
	@echo $(shell $(MAKE) -p _empty | grep "^[a-z]*:" | cut -d ":" -f1 | sort)
