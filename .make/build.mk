.PHONY: all build test test-race check check.fmt check.vet lint vuln format clean

all: check test build ## do check - test - build for the project

build: ## build msign for this platform into bin/ (unsigned)
	@mkdir -p $(GOOUTDIR)
	$(GOBUILD) -o $(GOOUTDIR)/ $(BINARIES)

test: ## run unit tests with code coverage info
	@mkdir -p $(GOOUTDIR)
	$(GOCMD) test -count=1 -coverprofile=$(GOOUTDIR)/cover.out ./...
	$(GOCMD) tool cover -html=$(GOOUTDIR)/cover.out -o $(GOOUTDIR)/cover.html

test-race: ## run unit tests with the race detector
	CGO_ENABLED=1 $(GOCMD) test -race -count=1 ./...

check: check.fmt check.vet lint ## do static code checks

check.fmt: ## check formatting
	@test -z "$$(gofmt -s -l .)" || { gofmt -s -l .; echo "Formatting is needed (please do 'make format')"; exit 1; }

check.vet: ## do go vet checks
	$(GOCMD) vet ./...

lint: ## run golangci-lint (v2.14 or later)
	$(GOLANGCI_LINT) run ./...

vuln: ## check for known vulnerabilities
	$(GOVULNCHECK) ./...

format: ## format go code
	gofmt -s -w .

clean: ## clean up files
	rm -rf $(GOOUTDIR) build
