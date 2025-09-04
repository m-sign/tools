
# tools section
.PHONY=tools tools.goimports tools.staticcheck tools.msign

tools: tools.goimports tools.staticcheck tools.msign ## install all required tools

tools.goimports:
	@command -v $(GOIMPORTS) >/dev/null ; if [ $$? -ne 0 ]; then \
		echo "[ installing goimports ]"; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	fi

tools.staticcheck:
	@command -v $(GOSTATICCHECK) >/dev/null ; if [ $$? -ne 0 ]; then \
		echo "[ installing staticcheck ]"; \
		go install honnef.co/go/tools/cmd/staticcheck@latest; \
	fi

tools.msign:
ifeq ($(MSIGN_SIGNATURE),yes)
	@command -v $(MSIGN) >/dev/null ; if [ $$? -ne 0 ]; then \
		echo "[ installing msign ]"; \
		go install github.com/m-sign/tools/cmd/msign@latest; \
	fi
endif
