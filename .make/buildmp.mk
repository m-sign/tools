TARGETS := $(foreach B,$(BINARIES:./cmd/%=%),$(addprefix $(B)-,$(BUILDS)))
ARTIFACTS := $(foreach T,$(TARGETS),$(GOOUTDIR)/$(T)$(call exe,$(T)))
HOST_MSIGN := $(HOSTDIR)/msign$(HOST_EXT)

.PHONY: buildmp host sign checksums release-check release _release_env

buildmp: $(TARGETS:%=build.go/%) ## cross-compile release binaries into bin/

build.go/%:
	@mkdir -p $(GOOUTDIR)
	GOOS=$(word 2,$(subst -, ,$*)) GOARCH=$(word 3,$(subst -, ,$*)) \
		$(GOBUILD) -o $(GOOUTDIR)/$*$(call exe,$*) ./cmd/$(word 1,$(subst -, ,$*))

host: ## build the msign used to sign releases, from this commit
	@mkdir -p $(HOSTDIR)
	$(GOBUILD) -o $(HOST_MSIGN) ./cmd/msign

_release_env:
	@test -n "$$MSIGN_PRIVATE" || { echo "MSIGN_PRIVATE is not set"; exit 1; }

sign: host _release_env ## sign release binaries (needs MSIGN_PRIVATE)
	@# Fails unless MSIGN_PRIVATE belongs to RELEASE_PUB.
	$(HOST_MSIGN) key id --public $(RELEASE_PUB)
	$(HOST_MSIGN) sign --force --to-file -q $(ARTIFACTS)

checksums: host _release_env ## write and sign bin/SHA256SUMS (needs MSIGN_PRIVATE)
	cd $(GOOUTDIR) && $(SHA256SUM) $(notdir $(ARTIFACTS)) > SHA256SUMS
	$(HOST_MSIGN) sign --force --to-file -q $(GOOUTDIR)/SHA256SUMS

release-check: host ## verify release assets against RELEASE_PUB
	$(HOST_MSIGN) verify -q --public $(RELEASE_PUB) $(ARTIFACTS) $(GOOUTDIR)/SHA256SUMS
	cd $(GOOUTDIR) && $(SHA256SUM) -c SHA256SUMS

release: _release_env ## build, sign and checksum all release assets (needs MSIGN_PRIVATE)
	$(MAKE) clean
	$(MAKE) buildmp
	$(MAKE) sign
	$(MAKE) checksums
	$(MAKE) release-check
