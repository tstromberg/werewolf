# werewolf: a Wolfi userland on an Alpine kernel, for virtual machines.
# make builds, tests and releases werewolf; howl builds and runs machines (cmd/howl/README.md).
#
#   make install-deps     install apko, Zig, QEMU and the rest, after asking
#   make howl             build build/host/howl; make install puts it on PATH
#   make test             run every unit test, in seconds
#   make lint             check Zig, YAML and docs; make fix repairs what it can
#   make install-precommit install the test, lint and local howl run hook
#   make precommit         run that hook now
#   make -j check         boot every form and a slot in parallel, and attack each
#   make check-FORM       check one form; check-shellfree-FORM checks it as shipped
#   make check-one        boot FORM REPEAT times, to chase a flake
#   make check-updater    run a whole update, over the network
#   make check-gcp        check prod-ssh on GCP; also check-aws and check-azure
#   make check-gcp-metadata check GCP people, key expiry, precedence and rotation
#   make example-FORM     run that form's local README fence; examples-gcp runs GCP
#   make ci               run CI's check job in an Ubuntu VM under Lima
#   make image|slot|disk  build FORM's initramfs, slot or UEFI disk
#   make list-forms       list the forms and the forms each includes
#   make relock           resolve FORM's packages again
#   make dist             build the released forms, unsigned (docs/releases.md)
#   make posture          build posture; on Linux, run it here as root
#   make clean            remove build/, except the package locks
#
# FORM picks the form (default sshd), ARCH the arch (default this machine's).

# := runs uname once; ARCH ?= $(shell ...) would run it at every use.
HOST_ARCH := $(shell uname -m | sed 's/arm64/aarch64/;s/amd64/x86_64/')
ARCH ?= $(HOST_ARCH)
HOST_OS := $(shell uname -s)

FORM ?= sshd
VARIANTS ?=
export VARIANTS
# Resolve the requested check's form before asking about its workload variants.
ifneq ($(strip $(VARIANTS)),)
ifeq ($(origin FORM),file)
VARIANT_CHECK_FORMS := $(sort $(foreach goal,$(MAKECMDGOALS),$(foreach name,$(patsubst check-native-tests-%,%,$(patsubst check-shellfree-%,%,$(patsubst check-%,%,$(goal)))),$(if $(wildcard forms/$(name)/form.yaml),$(name)))))
ifeq ($(words $(VARIANT_CHECK_FORMS)),1)
FORM := $(VARIANT_CHECK_FORMS)
endif
endif
endif
FORM_SELECTION = $(if $(VARIANTS),--variant $(VARIANTS))
FORM_TOOL = build/host/form
FORM_TOOL_SOURCES = lib/baselayout.zig tools/form.zig lib/form.zig lib/yaml.zig lib/lookup.zig lib/compose.zig lib/package.zig lib/allow.zig lib/sshd.zig lib/service.zig lib/seal.zig lib/settings.zig lib/people.zig
# compose_modules NAME is lib/compose.zig as module NAME, with its imports.
compose_modules = --dep allow --dep form --dep seal --dep service --dep package --dep people -M$(1)=lib/compose.zig -Mpackage=lib/package.zig \
	--dep allow --dep sshd -Mform=lib/form.zig -Mallow=lib/allow.zig --dep settings -Msshd=lib/sshd.zig \
	--dep seal --dep settings -Mservice=lib/service.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig -Mpeople=lib/people.zig
FORM_TOOL_MODULES = --dep form --dep compose -Mroot=tools/form.zig $(call compose_modules,compose)
COMPOSE_MODULES = $(call compose_modules,root)
HOWL = build/host/howl
FORM_REF := $(FORM)
override FORM := $(notdir $(patsubst %/,%,$(FORM)))
# These goals need no form tool, and install-deps runs before there is a Zig.
FORMLESS = install-deps install uninstall howl $(HOWL) build/host/mdoc clean help \
	lint _lint fix yamllint-lint zig-lint zig-fix doc-lint doc-fix man-lint code-lint
ifeq ($(filter-out $(FORMLESS),$(or $(MAKECMDGOALS),all)),)
FORM_ASK = :
else
FORM_ASK = $(FORM_TOOL) $(FORM_SELECTION)
# make asks the tool as it reads this file, so build it first.
FORM_TOOL_BUILT := $(shell [ -x $(FORM_TOOL) ] && [ -z "$$(find $(FORM_TOOL_SOURCES) -newer $(FORM_TOOL))" ] || \
	{ mkdir -p build/host && zig build-exe -O ReleaseSafe $(FORM_TOOL_MODULES) -femit-bin=$(FORM_TOOL).$$$$ >&2 && \
		mv $(FORM_TOOL).$$$$ $(FORM_TOOL); })
ifeq ($(wildcard $(FORM_TOOL)),)
$(error no $(FORM_TOOL), as zig says above; `make install-deps` installs zig)
endif
CHAIN := $(shell $(FORM_TOOL) $(FORM_SELECTION) names $(FORM_REF))
ifeq ($(CHAIN),)
$(error no form $(FORM_REF), as build/host/form says above; `make list-forms` lists them)
endif
endif
ifneq ($(strip $(VARIANTS)),)
ifneq ($(FORM_ASK),:)
NORMAL_VARIANTS := $(shell $(FORM_TOOL) --variant '$(VARIANTS)' variant-names)
ifeq ($(NORMAL_VARIANTS),)
$(error invalid VARIANTS selection)
endif
override VARIANTS := $(NORMAL_VARIANTS)
endif
endif
FORM_DIRS := $(shell $(FORM_ASK) dirs $(FORM_REF))
FORM_DIR := $(lastword $(FORM_DIRS))
FORM_FILES := $(wildcard $(addsuffix /form.yaml,$(FORM_DIRS)))
# form_list KEY is form.yaml's KEY along the chain; form_check KEY, its check: KEY.
form_list = $(shell $(FORM_ASK) list $(FORM_REF) $(1))
form_check = $(shell $(FORM_ASK) check $(FORM_REF) $(1))
KERNEL_ARGS := $(shell $(FORM_ASK) cmdline $(FORM_REF) $(ARCH))
ifeq ($(KERNEL_ARGS)$(filter :,$(FORM_ASK)),)
$(error form $(FORM) has no kernel arguments, as build/host/form says above)
endif

IPE ?=
BUILD = build/$(ARCH)$(if $(IPE),/ipe)
IPE_KERNEL ?= build/ipe-kernel/$(ARCH)/rootfs.tar
# Test an unpublished kernel without enabling IPE (notably JIT forms).
KERNEL_ROOTFS ?=
WEREWOLF_IPE_CRT ?=
WEREWOLF_IPE_KEY ?=
# Only the caller may opt out of protections: missing build inputs are a refusal,
# never consent. Direct-boot checks name their opt-outs with CHECK_DISABLE.
comma := ,
DISABLE ?=
ifneq ($(strip $(DISABLE)),)
ifeq ($(origin DISABLE),environment)
$(error DISABLE must be explicit on the make command line, not inherited from the environment)
endif
endif
APP ?=
OUT = $(BUILD)/$(FORM)$(if $(VARIANTS),-variants-$(VARIANTS))$(if $(APP),-app)$(if $(PUBLISHED),-published)$(if $(IPE),-ipe)
TAR ?= $(shell command -v bsdtar || echo tar)
SHA256 ?= $(shell command -v sha256sum || echo shasum -a 256)
.DELETE_ON_ERROR:

# A target named _NAME is a step of another target.
.PHONY: all install uninstall install-deps install-precommit precommit hooks image slot disk list-forms test \
	programs packages posture howl cve-tiers relock release-inputs dist clean help ci check check-forms \
	check-shellfree check-platform check-integrity check-cloud check-native check-one check-posture check-adhoc check-bastion check-people \
	check-slot check-compose check-updater check-updater-staged check-updater-published check-nodata \
	check-lease check-dns check-lan check-unwound check-static check-verity check-deadman check-metadata check-persist \
	check-dist check-gcp check-gcp-metadata check-aws check-azure check-secureboot check-firecracker check-updater-uki $(OUT)/disk.qcow2

all: image
install-deps:
	@tools/install-deps
precommit:
	@tools/git-hooks/pre-commit
install-precommit hooks:
	git config core.hooksPath tools/git-hooks
	@echo "pre-commit installed: test, lint, and a local howl run"

# howl always pins locked packages; PUBLISHED=1 takes programs from werewolf's repository.
HOWL_BUILD = $(HOWL) _build --verbose --with $(FORM_REF) $(FORM_SELECTION) --arch $(ARCH) $(if $(DISABLE),--disable=$(DISABLE)) \
	--build $(BUILD) --programs $(PROGRAMS) $(if $(APP),--app-root $(APP)) \
	$(if $(PUBLISHED),--published) $(if $(IPE),--ipe-kernel $(IPE_KERNEL) --ipe-key $(WEREWOLF_IPE_KEY) --ipe-cert $(WEREWOLF_IPE_CRT)) \
	$(if $(KERNEL_ROOTFS),--kernel-rootfs $(KERNEL_ROOTFS)) \
	$(if $(IPE_UPDATES),--ipe-updates $(IPE_UPDATES) --image-serial $(IMAGE_SERIAL)) \
	$(if $(IMAGE_INDEX),--image-index $(IMAGE_INDEX)) $(if $(TPM),--tpm)
image slot: $(HOWL)
	$(HOWL_BUILD) $@
.PHONY: prebuilt
prebuilt: $(HOWL)
	$(HOWL_BUILD) prebuilt
disk: $(HOWL)
	$(HOWL_BUILD) $(if $(DISK),--disk $(DISK)) $(if $(DISK_MIB),--disk-mib $(DISK_MIB)) $(if $(DISK_ARGS),--disk-args "$(DISK_ARGS)") disk
# A released disk never takes DISK_ARGS.
$(OUT)/disk.qcow2: $(HOWL)
	$(HOWL_BUILD) $(if $(DISK_MIB),--disk-mib $(DISK_MIB)) qcow2

# apko locks pin every package; these rules serve relock, and release-inputs's boot locks.
LOCK = build/lock
FORM_LOCK = $(LOCK)/$(FORM)$(if $(VARIANTS),-variants-$(VARIANTS))$(if $(PUBLISHED),-published).lock.json
BOOT_LOCKS = $(LOCK)/kernel.lock.json $(LOCK)/boot.lock.json
LOCKS = $(FORM_LOCK) $(BOOT_LOCKS)
FORM_APKO = $(BUILD)/form/$(FORM)$(if $(VARIANTS),-variants-$(VARIANTS)).yaml
# apko_retry COMMAND retries after 15, 30 and 45 s: the package server refuses bursts (HTTP 403).
APKO_NETWORK = status code (403|408|429|5[0-9][0-9])|connection reset|i/o timeout|TLS handshake|deadline exceeded|unexpected EOF|failed to fetch
apko_retry = o=$(CURDIR)/$@.apko && for t in 1 2 3 4; do \
	{ $(1); echo $$? >$$o.rc; } 2>&1 | tee $$o; rc=$$(cat $$o.rc); \
	if [ "$$rc" = 0 ]; then rm -f $$o $$o.rc; break; fi; \
	if ! grep -Eq '$(APKO_NETWORK)' $$o || [ $$t -eq 4 ]; then rm -f $$o $$o.rc; exit 1; fi; \
	echo "apko could not reach the package server; trying again in $$((t * 15))s" >&2; sleep $$((t * 15)); done
# apko_lock CONFIG runs in CONFIG's directory, where apko resolves its paths.
apko_lock = mkdir -p $(LOCK) && cd $(dir $(1)) && \
	$(call apko_retry,apko lock --arch aarch64$(,)x86_64 --output $(CURDIR)/$@ $(notdir $(1)))
, := ,
$(FORM_LOCK): $(FORM_FILES) | $(FORM_APKO)
	$(call apko_lock,$(FORM_APKO))
# Keep an unchanged config's mtime, as howl does, or howl rebuilds the root.
# The config names werewolf's key in $(BUILD)/keys (lib/package.zig's keyring).
$(FORM_APKO): $(FORM_FILES) $(FORM_TOOL)
	mkdir -p $(dir $@) $(BUILD)/keys && $(FORM_TOOL) $(FORM_SELECTION) apko $(FORM_REF) >$@.tmp && \
		{ cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@; } && \
		{ cmp -s release/packages.pub $(BUILD)/keys/werewolf-packages.rsa.pub || \
			cp release/packages.pub $(BUILD)/keys/werewolf-packages.rsa.pub; }
$(LOCK)/kernel.lock.json: boot/kernel.yaml release/packages.pub
	mkdir -p $(BUILD)/boot $(BUILD)/keys && \
		cp boot/kernel.yaml $(BUILD)/boot/kernel.yaml && \
		cp release/packages.pub $(BUILD)/keys/werewolf-packages.rsa.pub
	$(call apko_lock,$(BUILD)/boot/kernel.yaml)
$(LOCK)/boot.lock.json: boot/boot.yaml
	$(call apko_lock,$<)
relock:
	rm -f $(LOCKS)
	$(MAKE) --no-print-directory FORM=$(FORM_REF) $(BOOT_LOCKS) _howl-lock

# Zig is pre-1.0, so insist on the version the code is written for.
ZIG_VERSION = 0.17.0
PROGRAMS = build/$(ARCH)/programs
CMDS := $(filter-out howl,$(patsubst cmd/%/,%,$(wildcard cmd/*/)))
# program_bin NAME is where cmd/NAME is built; form_bin DIR, where forms/F/cmd/P is.
program_bin = $(PROGRAMS)/$(1)/$(or $(PROGRAM_AT_$(1)),usr/lib/werewolf/$(1))
PROGRAM_AT_init = init
form_bin = $(PROGRAMS)/forms/$(notdir $(patsubst %/cmd/$(notdir $(1)),%,$(1)))/usr/lib/werewolf/$(notdir $(1))
FORM_CMDS := $(sort $(patsubst %/,%,$(wildcard forms/*/cmd/*/) $(foreach d,$(FORM_DIRS),$(wildcard $(d)/cmd/*/))))
POSTURE_BIN = $(call program_bin,posture)
define zig_check
@[ "$$(zig version)" = "$(ZIG_VERSION)" ] || \
	{ echo "$< is written for zig $(ZIG_VERSION), not $$(zig version)" >&2; exit 1; }
mkdir -p $(dir $@)
endef

# A program may import any library; a library, only what its --dep flags name.
LIB_MODULES = --dep data-transfer --dep sandbox --dep seal -Mdata-read=lib/data-transfer-read.zig --dep data-transfer --dep people --dep service -Mdata-source=lib/data-transfer-source.zig -Mdata-transfer=lib/data-transfer.zig --dep seal -Msandbox=lib/sandbox.zig -Mbroker=lib/broker.zig -Mdm=lib/dm.zig \
	-Mverity=lib/verity.zig -Mipe=lib/ipe.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig \
	-Mupdate-policy=lib/update-policy.zig -Mnetwork=lib/network.zig \
	--dep sandbox -Mnet-rule=lib/net-rule.zig --dep network --dep net-rule --dep sandbox -Mdns=lib/dns.zig -Mhostkey=lib/hostkey.zig \
	--dep allow --dep sshd -Mform=lib/form.zig --dep seal -Maudit=lib/audit.zig \
	--dep seal --dep settings -Mservice=lib/service.zig -Mallow=lib/allow.zig -Mcve=lib/cve.zig \
	--dep network -Mcmdline=lib/cmdline.zig --dep settings -Msshd=lib/sshd.zig --dep form --dep seal \
	--dep service --dep package --dep allow --dep people -Mcompose=lib/compose.zig -Mpackage=lib/package.zig -Mimage=lib/image.zig \
	-Mgpt=boot/gpt.zig --dep package -Mapk=lib/apk.zig -Mfiles=files.zig -Mpeople=lib/people.zig \
	--dep apk --dep update-policy -Mprebuilt=lib/prebuilt.zig -Muki=tools/uki.zig --dep apk -Mtpm=lib/tpm.zig \
	--dep prebuilt --dep update-policy -Mboot-download=lib/boot-download.zig -Msecurity-inputs=lib/security-inputs.zig \
	-Muefi-sig=lib/uefi-sig.zig --dep form -Mtest-plan=test/native/plan.zig
ZIG_MODULES =--dep data-read --dep data-source --dep data-transfer --dep sandbox --dep broker --dep dm --dep verity --dep ipe --dep prebuilt --dep uki --dep tpm --dep seal --dep settings --dep update-policy \
	--dep boot-download --dep security-inputs --dep uefi-sig --dep test-plan \
	--dep dns --dep net-rule --dep network --dep hostkey --dep form --dep audit --dep service --dep allow --dep cve --dep cmdline \
	--dep sshd --dep compose --dep package --dep image --dep gpt --dep apk --dep files --dep people -Mroot=$(1) $(LIB_MODULES)
# A host-side test in Zig also takes test/host as module host (test/host/README.md):
# zig test $(call HOST_ZIG_MODULES,FILE) tests it, and $(call host_test,FILE) ARGS runs it.
HOST_ZIG_MODULES = --dep host $(call ZIG_MODULES,$(1)) -Mhost=test/host/host.zig
host_test = zig run -O ReleaseSafe $(call HOST_ZIG_MODULES,$(1)) --
# console boots a machine with no shell and judges it from outside (test/console.zig),
# with the native suites' regex shim; the checks that boot through it take it.
CONSOLE_CHECK = build/host/console
# Host-side programs that scripts, workflows and release tools run: test/NAME.zig is build/host/NAME.
HOST_PROGRAMS = cloud-console cloud-posture azure-security ssh-su metadata ipe-boot \
	check-legacy-image check-public-image check-protected-qemu check-published-lifecycle check-published-run \
	check-independent-updates remote-qemu check-hypervisor-isolation
$(addprefix build/host/,$(HOST_PROGRAMS)): build/host/%: test/%.zig test/published.zig test/postdoc.zig $(wildcard test/host/*.zig test/host/*.yaml lib/*.zig)
	$(zig_check)
	t=$@.$$$$ && zig build-exe -O ReleaseSafe $(call HOST_ZIG_MODULES,$<) -femit-bin=$$t && mv -f $$t $@
# The published-image checks share test/published.zig, imported by path.
build/host/check-public-image build/host/check-protected-qemu build/host/check-published-lifecycle build/host/check-published-run \
	build/host/check-legacy-image: test/published.zig
build/host/check-legacy-image: $(CONSOLE_CHECK)
# Host-side checks' own tests, in make test: they import host and the lib modules.
HOST_TESTS = test/check-hypervisor-isolation.zig test/metadata.zig test/check-dist.zig test/check-legacy-image.zig test/check-secureboot.zig \
	test/check-provider-ab.zig test/ab-fixture.zig test/check-bhyve-secureboot.zig test/check-bhyve-lifecycle.zig \
	test/check-lima-secureboot.zig test/gcp-metadata.zig \
	test/build-traced-stub.zig test/trace-stub.zig test/check-image-updater.zig \
	test/check-independent-updates.zig test/check-people-persist.zig forms/vuln-demo/test/appliance.zig \
	test/check-published-run.zig test/check-published-lifecycle.zig test/check-public-image.zig \
	test/check-protected-qemu.zig test/remote-qemu.zig

# Every guest binary is a static PIE, so ASLR moves its code and data, not only its
# stack and heap; howl refuses a root with a fixed-address program (lib/image.zig).
PROGRAM_FLAGS = -O ReleaseSafe -fstrip -fPIE
# A change of flags rebuilds every program, as a change of its source does.
PROGRAM_FLAGS_STAMP = build/$(ARCH)/program-flags
.PHONY: _program-flags
_program-flags:
$(PROGRAM_FLAGS_STAMP): _program-flags
	@mkdir -p $(dir $@)
	@printf '%s\n' '$(PROGRAM_FLAGS)' >$@.new
	@cmp -s $@.new $@ && rm -f $@.new || mv -f $@.new $@
# program NAME, BINARY, DIR is the rule that builds DIR (default cmd/NAME) into BINARY.
define program
$(2): $(or $(3),cmd/$(1))/$(1).zig $$(wildcard $(or $(3),cmd/$(1))/*.zig) $$(wildcard lib/*.zig) tools/uki.zig $(PROGRAM_FLAGS_STAMP)
	$$(zig_check)
	zig build-exe $(PROGRAM_FLAGS) -target $$(ARCH)-linux-musl $$(call ZIG_MODULES,$$<) -femit-bin=$$@
endef
$(foreach p,$(filter-out unwound-age,$(CMDS)),$(eval $(call program,$(p),$(call program_bin,$(p)))))
$(foreach c,$(FORM_CMDS),$(eval $(call program,$(notdir $(c)),$(call form_bin,$(c)),$(c))))

$(PROGRAMS)/plex-loopback/usr/lib/werewolf/plex-loopback.so: forms/plex/lib/plex-loopback.zig Makefile
	$(zig_check)
	zig build-lib -dynamic -O ReleaseSafe -fstrip -target $(ARCH)-linux-musl -fallow-shlib-undefined $< -femit-bin=$@
	# Select the form's maintained musl for Plex's self-bootstrapping ELFs.
	mkdir -p $(PROGRAMS)/plex-loopback/usr/lib/plexmediaserver/lib
	ln -sfn /usr/lib/werewolf-musl/libc.so $(PROGRAMS)/plex-loopback/usr/lib/plexmediaserver/lib/libc.so
	ln -sfn libc.so $(PROGRAMS)/plex-loopback/usr/lib/plexmediaserver/lib/ld-musl-$(ARCH).so.1

# howl makes programs before it builds an image.
programs: $(foreach p,$(CMDS),$(call program_bin,$(p))) $(foreach c,$(FORM_CMDS),$(call form_bin,$(c))) \
	$(PROGRAMS)/plex-loopback/usr/lib/werewolf/plex-loopback.so

# Manuals travel in the same overlay and APK as their executable. Keeping them
# as separate targets lets a documentation edit rebuild an image without Zig.
MDOC = build/host/mdoc
MAN_SOURCES := $(wildcard cmd/*/*.[1-9].md forms/*/cmd/*/*.[1-9].md examples/*/cmd/*/*.[1-9].md)
MAN_PAGES := $(addprefix build/man/,$(basename $(MAN_SOURCES)))
$(MDOC): tools/mdoc.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe $< -femit-bin=$@
$(MAN_PAGES): build/man/%: %.md $(MDOC)
	mkdir -p $(dir $@)
	$(MDOC) $< >$@.tmp && mv -f $@.tmp $@
.PHONY: manpages
programs: manpages
define manual
$(2)/usr/share/man/man$(subst .,,$(suffix $(basename $(1))))/$(notdir $(basename $(1))): build/man/$(basename $(1))
	mkdir -p $$(dir $$@)
	cp $$< $$@
manpages: $(2)/usr/share/man/man$(subst .,,$(suffix $(basename $(1))))/$(notdir $(basename $(1)))
endef
$(foreach p,$(CMDS),$(foreach m,$(wildcard cmd/$(p)/*.[1-9].md),$(eval $(call manual,$(m),$(PROGRAMS)/$(p)))))
$(foreach c,$(FORM_CMDS),$(foreach m,$(wildcard $(c)/*.[1-9].md),$(eval $(call manual,$(m),$(PROGRAMS)/forms/$(notdir $(patsubst %/cmd/$(notdir $(c)),%,$(c)))))))

VERITY_BIN = build/host/verity
$(VERITY_BIN): tools/verity.zig lib/verity.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe --dep verity -Mroot=$< -Mverity=lib/verity.zig -femit-bin=$@

UKI_BIN = build/host/uki
$(UKI_BIN): tools/uki.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe -Mroot=$< -femit-bin=$@

# A release's UKI: kernel, stage0, root and command line as one PE the boot
# key signs (tools/uki; docs/design/implemented/verified-boot.md, docs/releases.md).
# Built when WEREWOLF_BOOT_KEY names the key; the certificate is the
# committed release/boot.crt, and UKI_STUB systemd's linuxaa64.efi.stub.
WEREWOLF_BOOT_CRT ?= release/boot.crt
UKI_STUB ?= out/tools/stubs/$(ARCH)/linux.efi.stub
UKI = $(OUT)/slot/uki.efi
UKI_WORK = $(BUILD)/uki
UKI_NATIVE ?=
UKI_ARGS ?= $(if $(UKI_NATIVE),werewolf.native=1 werewolf.slots=57e1f000-77e2-4b0f-8a3c-0000000000a0 werewolf.esp=57E1-F000)
.PHONY: _uki-options
_uki-options:
$(UKI_WORK)/options: _uki-options
	@mkdir -p $(UKI_WORK)
	@printf '%s\n' '$(CONSOLE)' '$(UKI_ARGS)' '$(WEREWOLF_BOOT_KEY)' '$(WEREWOLF_BOOT_CRT)' '$(UKI_STUB)' >$@.new
	@cmp -s $@.new $@ && rm -f $@.new || mv -f $@.new $@
$(UKI): $(OUT)/slot/root.erofs $(OUT)/slot/stage0.zst $(OUT)/slot/cmdline $(BUILD)/vmlinuz $(UKI_BIN) $(WEREWOLF_BOOT_KEY) $(WEREWOLF_BOOT_CRT) $(UKI_STUB) $(UKI_WORK)/options
	@[ -n "$(WEREWOLF_BOOT_KEY)" ] && [ -n "$(WEREWOLF_BOOT_CRT)" ] && [ -f "$(UKI_STUB)" ] || \
		{ echo "$@: WEREWOLF_BOOT_KEY, WEREWOLF_BOOT_CRT and UKI_STUB (= systemd's linuxaa64.efi.stub) name the boot key and the stub (docs/testing.md)" >&2; exit 1; }
	@mkdir -p $(UKI_WORK) && cp $(OUT)/slot/root.erofs $(UKI_WORK)/
	@touch -t 197001010000 $(UKI_WORK)/root.erofs
	@cd $(UKI_WORK) && $(TAR) -cf - --format newc --uid 0 --gid 0 --numeric-owner root.erofs | zstd -1 -q -c >root.cpio.zst
	@cat $(OUT)/slot/stage0.zst $(UKI_WORK)/root.cpio.zst >$(UKI_WORK)/initrd
	@printf '%s console=%s %s\0' "$$(cat $(OUT)/slot/cmdline)" $(CONSOLE) '$(UKI_ARGS)' >$(UKI_WORK)/cmdline
	@rm -f $(UKI).signed
	$(UKI_BIN) $(UKI_STUB) $(UKI).unsigned .linux=$(BUILD)/vmlinuz .initrd=$(UKI_WORK)/initrd .cmdline=$(UKI_WORK)/cmdline
	osslsigncode sign -time 0 -certs $(WEREWOLF_BOOT_CRT) -key $(WEREWOLF_BOOT_KEY) -in $(UKI).unsigned -out $(UKI).signed >/dev/null
	@mv -f $(UKI).signed $(UKI) && rm -f $(UKI).unsigned

# Built under a temporary name, so a running check never finds an empty howl, which sh runs as a pass.
howl: $(HOWL)
$(HOWL): cmd/howl/howl.zig $(wildcard lib/data-transfer*.zig) $(wildcard cmd/howl/*.zig) lib/settings.zig lib/update-policy.zig lib/network.zig \
	lib/form.zig lib/yaml.zig test/native/plan.zig test/native/steps.zig test/native/host.zig lib/allow.zig lib/service.zig lib/seal.zig lib/sshd.zig lib/compose.zig lib/package.zig lib/apk.zig lib/apk-version.zig \
	lib/baselayout.zig lib/verity.zig lib/ipe.zig lib/prebuilt.zig lib/tpm.zig lib/boot-authority.zig lib/uefi-sig.zig lib/image.zig tools/uki.zig boot/gpt.zig files.zig \
	lib/boot-download.zig lib/security-inputs.zig $(shell grep -o '@embedFile("[^"]*")' files.zig | cut -d'"' -f2)
	$(zig_check)
	t=$@.$$$$ && zig build-exe -O ReleaseSafe $(call ZIG_MODULES,$<) -femit-bin=$$t && mv -f $$t $@

# install-deps installs the Zig that builds howl, so it comes first, even with -j.
INSTALL_DIRS = $(HOME)/bin $(HOME)/.local/bin /usr/local/bin
$(HOWL): | $(if $(filter install,$(MAKECMDGOALS)),install-deps)
install: install-deps $(HOWL)
	@tools/install $(HOWL) $(INSTALL_DIRS)
uninstall:
	@tools/install -u $(INSTALL_DIRS)

TEST_SK = build/host/test-sk.so
$(TEST_SK): tools/test-sk.zig
	$(zig_check)
	t=$@.$$$$ && zig build-lib -dynamic -O ReleaseSafe -lc -femit-bin=$$t $< && mv -f $$t $@
$(CONSOLE_CHECK): test/console.zig test/native/regex.c $(wildcard test/host/*.zig)
	$(zig_check)
	t=$@.$$$$ && zig build-exe -O ReleaseSafe -lc test/native/regex.c $(call HOST_ZIG_MODULES,$<) -femit-bin=$$t && mv -f $$t $@

# Each file's tests are a target, so make -j test runs them in parallel.
PROGRAM_SOURCES = $(foreach d,$(wildcard cmd/* forms/*/cmd/*),$(d)/$(notdir $(d)).zig)
TEST_SOURCES = lib/data-transfer.zig cmd/data-export/data-export.zig cmd/howl/boot-config.zig cmd/howl/lima.zig cmd/howl/local-secure.zig cmd/howl/data.zig cmd/howl/data-image.zig cmd/howl/data-helper.zig cmd/howl/data-cloud.zig cmd/howl/data-aws.zig cmd/howl/data-cloud-disk.zig cmd/howl/data-cloud-target.zig tools/mdoc.zig test/host/host.zig $(HOST_TESTS) test/howl/run.zig test/check-dns.zig test/unwound/lab.zig lib/yaml.zig test/native/plan.zig tools/native-tests.zig tools/form-coverage.zig test/native/iterate.zig test/native/system.zig cmd/howl/test.zig lib/sandbox.zig lib/seal.zig lib/dm.zig lib/verity.zig lib/settings.zig lib/update-policy.zig \
	lib/network.zig lib/net-rule.zig lib/dns.zig lib/lookup.zig cmd/unwound/fuzz.zig cmd/unwound/age.zig cmd/unwound/bootstrap.zig cmd/unwound/age_ipc.zig cmd/unwound/age_gate.zig cmd/unwound/age_http.zig cmd/unwound/age_evidence.zig lib/cmdline.zig lib/hostkey.zig lib/audit.zig lib/form.zig lib/compose.zig lib/package.zig \
	lib/allow.zig lib/service.zig lib/cve.zig lib/sshd.zig lib/image.zig lib/apk.zig lib/people.zig tools/form.zig tools/package.zig \
	boot/gpt.zig lib/ipe.zig lib/prebuilt.zig lib/boot-download.zig lib/security-inputs.zig lib/broker.zig lib/tpm.zig lib/boot-authority.zig tools/cve-tiers.zig tools/test-sk.zig tools/doc-check.zig tools/uki.zig tools/update-unwound-age-data.zig $(PROGRAM_SOURCES)
TEST_EXTRA = _test/mdoc _test/howl-smoke _test/howl-lock _test/cloud-console _test/azure-security _test/provider-ab _test/boot-images _test/local-prerequisites _test/tpm-floor _test/release-signing _test/form-coverage _test/package-consumers _test/probes
test: $(addprefix _test/,$(TEST_SOURCES)) $(TEST_EXTRA) _test/ci-forms
	@echo "test: $(words $(TEST_SOURCES)) suites passed, and howl's lines"
# The dispatch test starts nested Make processes with bounded deadlines.
# Run it after the parallel unit suites so CPU contention cannot exhaust them.
ifneq ($(filter test,$(MAKECMDGOALS)),)
_test/ci-forms: $(addprefix _test/,$(TEST_SOURCES)) $(TEST_EXTRA)
endif
.PHONY: _test/mdoc
_test/mdoc: $(MDOC)
	sh test/mdoc $(MDOC)
_test/ci-forms: ; zig test test/ci-forms.zig
# CI's check jobs check forms one at a time with it (test/ci-forms.zig).
build/host/ci-forms: test/ci-forms.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe -Mroot=$< -femit-bin=$@
_test/cloud-console: build/host/cloud-console build/host/azure-security build/host/cloud-posture
	zig test $(call HOST_ZIG_MODULES,test/cloud-posture.zig)
	$(call host_test,test/cloud-checks.zig)
$(addprefix _test/,$(HOST_TESTS)): _test/%: ; zig test $(call HOST_ZIG_MODULES,$*)
_test/probes:
	@mkdir -p build/test-probes
	zig test -lc test/native/match.zig test/native/regex.c
	zig test -lc test/native/probes.zig test/native/regex.c
	zig test -lc test/native/tree.zig test/native/regex.c
	zig test -lc test/native/tcp.zig test/native/regex.c
	zig test test/native/write.zig
	zig test test/native/process.zig
	zig test test/native/udp.zig
	zig test -lc test/native/regex.c $(call HOST_ZIG_MODULES,test/native-host.zig)
	zig test -lc test/native/regex.c $(call HOST_ZIG_MODULES,test/console.zig)
	zig test test/native/driver.zig
	zig test --dep test-driver -Mroot=test/native/stage.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/samba/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=forms/nats/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/zeek/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/solr/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/tailscale/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/suricata/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test test/native/bson.zig
	zig test test/native/amqp.zig
	zig test --dep test-driver -Mroot=forms/rabbitmq/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=examples/unifi-os/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/haproxy/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/opencanary/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/headscale/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=forms/squid/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=forms/mastodon/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=forms/home-assistant/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=forms/wordpress/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=forms/limesurvey/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=forms/mediawiki/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=forms/bugsink/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/cron/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/postdoc-server/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/mox/test/smtp.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/minecraft/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=forms/mox/test/submit.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/galene/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=forms/greenbone/test/web.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=forms/immich/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/moodle/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/langflow/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test --dep test-driver -Mroot=forms/overleaf/test/driver.zig -Mtest-driver=test/native/driver.zig
	zig test -lc --dep test-driver -Mroot=test/native/platform.zig -Mtest-driver=test/native/driver.zig
	zig build-exe -lc -O ReleaseSafe test/native/probes.zig test/native/regex.c -femit-bin=build/test-probes/host
	$(call host_test,test/probe-tests.zig) build/test-probes/host

FORM_COVERAGE = build/host/form-coverage
$(FORM_COVERAGE): tools/form-coverage.zig test/native/plan.zig test/native/steps.zig test/native/host.zig lib/form.zig lib/yaml.zig
	$(zig_check)
	t=$@.$$$$ && zig build-exe -O ReleaseSafe $(call ZIG_MODULES,$<) -femit-bin=$$t && mv -f $$t $@
# make form-coverage lists each form's integration cases (docs/testing.md).
.PHONY: form-coverage
form-coverage: $(FORM_COVERAGE)
	@$(FORM_COVERAGE) --list
_test/form-coverage: $(FORM_COVERAGE)
	$(FORM_COVERAGE) --probes
_test/bhyve-runtime: ; zig test tools/bhyve-arm64/runtime.zig
_test/package-consumers: build/host/form
	$(call host_test,test/package-consumers.zig)
_test/release-signing: _test/tools/release/release.zig
_test/azure-security: ; zig test test/azure-security.zig
_test/provider-ab: _test/bhyve-runtime
	zig test --test-filter evidence --test-filter provider $(call ZIG_MODULES,test/host/host.zig)
_test/local-prerequisites: $(HOWL)
	$(call host_test,test/lima-state.zig) $(HOWL)
_test/tpm-floor: build/host/tpm-floor test/check-tpm-floor.zig
	$(call host_test,test/check-tpm-floor.zig) build/host/tpm-floor
_test/boot-images: $(HOWL) build/host/form _test/tools/release/release.zig
	$(call host_test,test/owner-control.zig) $(HOWL)
# build/host/release builds, signs and publishes images (tools/release/README.md).
RELEASE_TOOL = build/host/release
RELEASE_MODULES = -lc $(call ZIG_MODULES,tools/release/release.zig)
$(RELEASE_TOOL): $(wildcard tools/release/*.zig lib/*.zig)
	$(zig_check)
	t=$@.$$$$ && zig build-exe -O ReleaseSafe $(RELEASE_MODULES) -femit-bin=$$t && mv -f $$t $@
_test/tools/release/release.zig: ; zig test $(RELEASE_MODULES)
_test/lib/sandbox.zig _test/lib/audit.zig: _test/%: ; zig test --dep seal -Mroot=$* -Mseal=lib/seal.zig
_test/lib/dns.zig _test/lib/net-rule.zig: _test/%: ; zig test $(call ZIG_MODULES,$*)
_test/lib/cmdline.zig: ; zig test --dep network -Mroot=lib/cmdline.zig -Mnetwork=lib/network.zig
_test/lib/prebuilt.zig: ; zig test --dep apk --dep update-policy -Mroot=lib/prebuilt.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig -Mupdate-policy=lib/update-policy.zig
_test/lib/boot-download.zig: ; zig test --dep prebuilt --dep update-policy --dep host -Mroot=lib/boot-download.zig \
	--dep apk --dep update-policy -Mprebuilt=lib/prebuilt.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig \
	-Mupdate-policy=lib/update-policy.zig -Mhost=test/host/host.zig
_test/cmd/howl/howl.zig _test/cmd/howl/test.zig _test/cmd/howl/data.zig _test/cmd/howl/data-helper.zig _test/cmd/howl/data-cloud.zig _test/cmd/howl/data-cloud-target.zig _test/cmd/howl/data-cloud-disk.zig _test/cmd/howl/data-aws.zig: _test/%: ; zig test $(call HOST_ZIG_MODULES,$*)
_test/lib/tpm.zig: ; zig test --dep apk -Mroot=lib/tpm.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig
_test/lib/boot-authority.zig: ; zig test --dep apk -Mroot=lib/boot-authority.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig
build/host/tpm-floor: tools/tpm-floor.zig lib/tpm.zig lib/boot-authority.zig lib/apk.zig lib/package.zig
	@mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe --dep apk --dep tpm -Mroot=$< --dep apk -Mtpm=lib/tpm.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig -femit-bin=$@

.PHONY: check-tpm-floor check-independent-updates
# The release floor against swtpm, as guest root would attack it (lib/tpm.zig).
check-tpm-floor: _test/tpm-floor

# Unrelated machines install from a public image, take their own TPMs, and update
# from a static channel with no host help (docs/design/implemented/independent-updates.md).
check-independent-updates: $(HOWL)
	$(call host_test,test/check-independent-updates.zig) $(HOWL) $(BUILD)/check/independent-updates $(PROVIDER)

_test/lib/form.zig: ; zig test --dep allow --dep sshd -Mroot=lib/form.zig -Mallow=lib/allow.zig --dep settings -Msshd=lib/sshd.zig -Msettings=lib/settings.zig
_test/lib/sshd.zig: ; zig test --dep settings -Mroot=lib/sshd.zig -Msettings=lib/settings.zig
_test/lib/service.zig: ; zig test --dep seal --dep settings -Mroot=lib/service.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig
_test/tools/form.zig: ; zig test $(FORM_TOOL_MODULES)
_test/lib/compose.zig: ; zig test $(COMPOSE_MODULES)
_test/tools/package.zig _test/lib/apk.zig: _test/%: ; zig test --dep package -Mroot=$* -Mpackage=lib/package.zig
_test/tools/cve-tiers.zig: ; zig test $(call ZIG_MODULES,tools/cve-tiers.zig)
_test/tools/test-sk.zig: ; zig test tools/test-sk.zig -lc
_test/cmd/%.zig: ; zig test $(call ZIG_MODULES,cmd/$*.zig)
_test/forms/%.zig: ; zig test $(call ZIG_MODULES,forms/$*.zig)
# host's tests read its YAML tables with lib/form.zig, which host itself does not import.
_test/test/host/host.zig: ; zig test $(call ZIG_MODULES,test/host/host.zig)
_test/test/howl/run.zig: ; zig test $(call ZIG_MODULES,test/howl/run.zig)
_test/test/native/plan.zig _test/tools/native-tests.zig _test/tools/form-coverage.zig: _test/%: ; zig test $(call ZIG_MODULES,$*)
_test/%.zig: ; zig test $*.zig

SYSLOG_PROBE = $(BUILD)/syslog-init
$(SYSLOG_PROBE): test/syslog-init.zig cmd/syslogd/policy.zig lib/seal.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe -fPIE -target $(ARCH)-linux-musl --dep seal --dep log-policy \
		-Mroot=$< -Mseal=lib/seal.zig -Mlog-policy=cmd/syslogd/policy.zig -femit-bin=$@
.PHONY: check-syslog fuzz-syslog
SYSLOG_FUZZ_RUNS ?= 100000
fuzz-syslog:
	@for target in 'fuzz syslog' 'fuzz kernel' 'fuzz configuration' 'fuzz gzip'; do \
		zig build --build-file cmd/syslogd/build.zig test -Dfilter="$$target" \
			--fuzz=$(SYSLOG_FUZZ_RUNS) --summary all || exit; \
	done

check-syslog: $(HOWL) $(call program_bin,syslogd) $(call program_bin,leash) $(SYSLOG_PROBE)
	@test -r $(BUILD)/vmlinuz || $(MAKE) --no-print-directory DISABLE=$(CHECK_DISABLE) image
	$(call host_test,test/check-syslog.zig) --arch $(ARCH) --kernel $(BUILD)/vmlinuz \
		--daemon $(call program_bin,syslogd) --probe $(SYSLOG_PROBE) \
		--leash $(call program_bin,leash) --work $(BUILD)/check/syslog \
		$(if $(SYSLOG_MODULES),--modules $(SYSLOG_MODULES))

_test/howl-smoke: $(HOWL) $(CONSOLE_CHECK)
	@test/howl-smoke $(HOWL) $(BUILD)
	@$(call host_test,test/howl/run.zig) $(HOWL) test/howl/cases.yaml protections make forms ssh current-user
	@$(call host_test,test/native-tests-regression.zig) $(HOWL)
	@zig test test/native/driver.zig
	@zig test --dep test-driver -Mroot=forms/greenbone/test/driver.zig -Mtest-driver=test/native/driver.zig
_test/howl-lock: $(HOWL)
	@$(call host_test,test/howl/run.zig) $(HOWL) test/howl/cases.yaml lock

posture: $(POSTURE_BIN)
ifeq ($(HOST_OS)-$(HOST_ARCH),Linux-$(ARCH))
	$(if $(filter 0,$(shell id -u)),,sudo) $(POSTURE_BIN)
else
	@echo "$(POSTURE_BIN): copy it to a Linux $(ARCH) machine and run it there, as root"
endif

PACKAGE_TOOL = build/host/package
PACKAGES = $(BUILD)/packages
PACKAGE_TIME ?= $(shell git log -1 --format=%ct 2>/dev/null)
# Each program depends on the format its files are in (lib/compose.zig).
PACKAGE_FORMAT = $(shell $(FORM_ASK) format)
$(PACKAGE_TOOL): tools/package.zig lib/package.zig lib/baselayout.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe --dep package -Mroot=$< -Mpackage=lib/package.zig -femit-bin=$@
# Each form CI publishes is NAME-form: the form as an image stages it, with its
# own programs, depending on what it is built on, takes and runs (tools/form.zig).
PACKAGE_FORMS = $(shell $(FORM_ASK) packaged)
packages: $(PACKAGE_TOOL) $(FORM_TOOL) programs
	@[ -n "$(PACKAGE_TIME)" ] || { echo "packages: no commit time; set PACKAGE_TIME" >&2; exit 1; }
	# Where a boot key is given, each release form's slot gains its signed
	# UKI first, so the packages below can carry it (docs/releases.md).
	@[ -z "$(WEREWOLF_BOOT_KEY)" ] || [ -z "$(UKI_STUB)" ] || for f in $(RELEASE_FORMS); do \
		$(MAKE) --no-print-directory FORM=$$f ARCH=$(ARCH) slot && \
		$(MAKE) --no-print-directory FORM=$$f ARCH=$(ARCH) WEREWOLF_BOOT_KEY=$(WEREWOLF_BOOT_KEY) \
			WEREWOLF_BOOT_CRT=$(WEREWOLF_BOOT_CRT) UKI_STUB=$(UKI_STUB) $(BUILD)/$$f/slot/uki.efi || exit 1; done
	rm -rf $(PACKAGES)/$(ARCH) $(PACKAGES)/format $(PACKAGES)/advisories $(PACKAGES)/forms && mkdir -p $(PACKAGES)/$(ARCH) $(PACKAGES)/format/usr/lib/werewolf $(PACKAGES)/advisories/usr/share/werewolf
	echo $(PACKAGE_FORMAT) >$(PACKAGES)/format/usr/lib/werewolf/format && $(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) $(PACKAGES)/format \
		werewolf-format$(PACKAGE_FORMAT) - $(ARCH) $(PACKAGE_TIME) "werewolf's format (lib/compose.zig)" provide:werewolf-format=$(PACKAGE_FORMAT)
	cp release/advisories $(PACKAGES)/advisories/usr/share/werewolf/ && $(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) \
		$(PACKAGES)/advisories werewolf-advisories - $(ARCH) $(PACKAGE_TIME) "werewolf's own advisories (release/advisories)"
	$(PACKAGE_TOOL) baselayout $(PACKAGES)/$(ARCH) $(ARCH) $(PACKAGE_TIME)
	for p in $(CMDS); do $(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) $(PROGRAMS)/$$p werewolf-$$p - \
		$(ARCH) $(PACKAGE_TIME) "werewolf's $$p (cmd/$$p)" depend:werewolf-format$(PACKAGE_FORMAT) || exit 1; done
	# A signed UKI, when the boot key built one (docs/design/implemented/verified-boot.md):
	# its package puts it in new roots, where installEsp lays it.
	for f in $(RELEASE_FORMS); do [ ! -f $(BUILD)/$$f/slot/uki.efi ] || { \
		t=$(PACKAGES)/uki/$$f/usr/lib/werewolf/uki && mkdir -p $$t && \
		cp $(BUILD)/$$f/slot/uki.efi $$t/slot.efi && \
		$(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) $(PACKAGES)/uki/$$f uki-$$f - \
		$(ARCH) $(PACKAGE_TIME) "werewolf's signed UKI for $$f (docs/design/implemented/verified-boot.md)" \
		depend:werewolf-format$(PACKAGE_FORMAT) || exit 1; }; done
	for f in $(PACKAGE_FORMS); do t=$(PACKAGES)/forms/$$f && $(FORM_TOOL) stage $$f $$t && \
		{ [ ! -d $(PROGRAMS)/forms/$$f ] || cp -R $(PROGRAMS)/forms/$$f/. $$t/; } && \
		$(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) $$t $$f-form - $(ARCH) $(PACKAGE_TIME) "werewolf's form $$f (forms/$$f)" \
		$$($(FORM_TOOL) depends $$f | sed 's/^/depend:/') \
		$$([ -f $(BUILD)/$$f/slot/uki.efi ] && [ -f $(PACKAGES)/uki/$$f/usr/lib/werewolf/uki/slot.efi ] && echo depend:uki-$$f) || exit 1; done
	$(PACKAGE_TOOL) index $(PACKAGES)/$(ARCH) -
	@echo "packages: $(words $(CMDS)) programs and $(words $(PACKAGE_FORMS)) forms in $(PACKAGES)/$(ARCH);" \
		"sign APKINDEX.member, then build/host/package sign"

# cve-tiers reads the NVD key in the recipe, so make never prints it (tools/README.md).
CVE_TIERS_BIN = build/host/cve-tiers
NVD_API_KEY_FILE ?= $(HOME)/.tok/werewolf-nvd
$(CVE_TIERS_BIN): tools/cve-tiers.zig lib/cve.zig lib/update-policy.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe $(call ZIG_MODULES,$<) -femit-bin=$@
cve-tiers: $(CVE_TIERS_BIN) $(LOCK)/kernel.lock.json
	mkdir -p build/tiers && FORM_TOOL=$(FORM_TOOL) release/origins build/tiers/origins
	@kernel=$$(sed -n 's|.*"url": "[^"]*/$(ARCH)/\(linux-werewolf-[^/]*\)\.apk".*|\1|p' $(LOCK)/kernel.lock.json) && \
	NVD_API_KEY=$${NVD_API_KEY:-$$(cat $(NVD_API_KEY_FILE))} \
	$(CVE_TIERS_BIN) "$$kernel" build/tiers/origins build/tiers/nvd build/tiers/in build/tiers/cve-tiers.json

list-forms:
	@$(FORM_TOOL) tree

# CI releases these forms when release-inputs changes; locks pin both runners to the same packages.
RELEASE_FORMS = $(shell $(FORM_ASK) released)
DIST_DIRECT_FORMS = minimal
DIST = dist
RELEASE_SOURCES = Makefile forms boot cmd lib tools release/image.pub release/tiers.pub release/advisories release/packages.pub release/boot.crt
# Releases take werewolf's programs from its repository, so a newly published program is an input.
RELEASE_LOCKS = $(addprefix $(LOCK)/,$(addsuffix -published.lock.json,$(RELEASE_FORMS)) kernel.lock.json boot.lock.json)
# The inputs are a digest of the sources' bytes and exec bits, and every package's URL.
release-inputs:
	rm -f $(RELEASE_LOCKS)
	$(MAKE) --no-print-directory -j $(BOOT_LOCKS)
	for f in $(RELEASE_FORMS); do $(MAKE) --no-print-directory _lock/$$f || exit 1; done
	{ echo "tree $$({ find $(RELEASE_SOURCES) -type f ! -name .DS_Store ! -path '*/__pycache__/*' | LC_ALL=C sort | xargs $(SHA256); \
		find $(RELEASE_SOURCES) -type f -perm -100 ! -path '*/__pycache__/*' | LC_ALL=C sort; } | $(SHA256) | cut -c1-64)"; \
	  sed -n 's|.*"url": "\([^"]*\.apk\)".*|\1|p' $(RELEASE_LOCKS) | LC_ALL=C sort -u; } >$(LOCK)/inputs
	@echo "inputs: $$($(SHA256) < $(LOCK)/inputs | cut -c1-16), $$(grep -c '^https' $(LOCK)/inputs) packages"
# A release's forms come from werewolf's repository, so howl writes its config and lock,
# one form at a time: they share the forms it fetches.
_lock/%: $(HOWL)
	@$(MAKE) --no-print-directory PUBLISHED=1 FORM=$* _howl-lock
_howl-lock: $(HOWL)
	$(HOWL_BUILD) lock
dist:
	for f in $(RELEASE_FORMS); do $(MAKE) --no-print-directory FORM=$$f _dist-form || exit 1; done
# howl build always builds in build/ARCH, without APP, so refuse it.
_dist-form: $(HOWL)
	@[ "$(BUILD)" = build/$(ARCH) ] && [ -z "$(APP)" ] || \
		{ echo "_dist-form: a release builds in build/$(ARCH), without APP (howl build --app)" >&2; exit 1; }
	$(HOWL) build --verbose --with $(FORM_REF) --arch $(ARCH) -o $(DIST) \
		$(if $(DISABLE),--disable=$(DISABLE))

# check-NAME builds what it boots, then runs test/check-NAME; machines share nothing, so -j works.
MACHINE = $(if $(filter aarch64,$(ARCH)),virt,q35)
CONSOLE = $(if $(filter aarch64,$(ARCH)),ttyAMA0,ttyS0)
# QEMU_HOST runs the machines on that Linux host, with KVM, through ssh
# (test/remote-qemu.zig): make QEMU_HOST=gandalf ARCH=x86_64 check-overleaf.
QEMU_HOST ?=
REMOTE_QEMU = $(if $(QEMU_HOST),build/host/remote-qemu)
# Without KVM, HVF or NVMM (some CI runners, FreeBSD), QEMU emulates.
ifneq ($(QEMU_HOST),)
ACCEL = kvm
CPU = host
else ifeq ($(ARCH),$(HOST_ARCH))
ACCEL = $(if $(filter Darwin,$(HOST_OS)),hvf,$(or $(shell test -r /dev/kvm && test -w /dev/kvm && echo kvm),$(if $(wildcard /dev/nvmm),nvmm,tcg)))
CPU = $(if $(filter tcg,$(ACCEL)),max,host)
else
ACCEL = tcg
CPU = max
endif
# Checks lend aarch64 guests EL2 where QEMU can, so posture proves kvm-arm.mode=none holds.
EL2 = $(if $(QEMU_HOST),,$(if $(filter aarch64,$(ARCH)),$(shell echo quit | qemu-system-aarch64 -M virt,virtualization=on -accel $(ACCEL) -cpu $(CPU) -nodefaults -display none -monitor stdio -S >/dev/null 2>&1 && echo ,virtualization=on)))
QEMU = $(if $(QEMU_HOST),$(REMOTE_QEMU) $(QEMU_HOST) )qemu-system-$(ARCH) -M $(MACHINE)$(EL2) -accel $(ACCEL) -cpu $(CPU) -nographic

FORMS := $(patsubst forms/%/form.yaml,%,$(wildcard forms/*/form.yaml))
FORMS_FOR_ARCH := $(shell $(FORM_ASK) for-arch $(ARCH))
NATIVE_TEST_FORMS := $(filter-out bastion,$(filter $(FORMS_FOR_ARCH),$(patsubst forms/%/test/tests.yaml,%,$(wildcard forms/*/test/tests.yaml))))
CHECK = $(BUILD)/check$(if $(VARIANTS),/variants-$(VARIANTS))
NATIVE_WORK = build/native-tests/$(ARCH)$(if $(VARIANTS),/variants-$(VARIANTS))
# A check boots directly: no firmware or TPM, and IPE only under IPE=1.
CHECK_DISABLE = secureboot,tpm$(if $(IPE),,$(comma)ipe)
# 1 GiB keeps forms lean unless check: memory says more; an offline form gets restrict=on; no boot ROM.
CHECK_MEMORY := $(or $(call form_check,memory),1024)
CHECK_OFFLINE := $(if $(filter true,$(call form_check,offline)),$(,)restrict=on)
CHECK_QEMU = $(QEMU) -smp 2 -m $(CHECK_MEMORY) -no-reboot -device virtio-rng-pci \
	-netdev user,id=n0$(CHECK_OFFLINE) -device virtio-net-pci,netdev=n0,romfile=
# A stall panics and ends QEMU, so a hang fails in seconds with the kernel's reason.
CHECK_STALLS = rcupdate.rcu_cpu_stall_timeout=20 sysctl.kernel.panic_on_rcu_stall=1 \
	sysctl.kernel.hung_task_timeout_secs=120 sysctl.kernel.hung_task_panic=1 sysctl.kernel.softlockup_panic=1
CHECK_BOOT = console=$(CONSOLE) $(KERNEL_ARGS) panic=1 werewolf.debug=1 werewolf.check=1 $(CHECK_STALLS) \
	$(if $(DISABLE),werewolf.disable=$(DISABLE))
CHECK_CMDLINE = $(CHECK_BOOT) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3
# The posture failures the console expects: test/posture-known's and the form's weaknesses.
POSTURE_KNOWN_KIND := $(shell awk -v b='*' -v a=$(ARCH) '$$1 == b || $$1 == a { $$1 = ""; k = k $$0 } END { print k }' test/posture-known)
export POSTURE_KNOWN := $(if $(IPE),$(filter-out boot-ipe-enforced,$(POSTURE_KNOWN_KIND)),$(POSTURE_KNOWN_KIND)) $(shell $(FORM_ASK) weaknesses $(FORM_REF))
# A check script's environment (docs/testing.md). Homebrew keeps debugfs off PATH.
SLOTS_UUID = 0e7e1f00-c4ec-4b00-8000-00000000c4ec
DEBUGFS = $(firstword $(shell command -v debugfs) $(wildcard /opt/homebrew/opt/e2fsprogs/sbin/debugfs /usr/local/opt/e2fsprogs/sbin/debugfs))
CHECK_ENV = CHECK=$(CHECK) FORM=$(FORM) OUT=$(OUT) KERNEL=$(BUILD)/vmlinuz BOOT='$(CHECK_BOOT)' \
	CMDLINE='$(CHECK_CMDLINE)' SLOTS=$(SLOTS_UUID) DEBUGFS=$(DEBUGFS) HOWL=$(HOWL) TAR=$(TAR)
# built NAME, COMMAND logs COMMAND to CHECK/NAME-build.log, and shows its tail on failure.
built = mkdir -p $(CHECK) && $(2) >$(CHECK)/$(1)-build.log 2>&1 || \
	{ tail -n 20 $(CHECK)/$(1)-build.log; echo "FAIL   $(1) build: see $(CHECK)/$(1)-build.log"; exit 1; }
# What every check needs, built once, before the forms build in parallel.
_check-shared: $(HOWL) $(TEST_SK)
	@$(call built,shared,$(MAKE) --no-print-directory DISABLE=$(CHECK_DISABLE) FORM=minimal APP= image)

# CI runs each group as a job; SHARD=K/N runs every Nth form from the Kth, in name order.
ifneq ($(SHARD),)
ifeq ($(shell echo '$(SHARD)' | awk -F/ '/^[1-9][0-9]*\/[1-9][0-9]*$$/ && $$1 <= $$2'),)
$(error SHARD=$(SHARD): K/N, the Kth of N, 1 <= K <= N)
endif
endif
shard = $(if $(SHARD),$(shell echo $(sort $(1)) | tr ' ' '\n' | \
	awk -F/ -v s=$(SHARD) 'BEGIN { split(s, a, "/") } (NR - 1) % a[2] == a[1] - 1'),$(1))
# Octal keeps Make's comment parser and awk's escape handling portable.
APP_CHECK_FORMS := $(shell awk '!/^\043/ && NF { print $$1 }' test/app-fixtures)
.PHONY: check-apps $(addprefix check-app-,$(APP_CHECK_FORMS))
check-apps: $(addprefix check-app-,$(call shard,$(APP_CHECK_FORMS)))
# A runtime is for running an application: check-RUNTIME boots its carrier
# with the hello-world test/app-fixtures names, as howl --app lays one.
APP_RUNTIMES := $(shell awk '!/^\043/ && NF { print $$3 ":" $$1 }' test/app-fixtures)
APP_RUNTIME_FORMS := $(foreach r,$(APP_RUNTIMES),$(firstword $(subst :, ,$(r))))
$(foreach r,$(APP_RUNTIMES),$(eval check-$(firstword $(subst :, ,$(r))): check-app-$(lastword $(subst :, ,$(r)))))
check-forms:     $(addprefix check-,$(call shard,$(FORMS_FOR_ARCH))) _test/form-coverage
check-shellfree: $(addprefix check-shellfree-,$(call shard,$(FORMS_FOR_ARCH)))
# check-secureboot runs where firmware boots fast enough: an arm64 host
# with its own accelerator. Emulated arm64 skips it, as it skips the UEFI
# boots below.
check-integrity: check-slot check-verity check-deadman check-posture \
	$(if $(filter aarch64-hvf aarch64-kvm,$(ARCH)-$(ACCEL)),check-secureboot)

# IPE is opt-in; enrolled images update through signed prebuilt bundles.
.PHONY: ipe-kernel check-ipe _check-ipe
# A test kernel, IPE trusting WEREWOLF_IPE_CRT (tools/test-kernel). On macOS,
# QEMU_KERNEL_IMAGE and QEMU_BASE_INITRAMFS name melange's guest.
ipe-kernel:
	@[ -n "$(WEREWOLF_IPE_CRT)" ] || \
		{ echo "ipe-kernel: WEREWOLF_IPE_CRT must name the test IPE certificate" >&2; exit 1; }
	tools/test-kernel $(ARCH) $(WEREWOLF_IPE_CRT) $(IPE_KERNEL)

IPE_PROBE = $(BUILD)/test/ipe-probe-root/usr/lib/werewolf/ipe-probe
$(IPE_PROBE): test/ipe-init.zig lib/ipe.zig lib/dm.zig lib/verity.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe -fPIE -target $(ARCH)-linux-musl --dep dm --dep verity --dep ipe \
		-Mroot=$< -Mdm=lib/dm.zig -Mverity=lib/verity.zig -Mipe=lib/ipe.zig -femit-bin=$@
check-ipe: $(HOWL) $(VERITY_BIN) $(IPE_PROBE) build/host/ipe-boot $(CONSOLE_CHECK)
	@[ "$(IPE)" = 1 ] || { echo "check-ipe: set IPE=1 and the kernel, key and certificate paths" >&2; exit 1; }
	$(MAKE) --no-print-directory DISABLE=$(CHECK_DISABLE) FORM=minimal APP=$(BUILD)/test/ipe-probe-root image
	$(MAKE) --no-print-directory DISABLE=$(CHECK_DISABLE) FORM=minimal APP=$(BUILD)/test/ipe-probe-root _check-ipe
_check-ipe:
	@$(CHECK_ENV) IPE_PROBE=$(IPE_PROBE) VERITY=$(VERITY_BIN) \
		IPE_KEY=$(WEREWOLF_IPE_KEY) IPE_CERT=$(WEREWOLF_IPE_CRT) test/check-ipe $(CHECK_QEMU)
.PHONY: check-image-updater
check-image-updater: $(HOWL)
	@[ "$(IPE)" = 1 ] || { echo "check-image-updater: set IPE=1 and its kernel/key/certificate" >&2; exit 1; }
	@$(CHECK_ENV) ARCH=$(ARCH) IPE_KERNEL=$(IPE_KERNEL) IPE_KEY=$(WEREWOLF_IPE_KEY) \
		IPE_CERT=$(WEREWOLF_IPE_CRT) $(call host_test,test/check-image-updater.zig) \
		$(QEMU) -smp 2 -m 2048 -no-reboot -device virtio-rng-pci

# Continuous EFI update: the new UKI and external root must agree under IPE.
IPE_UPDATE_SECUREBOOT ?= 1
check-image-updater-uki: $(HOWL)
	@[ "$(IPE)" = 1 ] || { echo "check-image-updater-uki: set IPE=1 and its kernel/key/certificate" >&2; exit 1; }
	@$(CHECK_ENV) ARCH=$(ARCH) IPE_UPDATE_BOOT=efi IPE_UPDATE_SECUREBOOT=$(IPE_UPDATE_SECUREBOOT) \
		FIRMWARE=$(UEFI_FIRMWARE) IPE_KERNEL=$(IPE_KERNEL) IPE_KEY=$(WEREWOLF_IPE_KEY) \
		IPE_CERT=$(WEREWOLF_IPE_CRT) $(call host_test,test/check-image-updater.zig) \
		$(QEMU) -smp 2 -m 2048 -device virtio-rng-pci
# The shipping vuln-demo image built in VULN_DEMO_BUILD, probed over forwarded ports.
VULN_DEMO_BUILD ?= build/vuln-demo-check
.PHONY: check-vuln-demo-appliance
check-vuln-demo-appliance: $(HOWL)
	$(call host_test,forms/vuln-demo/test/appliance.zig) --build $(VULN_DEMO_BUILD)
# check-adhoc pulls an OCI image, too slowly on emulated arm64.
check-cloud:     check-metadata check-nodata check-lease check-static check-people check-people-persist $(if $(filter aarch64-tcg,$(ARCH)-$(ACCEL)),,check-adhoc)
check-platform: check-integrity check-cloud check-persist check-syslog
check: check-forms check-shellfree check-platform
	@echo "check: every form, and a slot, passed"

NATIVE_FORMS := $(filter-out $(shell $(FORM_ASK) having native false),$(FORMS_FOR_ARCH))
.PHONY: $(addprefix check-native-,$(NATIVE_FORMS))
check-native: $(addprefix check-native-,$(call shard,$(NATIVE_FORMS)))
$(addprefix check-native-,$(NATIVE_FORMS)): check-native-%: | _check-shared
	@$(call built,$*-native,$(MAKE) --no-print-directory FORM=$* DISABLE=$(CHECK_DISABLE) slot)
	@$(MAKE) --no-print-directory FORM=$* DISABLE=$(CHECK_DISABLE) _check-native
_check-native:
	@test/cage $(FORM) $(OUT)/slot/root.erofs $(CHECK)/$(FORM)-native.log

REPEAT ?= 10
check-one:
	@mkdir -p $(CHECK)
	@test/check-one $(REPEAT) $(CHECK) $(FORM) $(MAKE) --no-print-directory check-$(FORM)

# Native clients are a separate generated form, never a member of /etc/sv.
# Compare their baseline before booting, then reuse one data disk.
.PHONY: check-native-tests _check-native-tests
.PHONY: check-plex-data
check-plex-data:
	$(call host_test,test/check-plex-data.zig)
# native-host runs a native run's host suites (test/native/host.zig) with the
# guest's matchers, and so their regex shim.
NATIVE_HOST = build/host/native-host
$(NATIVE_HOST): test/native-host.zig test/native/match.zig test/native/regex.c $(wildcard test/host/*.zig lib/*.zig)
	$(zig_check)
	t=$@.$$$$ && zig build-exe -O ReleaseSafe -lc test/native/regex.c $(call HOST_ZIG_MODULES,$<) -femit-bin=$$t && mv -f $$t $@
NATIVE_TESTS = build/host/native-tests
$(NATIVE_TESTS): tools/native-tests.zig tools/native-iterate.zig tools/native-compare.zig tools/native-ssh.zig \
	test/native/plan.zig test/native/steps.zig test/native/host.zig lib/form.zig lib/yaml.zig
	$(zig_check)
	t=$@.$$$$ && zig build-exe -O ReleaseSafe $(call ZIG_MODULES,$<) -femit-bin=$$t && mv -f $$t $@
# An example's native tests name its directory, as FORM may.
NATIVE_TEST_EXAMPLES := $(patsubst examples/%/test/tests.yaml,%,$(wildcard examples/*/test/tests.yaml))
native_ref = $(if $(filter $(1),$(NATIVE_TEST_EXAMPLES)),examples/$(1),$(1))
check-native-tests: $(addprefix check-native-tests-,$(NATIVE_TEST_FORMS) $(filter bastion,$(FORMS_FOR_ARCH)))
# native_image NAME,REF[,BASE[,APP]] builds what native_check boots: the
# production image and the native test image (below), and boots neither.
define native_image
	@$(NATIVE_TESTS) describe $(2) $(ARCH) >/dev/null
	@$(call built,$(or $(3),$(1))$(if $(VARIANTS),-variants-$(VARIANTS))$(if $(4),-app)-baseline,$(MAKE) --no-print-directory FORM=$(or $(3),$(2)) APP=$(4) DISABLE=$(CHECK_DISABLE) image)
	PRODUCTION_OUT=$(BUILD)/$(or $(3),$(1))$(if $(VARIANTS),-variants-$(VARIANTS))$(if $(4),-app)$(if $(IPE),-ipe) $(NATIVE_TESTS) prepare $(2) $(ARCH)
	@$(call built,$(1)-native,$(MAKE) --no-print-directory FORM=$(NATIVE_WORK)/$(1)/native-test-$(1) APP=$(4) DISABLE=$(CHECK_DISABLE) image)
endef
# native_check NAME,REF,VARIABLES[,BASE[,APP]] builds the production image of
# BASE, a scenario's stock form, or else of REF, and REF's native test image,
# each with APP's code if given (an -app image), compares them, and boots the
# test image with VARIABLES.
define native_check
$(call native_image,$(1),$(2),$(4),$(5))
$(call native_boot,$(1),$(2),$(3),$(4),$(5))
endef
# Compare and boot an already prepared native image.
define native_boot
	BUILD=$(BUILD) PRODUCTION_OUT=$(BUILD)/$(or $(4),$(1))$(if $(VARIANTS),-variants-$(VARIANTS))$(if $(5),-app)$(if $(IPE),-ipe) \
		TEST_OUT=$(BUILD)/native-test-$(1)$(if $(VARIANTS),-variants-$(VARIANTS))$(if $(5),-app)$(if $(IPE),-ipe) $(NATIVE_TESTS) compare $(2) $(ARCH)
	@$(MAKE) --no-print-directory FORM=$(NATIVE_WORK)/$(1)/native-test-$(1) APP=$(5) DISABLE=$(CHECK_DISABLE) NATIVE_FORM=$(2) $(if $(4),NATIVE_PRODUCTION=$(BUILD)/$(4)$(if $(VARIANTS),-variants-$(VARIANTS))$(if $(5),-app)) $(3) _check-native-tests
endef
# Slot, deadman and the ordinary minimal check share the generated image.
# One prerequisite prepares it once before any of those parallel boots read it.
NATIVE_IMAGES := $(addprefix _check-native-image-,$(NATIVE_TEST_FORMS) $(NATIVE_TEST_EXAMPLES))
.PHONY: $(NATIVE_IMAGES)
$(NATIVE_IMAGES): _check-native-image-%: $(HOWL) $(NATIVE_TESTS)
	$(call native_image,$*,$(call native_ref,$*))
$(addprefix check-native-tests-,$(NATIVE_TEST_FORMS) $(NATIVE_TEST_EXAMPLES)): check-native-tests-%: _check-native-image-%
	$(call native_boot,$*,$(call native_ref,$*))
# A scenario (test/scenarios/NAME, docs/testing-scenarios.md) boots a stock form
# some other way, built from that form's own production image. metadata's boots
# are check-metadata's, and people-persist's check-people-persist's.
SCENARIOS := $(filter-out metadata people-persist,$(patsubst test/scenarios/%/tests.yaml,%,$(wildcard test/scenarios/*/tests.yaml)))
scenario_form = $(shell sed -n 's/^form: *//p' test/scenarios/$(1)/tests.yaml)
.PHONY: check-scenarios $(addprefix check-scenario-,$(SCENARIOS))
check-scenarios: $(addprefix check-scenario-,$(SCENARIOS))
scenario_app = $(shell sed -n 's/^app: *//p' test/scenarios/$(1)/tests.yaml)
scenario_app_dir = $(if $(call scenario_app,$(1)),$(CHECK)/apps/$(call scenario_app,$(1)))
$(addprefix check-scenario-,$(SCENARIOS)): check-scenario-%: $(HOWL) $(NATIVE_TESTS)
	$(if $(call scenario_app,$*),@test/app-fixture $(call scenario_app,$*) $(call scenario_app_dir,$*))
	$(call native_check,scenario-$*,test/scenarios/$*,,$(call scenario_form,$*),$(call scenario_app_dir,$*))
# The platform checks that are scenarios now.
check-lease: check-scenario-lease
check-static: check-scenario-static
check-posture: check-scenario-posture
check-nodata: check-scenario-nodata
# bastion's checks use an ordinary login and one permitted destination.
check-native-tests-bastion: $(HOWL) $(NATIVE_TESTS) $(TEST_SK)
	@test/bastion-form $(CHECK) $(FORM_TOOL) $(CURDIR)/$(TEST_SK)
	$(call native_check,bastion-check,$(CHECK)/bastion-check,NATIVE_SSH_PORT=$(call check_port,24200,bastion) NATIVE_SSH_KEYS=$(CHECK)/bastion-check)
check-bastion: check-native-tests-bastion
# A run's host suites log in through its own forwarded port (tools/native-ssh.zig).
NATIVE_SSH_PORT ?= $(call check_port,24200,$(notdir $(NATIVE_FORM)))
_check-native-tests: $(NATIVE_TESTS) $(NATIVE_HOST) $(CONSOLE_CHECK) $(REMOTE_QEMU) $(TEST_SK) build/host/ssh-su
	@$(CHECK_ENV) PRODUCTION_OUT=$(or $(NATIVE_PRODUCTION),$(BUILD)/$(notdir $(NATIVE_FORM))$(if $(VARIANTS),-variants-$(VARIANTS)))$(if $(IPE),-ipe) \
		NATIVE_SSH_PORT=$(NATIVE_SSH_PORT) NATIVE_SSH_KEYS=$(NATIVE_SSH_KEYS) SSH_SK_PROVIDER=$(CURDIR)/$(TEST_SK) \
		$(NATIVE_TESTS) run $(NATIVE_FORM) $(ARCH) $(CHECK_QEMU)

# A form's check is its native tests.
$(addprefix check-,$(NATIVE_TEST_FORMS)): check-%: check-native-tests-%

# howl test --iterate reuses one SSH VM per form (docs/testing-native.md).
.PHONY: $(addprefix iterate-,$(NATIVE_TEST_FORMS) $(NATIVE_TEST_EXAMPLES))
$(addprefix iterate-,$(NATIVE_TEST_FORMS) $(NATIVE_TEST_EXAMPLES)): iterate-%: $(NATIVE_TESTS)
	@$(NATIVE_TESTS) iterate '$(ITERATE_HOWL)' $(call native_ref,$*) $(ARCH) $(ITERATE) $(PHASE) $(DRIVER)

# An application-carrier form is tested with code in its verified image, as
# well as in its ordinary boot without: scenario app-FORM boots it with
# test/app-fixtures' code, as howl --app supplies it.
$(addprefix check-app-,$(APP_CHECK_FORMS)): check-app-%: check-scenario-app-%
# Each form's ports get their own host ports, so forms boot in parallel.
check_port = $(shell echo $(FORMS) | tr ' ' '\n' | grep -n -x '$(2)' | cut -d: -f1 | awk '{ print $(1) + $$1 }')

# check-adhoc's checks run on howl form's form: prod with nginx's OCI image, whose
# pledge adds sendfile, as nginx needs (docs/applications.md).
check-adhoc: $(HOWL) $(NATIVE_TESTS)
	@mkdir -p $(CHECK) && rm -rf $(BUILD)/adhoc/check-oci
	@$(HOWL) form --build --with prod --services.web.image cgr.dev/chainguard/nginx --services.web.listen tcp/8080 --services.web.write /var/lib/nginx/tmp --services.web.pledge 'stdio rpath wpath inet unix connect listen proc sendfile' -o $(BUILD)/adhoc/check-oci >$(CHECK)/check-oci-form.log 2>&1 || \
		{ tail -n 20 $(CHECK)/check-oci-form.log; echo "FAIL   check-oci form: see $(CHECK)/check-oci-form.log"; exit 1; }
	@mkdir -p $(BUILD)/adhoc/check-oci/test && cp test/generated/oci/tests.yaml $(BUILD)/adhoc/check-oci/test/
	$(call native_check,check-oci,$(BUILD)/adhoc/check-oci)

# Generated forms (test/bastion-form, test/people-form): rules of their own, so check-% takes none of these nor check-shellfree-FORM.
# People uses 22199, below the forms' ports, so check-cloud and check-forms can run together.
# people's checks run on test/people-form's form: prod-ssh with two people.
check-people: $(HOWL) $(NATIVE_TESTS)
	@test/people-form $(CHECK) $(FORM_TOOL)
	$(call native_check,people-check,$(CHECK)/people-check)
$(addprefix check-shellfree-,$(filter-out data-transfer-helper,$(FORMS))): check-shellfree-%: $(HOWL)
	@$(call built,$*-shellfree,$(MAKE) --no-print-directory FORM=$* DISABLE=$(CHECK_DISABLE) image)
	@$(MAKE) --no-print-directory FORM=$* DISABLE=$(CHECK_DISABLE) _check-shellfree
_check-shellfree: $(CONSOLE_CHECK) $(REMOTE_QEMU)
	@$(CHECK_ENV) FORM_REF=$(FORM_REF) FORM_DIR=$(FORM_DIR) CONSOLE=$(wildcard $(FORM_DIR)/test/console) test/check-shellfree $(CHECK_QEMU)

# A Linux check runs as root in private namespaces (test/host/netns.zig), so
# it is a static program for the machine it tests; CHECK_LINK adds libraries.
$(BUILD)/check-%: test/check-%.zig $(wildcard test/unwound/* test/dns/* test/host/*.zig lib/*.zig)
	$(zig_check)
	zig build-exe -O ReleaseSafe -target $(ARCH)-linux-musl $(call HOST_ZIG_MODULES,$<) \
		$(CHECK_LINK) -femit-bin=$@
# The age checks seed and read the store through the age writer's SQLite.
$(BUILD)/check-unwound $(BUILD)/check-unwound-age-authority $(BUILD)/check-unwound-age-mount: \
	CHECK_LINK = -lc build/$(ARCH)/unwound-age-sqlite.o
$(BUILD)/check-unwound $(BUILD)/check-unwound-age-authority $(BUILD)/check-unwound-age-mount: \
	build/$(ARCH)/unwound-age-sqlite.o

# The Linux kernel, private namespaces and a local DNS/TLS/DHCP fixture; no internet.
$(BUILD)/dns-policy: test/dns-policy.zig $(wildcard lib/*.zig)
	$(zig_check)
	zig build-exe -O ReleaseSafe -fPIE -target $(ARCH)-linux-musl $(call ZIG_MODULES,$<) -femit-bin=$@
$(BUILD)/posture-egress: test/posture-egress.zig $(wildcard cmd/posture/*.zig) $(wildcard lib/*.zig)
	$(zig_check)
	zig build-exe -O ReleaseSafe -fPIE -target $(ARCH)-linux-musl --dep posture $(call ZIG_MODULES,$<) \
		--dep cmdline --dep allow --dep service --dep audit --dep ipe --dep tpm --dep uefi-sig --dep sandbox -Mposture=cmd/posture/posture.zig -femit-bin=$@
check-dns: $(call program_bin,fence) $(call program_bin,dhcp-client) $(BUILD)/dns-policy $(BUILD)/posture-egress \
	$(BUILD)/check-dns $(BUILD)/check-lan
	$(DNS_TEST_RUNNER) $(BUILD)/check-dns $(call program_bin,fence) $(BUILD)/dns-policy $(call program_bin,dhcp-client) $(BUILD)/posture-egress
	$(DNS_TEST_RUNNER) $(BUILD)/check-lan $(call program_bin,fence)
# make test reads check-dns's and check-unwound's cases, which need no Linux.
_test/test/check-dns.zig _test/test/unwound/lab.zig: _test/%: ; zig test $(call HOST_ZIG_MODULES,$*)

$(BUILD)/updater-installer-test: cmd/slot-update/installer.zig lib/sandbox.zig lib/seal.zig
	$(zig_check)
	mkdir -p $(dir $@)
	zig test -target $(ARCH)-linux-musl --test-no-exec -femit-bin=$@ \
		--dep sandbox -Mroot=$< --dep seal -Msandbox=lib/sandbox.zig -Mseal=lib/seal.zig
$(BUILD)/updater-coordinator-test: $(wildcard cmd/slot-update/*.zig) $(wildcard lib/*.zig)
	$(zig_check)
	mkdir -p $(dir $@)
	zig test -target $(ARCH)-linux-musl --test-filter coordinator --test-no-exec -femit-bin=$@ $(call ZIG_MODULES,cmd/slot-update/slot-update.zig)
.PHONY: check-updater-installer
check-updater-installer: $(BUILD)/updater-installer-test $(BUILD)/updater-coordinator-test
	$(LINUX_TEST_RUNNER) sh test/check-updater-installer $(OUT)/rootfs.tar $(OUT)/overlay.tar $(BUILD)/updater-installer-test
	$(LINUX_TEST_RUNNER) sh test/check-updater-installer $(OUT)/rootfs.tar $(OUT)/overlay.tar $(BUILD)/updater-coordinator-test

.PHONY: check-mount-broker check-privilege-boundaries
$(BUILD)/mount-broker-test: cmd/mount-broker/mount-broker.zig $(wildcard lib/*.zig) tools/uki.zig
	zig test -target $(ARCH)-linux-musl --test-no-exec -femit-bin=$@ $(call ZIG_MODULES,cmd/mount-broker/mount-broker.zig)
check-mount-broker: $(call program_bin,mount-broker) $(BUILD)/mount-broker-test $(BUILD)/check-mount-broker
	$(LINUX_TEST_RUNNER) $(BUILD)/check-mount-broker $(call program_bin,mount-broker) $(BUILD)/mount-broker-test
check-privilege-boundaries: $(HOWL)
	$(call host_test,test/check-privilege-boundaries.zig) $(HOWL)

BROKER_FUZZ_RUNS ?= 50000
.PHONY: fuzz-broker
fuzz-broker:
	@rm -f test/broker-fuzz/.zig-cache/f/crash
	zig build --build-file test/broker-fuzz/build.zig --fuzz=$(BROKER_FUZZ_RUNS) --summary all
	@test ! -e test/broker-fuzz/.zig-cache/f/crash || { echo 'broker parser fuzz crash'; exit 1; }

check-lan: $(call program_bin,fence) $(BUILD)/check-lan
	$(DNS_TEST_RUNNER) $(BUILD)/check-lan $(call program_bin,fence)

# check-unwound runs the real fence and unwound against a fixture resolver
# in private namespaces, as root, on Linux (cmd/unwound/unwound.8.md).
.PHONY: check-unwound check-unwound-age check-unwound-age-live check-unwound-dnssec check-unwound-dnssec-mox check-unwound-tunnels check-unwound-caddy fuzz-unwound

# The age writer is statically linked with a hash-pinned SQLite amalgamation.
# This host test exercises the real schema before the writer joins unwound.
UNWOUND_SQLITE = out/third-party/sqlite-3540100
$(UNWOUND_SQLITE)/sqlite3.c: tools/checkout-unwound-sqlite.zig
	$(zig_check)
	zig run -O ReleaseSafe $<
build/$(ARCH)/unwound-age-sqlite.o: $(UNWOUND_SQLITE)/sqlite3.c
	@mkdir -p $(dir $@)
	zig cc -target $(ARCH)-linux-musl -O2 -fPIC -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_DQS=0 -DSQLITE_THREADSAFE=0 -c $< -o $@
# Both embed the age schema and the pinned PSL and RDAP data.
$(call program_bin,unwound) $(call program_bin,unwound-age): cmd/unwound/age.sql $(wildcard cmd/unwound/data/*)
$(call program_bin,unwound-age): cmd/unwound/age_authority.zig $(wildcard cmd/unwound/*.zig) $(wildcard lib/*.zig) build/$(ARCH)/unwound-age-sqlite.o $(PROGRAM_FLAGS_STAMP)
	$(zig_check)
	@mkdir -p $(dir $@)
	zig build-exe $(PROGRAM_FLAGS) -target $(ARCH)-linux-musl -lc $(call ZIG_MODULES,cmd/unwound/age_authority.zig) build/$(ARCH)/unwound-age-sqlite.o -femit-bin=$@
build/host/unwound-sqlite.o: $(UNWOUND_SQLITE)/sqlite3.c
	@mkdir -p $(dir $@)
	zig cc -O2 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_DQS=0 -DSQLITE_THREADSAFE=0 -c $< -o $@
.PHONY: check-unwound-age-store
check-unwound-age-store: build/host/unwound-sqlite.o
	zig test -lc cmd/unwound/age_db.zig $<
	zig test -lc cmd/unwound/age_evidence.zig $<
	zig run -O ReleaseSafe -lc $(call HOST_ZIG_MODULES,test/check-unwound-age-db.zig) $< -- cmd/unwound/age.sql

_test/cmd/unwound/age_evidence.zig: build/host/unwound-sqlite.o
	zig test -lc cmd/unwound/age_evidence.zig $<

_test/cmd/unwound-age/unwound-age.zig: build/host/unwound-sqlite.o
	zig test -lc $(call ZIG_MODULES,cmd/unwound/age_authority.zig) $<

.PHONY: check-unwound-age-mount
check-unwound-age-mount: $(BUILD)/check-unwound-age-mount
	$(DNS_TEST_RUNNER) $(BUILD)/check-unwound-age-mount

.PHONY: check-unwound-age-authority
check-unwound-age-authority: $(call program_bin,unwound-age) $(BUILD)/check-unwound-age-authority
	$(DNS_TEST_RUNNER) $(BUILD)/check-unwound-age-authority $(call program_bin,unwound-age)

UNWOUND_CHECK = $(call program_bin,fence) $(call program_bin,unwound)
check-unwound: $(UNWOUND_CHECK) $(BUILD)/check-unwound
	$(DNS_TEST_RUNNER) $(BUILD)/check-unwound $(UNWOUND_CHECK)
check-unwound-age: $(UNWOUND_CHECK) $(call program_bin,unwound-age) $(BUILD)/check-unwound
	$(DNS_TEST_RUNNER) $(BUILD)/check-unwound $(UNWOUND_CHECK) $(call program_bin,unwound-age)
check-unwound-age-live: $(UNWOUND_CHECK) $(call program_bin,unwound-age) $(BUILD)/check-unwound
	$(DNS_TEST_RUNNER) $(BUILD)/check-unwound --live $(UNWOUND_CHECK) $(call program_bin,unwound-age)
# Lab check with a freshly signed local TLSA zone and a deliberately invalid
# signature. Requires named, unbound and BIND's dnssec tools in unwound-lab.
check-unwound-dnssec: $(UNWOUND_CHECK) $(BUILD)/check-unwound-dnssec
	$(DNS_TEST_RUNNER) $(BUILD)/check-unwound-dnssec $(UNWOUND_CHECK)
MOX_DNSSEC_BIN ?= $(BUILD)/mox/melange/usr/bin/mox
check-unwound-dnssec-mox: $(UNWOUND_CHECK) $(BUILD)/check-unwound-dnssec
	@test -x "$(MOX_DNSSEC_BIN)" || { echo "build Mox or set MOX_DNSSEC_BIN" >&2; exit 1; }
	$(DNS_TEST_RUNNER) $(BUILD)/check-unwound-dnssec $(UNWOUND_CHECK) $(MOX_DNSSEC_BIN)
# Optional lab check: real iodine, dns2tcp and shellack clients against their
# local servers, first directly and then through the screened resolver.
SHELLACK ?= $(HOME)/src/shellack
check-unwound-tunnels: $(UNWOUND_CHECK) $(BUILD)/check-unwound-tunnels
	@test -f "$(SHELLACK)/shellack.sh" || { echo "set SHELLACK to a shellack checkout" >&2; exit 1; }
	cd "$(SHELLACK)" && GOOS=linux GOARCH=$(if $(filter aarch64,$(ARCH)),arm64,amd64) \
		go build -o "$(CURDIR)/$(BUILD)/shellack-server" ./cmd/server
	$(DNS_TEST_RUNNER) $(BUILD)/check-unwound-tunnels $(UNWOUND_CHECK) \
		$(BUILD)/shellack-server "$(SHELLACK)/shellack.sh"
# Lab check: Caddy's ACME lookup under a form's composed policy, as
# CADDY_POLICY=build/ARCH/caddy/.../net CADDY_DOMAIN=example.com.
check-unwound-caddy: $(UNWOUND_CHECK) $(BUILD)/check-unwound-caddy
	@test -f "$(CADDY_POLICY)" && test -n "$(CADDY_DOMAIN)" || { echo "set CADDY_POLICY and CADDY_DOMAIN" >&2; exit 1; }
	$(DNS_TEST_RUNNER) $(BUILD)/check-unwound-caddy $(UNWOUND_CHECK) $(CADDY_POLICY) $(CADDY_DOMAIN)
UNWOUND_FUZZ_RUNS ?= 1000000
fuzz-unwound:
	@# zig build --fuzz succeeds even when a target crashes; the input it
	@# saves is how a crash shows.
	@for target in 'fuzz queries' 'fuzz responses' 'fuzz policy' 'fuzz cache'; do \
		rm -f cmd/unwound/.zig-cache/f/crash; \
		zig build --build-file cmd/unwound/build.zig test -Dfilter="$$target" \
			--fuzz=$(UNWOUND_FUZZ_RUNS) --summary all || exit; \
		if [ -e cmd/unwound/.zig-cache/f/crash ]; then \
			echo "fuzz-unwound: $$target crashed; input in cmd/unwound/.zig-cache/f/crash" >&2; \
			exit 1; \
		fi; \
	done

# check-metadata boots metadata's native test image behind a stand-in metadata
# server, or prod's own image for a machine that must take nothing (test/cloud-boot).
check-metadata: $(HOWL) $(NATIVE_TESTS) $(CONSOLE_CHECK) build/host/metadata
	$(call native_image,scenario-metadata,test/scenarios/metadata,prod)
	@$(MAKE) --no-print-directory FORM=$(NATIVE_WORK)/scenario-metadata/native-test-scenario-metadata DISABLE=$(CHECK_DISABLE) _check-metadata
# check-verity boots minimal's own image, its root changed after the build.
check-verity: $(HOWL) $(CONSOLE_CHECK)
	@$(call built,minimal-baseline,$(MAKE) --no-print-directory FORM=minimal DISABLE=$(CHECK_DISABLE) image)
	@$(MAKE) --no-print-directory FORM=minimal DISABLE=$(CHECK_DISABLE) _check-verity
# check-slot boots minimal's native test image from a slot (test/check-slot).
check-slot: _check-native-image-minimal $(CONSOLE_CHECK)
	@$(MAKE) --no-print-directory FORM=$(NATIVE_WORK)/minimal/native-test-minimal DISABLE=$(CHECK_DISABLE) _check-slot
# check-deadman boots minimal's native test image, from which alone stage0
# takes a shorter deadman.
check-deadman: _check-native-image-minimal $(CONSOLE_CHECK)
	@$(MAKE) --no-print-directory FORM=$(NATIVE_WORK)/minimal/native-test-minimal DISABLE=$(CHECK_DISABLE) _check-deadman
check-secureboot: $(HOWL)
	@rm -f $(CHECK)/sb.key $(CHECK)/sb.crt
	@mkdir -p $(CHECK)
	openssl req -newkey rsa:2048 -nodes -keyout $(CHECK)/sb.key -x509 -new \
		-subj /CN=werewolf-secureboot-check -days 30 -out $(CHECK)/sb.crt 2>/dev/null
	@$(MAKE) --no-print-directory FORM=prod ARCH=$(ARCH) _check-secureboot
check-lima-secureboot: check-secureboot
	$(call host_test,test/check-lima-secureboot.zig) $(CHECK)/secureboot/release/prod-$(ARCH)-disk.qcow2 \
		$(CHECK)/secureboot/enrolled $(CHECK)/lima-secureboot
# check-firecracker builds for x86_64 here and boots on FIRECRACKER_HOST
# (default galadriel) through a cross-compiled howl, so the host needs no
# toolchain (docs/testing.md). The form is sshd relaxed to take a key file,
# which the host has, as a posture weakness it declares.
FIRECRACKER_HOST ?= galadriel
FC_FORM = build/adhoc/check-fc
POSTURE_KNOWN_X64 := $(shell awk -v b='*' -v a=x86_64 '$$1 == b || $$1 == a { $$1 = ""; k = k $$0 } END { print k }' test/posture-known) \
	network-no-login programs-no-downloaders programs-no-interpreters programs-no-shell network-ssh-security-keys
check-firecracker: build/host/cloud-console | _check-shared
	@rm -rf $(FC_FORM) && $(HOWL) form --build --with sshd --sshd.pubkey-accepted-algorithms ssh-ed25519 -o $(FC_FORM)/
	@$(call built,firecracker,$(MAKE) --no-print-directory ARCH=x86_64 FORM=$(FC_FORM) DISABLE=$(CHECK_DISABLE) programs disk)
	@mkdir -p $(CHECK) build/x86_64/tools
	zig build-exe -O ReleaseSafe -target x86_64-linux-musl $(call ZIG_MODULES,cmd/howl/howl.zig) -femit-bin=build/x86_64/tools/howl
	zig build-exe -O ReleaseSafe -target x86_64-linux-musl $(FORM_TOOL_MODULES) -femit-bin=build/x86_64/tools/form
	zig build-exe -O ReleaseSafe -target x86_64-linux-musl --dep verity -Mroot=tools/verity.zig -Mverity=lib/verity.zig -femit-bin=build/x86_64/tools/verity
	@$(CHECK_ENV) FIRECRACKER_HOST=$(FIRECRACKER_HOST) FORM_DIR=$(FC_FORM) \
		POSTURE_KNOWN='$(POSTURE_KNOWN_X64)' test/check-firecracker
_check-verity _check-slot _check-deadman: $(HOWL)
	@$(CHECK_ENV) ARCH=$(ARCH) test/$(@:_%=%) $(CHECK_QEMU)
_check-secureboot: $(HOWL)
	@$(CHECK_ENV) ARCH=$(ARCH) SECUREBOOT_DIR=$(SECUREBOOT_DIR) \
		BOOT_KEY=$(CHECK)/sb.key BOOT_CRT=$(CHECK)/sb.crt $(call host_test,test/check-secureboot.zig) \
		qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -nographic -smp 2 \
		-m $(CHECK_MEMORY) -no-reboot -device virtio-rng-pci
_check-metadata: build/host/metadata
	@$(CHECK_ENV) ARCH=$(ARCH) PRODUCTION_OUT=$(BUILD)/prod$(if $(IPE),-ipe) FIRMWARE=$(if $(filter aarch64,$(ARCH)),$(UEFI_FIRMWARE)) \
		test/check-metadata $(QEMU) -smp 2 -m 1024 -no-reboot -device virtio-rng-pci

# check-people-persist boots its scenario's native test image again and again
# on one disk (test/check-people-persist.zig).
.PHONY: check-people-persist _check-people-persist
check-people-persist: $(HOWL) $(NATIVE_TESTS) $(CONSOLE_CHECK)
	$(call native_image,scenario-people-persist,test/scenarios/people-persist,prod)
	@$(MAKE) --no-print-directory FORM=$(NATIVE_WORK)/scenario-people-persist/native-test-scenario-people-persist DISABLE=$(CHECK_DISABLE) _check-people-persist
_check-people-persist:
	@$(CHECK_ENV) ARCH=$(ARCH) $(call host_test,test/check-people-persist.zig) $(CHECK_QEMU)

# Each run copies x86_64's UEFI variables, sparing the template; splash-time=0 skips edk2's 5 s wait.
UEFI_FIRMWARE = $(firstword $(wildcard $(if $(filter aarch64,$(ARCH)), \
	/opt/homebrew/share/qemu/edk2-aarch64-code.fd /usr/local/share/qemu/edk2-aarch64-code.fd \
	/usr/share/qemu/edk2-aarch64-code.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd, \
	/opt/homebrew/share/qemu/edk2-x86_64-code.fd /usr/local/share/qemu/edk2-x86_64-code.fd \
	/usr/share/qemu/edk2-x86_64-code.fd /usr/share/ovmf/OVMF.fd \
	/usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd \
	/usr/share/edk2/x64/OVMF_CODE.4m.fd)))
UEFI_VARS = $(firstword $(wildcard /opt/homebrew/share/qemu/edk2-i386-vars.fd /usr/local/share/qemu/edk2-i386-vars.fd \
	/usr/share/qemu/edk2-i386-vars.fd /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd \
	/usr/share/edk2/x64/OVMF_VARS.4m.fd))
UEFI_VARS_COPY = $(CHECK)/ovmf-vars.fd
UEFI_FLAGS = -boot menu=on,splash-time=0 $(if $(filter aarch64,$(ARCH)),-bios $(UEFI_FIRMWARE),\
	-drive if=pflash,format=raw,unit=0,readonly=on,file=$(UEFI_FIRMWARE) \
	-drive if=pflash,format=raw,unit=1,file=$(UEFI_VARS_COPY))
UEFI_ENV = CHECK=$(CHECK) FORM=$(FORM) ARCH=$(ARCH) FIRMWARE=$(UEFI_FIRMWARE) \
	UEFI_VARS=$(UEFI_VARS) UEFI_VARS_COPY=$(UEFI_VARS_COPY)

# Emulated arm64 skips the UEFI boots: edk2 never reaches systemd-boot in time.
check-dist:
ifeq ($(ARCH)-$(ACCEL),aarch64-tcg)
	@echo "skip   dist               emulated arm64 (no EL2): UEFI boot too slow; x86_64 covers it"
else
	@failed=0; for f in $(filter-out $(DIST_DIRECT_FORMS),$(RELEASE_FORMS)); do \
		$(MAKE) --no-print-directory FORM=$$f _check-dist || failed=1; done; exit $$failed
endif
_check-dist: $(CONSOLE_CHECK)
	@$(UEFI_ENV) DIST=$(DIST) HOWL=$(HOWL) FORM_REF=$(FORM_REF) FORM_DIR=$(FORM_DIR) \
		CONSOLE=$(wildcard $(FORM_DIR)/test/console) \
		POSTURE_KNOWN="$(filter-out boot-ipe-enforced,$(POSTURE_KNOWN))" \
		$(call host_test,test/check-dist.zig) qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) \
		-nographic -smp 2 -m $(or $(call form_check,memory),2048) -snapshot -no-reboot $(UEFI_FLAGS) -device virtio-rng-pci \
		-netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0,romfile=

# check-persist boots the demo's own disk (test/check-persist) without EL2
# (edk2 under HVF never boots) and offline; CI sets PERSIST_AFTER=.
PERSIST_ARGS = console=$(CONSOLE) werewolf.debug=1 werewolf.check=1 $(CHECK_STALLS)
PERSIST_AFTER ?= check-demo
check-persist: $(HOWL) $(CONSOLE_CHECK) | $(PERSIST_AFTER)
ifeq ($(ARCH)-$(ACCEL),aarch64-tcg)
	@echo "skip   persist            emulated arm64 (no EL2): UEFI boot too slow; x86_64 covers it"
else
	@[ -n "$(UEFI_FIRMWARE)" ] || { echo "FAIL   persist            no UEFI firmware for $(ARCH) (edk2 or OVMF)"; exit 1; }
	@[ "$(ARCH)" = aarch64 ] || [ -n "$(UEFI_VARS)" ] || { echo "FAIL   persist            no UEFI variables template for $(ARCH) (edk2-i386-vars.fd or OVMF_VARS.fd)"; exit 1; }
	@rm -f $(CHECK)/persist.img
	@$(call built,persist,$(MAKE) --no-print-directory FORM=demo DISABLE=$(CHECK_DISABLE) disk DISK=$(CHECK)/persist.img DISK_MIB=2048 DISK_ARGS="$(PERSIST_ARGS)")
	@$(MAKE) --no-print-directory FORM=demo DISABLE=$(CHECK_DISABLE) _check-persist
endif
_check-persist:
	@$(UEFI_ENV) test/check-persist qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -nographic \
		-smp 2 -m 2048 -no-reboot -device virtio-rng-pci $(UEFI_FLAGS) \
		-netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0,romfile= \
		-drive file=$(CHECK)/persist.img,format=raw,if=virtio

check-gcp-metadata: $(HOWL) $(TEST_SK)
	@$(call host_test,test/gcp-metadata.zig) $(HOWL) $(CURDIR)/$(TEST_SK) $(ARCH)

check-gcp check-aws check-azure: check-%:
	@$(MAKE) --no-print-directory FORM=prod-ssh CLOUD=$* _check-cloud

# Exercise checkout builds on every cloud; werewolf publishes no cloud downloads yet.
.PHONY: check-prod-ssh-clouds
check-prod-ssh-clouds:
	@failed=0; for cloud in gcp aws azure; do \
		$(MAKE) --no-print-directory check-$$cloud CLOUD_MODE=build || failed=1; \
	done; exit $$failed

# Explicit live lifecycle tests; cloud credentials are never required by PR CI.
.PHONY: check-ab-qemu check-ab-lima-qemu check-ab-lima-vz check-ab-aws check-ab-gcp check-ab-azure check-ab-bhyve check-ab-firecracker check-ab-proxmox check-bhyve-secureboot _check-provider-ab
check-ab-qemu check-ab-lima-qemu check-ab-lima-vz check-ab-aws check-ab-gcp check-ab-azure check-ab-bhyve check-ab-firecracker check-ab-proxmox: check-ab-%:
	@$(MAKE) --no-print-directory AB_PROVIDER=$* _check-provider-ab
check-bhyve-secureboot: $(HOWL)
	@test -n "$(AB_FIXTURE)" || { echo 'set AB_FIXTURE to a signed x86_64 fixture.json' >&2; exit 1; }
	@CHECK=$(CHECK) $(call host_test,test/check-bhyve-secureboot.zig) $(HOWL) $(AB_FIXTURE)
_check-provider-ab: $(HOWL)
	@CHECK=$(CHECK) IPE_KERNEL=$(IPE_KERNEL) IPE_KEY=$(WEREWOLF_IPE_KEY) IPE_CERT=$(WEREWOLF_IPE_CRT) \
		$(call host_test,test/check-provider-ab.zig) $(HOWL) $(AB_PROVIDER) $(ARCH)
# ARGS is check-bhyve-lifecycle's HOST ARCH DISK.zst KEY [tap|slirp] [SECONDS] (docs/testing-live.md),
# and build-traced-stub's --output FILE [--helper NAME] [--sync-arm-cache] [--firmware-kernel-loader].
.PHONY: check-bhyve-lifecycle build-traced-stub
check-bhyve-lifecycle build-traced-stub:
	$(call host_test,test/$@.zig) $(ARGS)

build/x86_64/tools/howl-linux: cmd/howl/howl.zig $(HOWL) $(wildcard cmd/howl/*.zig) files.zig
	@mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -target x86_64-linux-musl $(call ZIG_MODULES,$<) -femit-bin=$@

.PHONY: check-firecracker-protected
check-firecracker-protected: $(HOWL) build/host/check-hypervisor-isolation
	HOWL=$(HOWL) sh test/check-firecracker-protected

.PHONY: check-bhyve-protected
check-bhyve-protected: $(HOWL) build/host/check-hypervisor-isolation
	HOWL=$(HOWL) sh test/check-bhyve-protected
build/x86_64/tools/howl-freebsd build/aarch64/tools/howl-freebsd: build/%/tools/howl-freebsd: cmd/howl/howl.zig $(HOWL) $(wildcard cmd/howl/*.zig) files.zig
	@mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -target $*-freebsd $(call ZIG_MODULES,$<) -femit-bin=$@

# A form README's fences (docs/design/implemented/examples.md). Not part of make check:
# the console checks stay, and a README with no Getting Started is skipped.
example-%: $(HOWL)
	@test/example local $*
examples examples-gcp: $(HOWL)
examples:
	@status=0; for f in $(call shard,$(FORMS)); do test/example local $$f || status=1; done; exit $$status
examples-gcp:
	@status=0; for f in $(call shard,$(FORMS)); do test/example gcp $$f || status=1; done; exit $$status
_check-cloud: $(HOWL) $(TEST_SK) build/host/cloud-console build/host/azure-security build/host/cloud-posture
	@mkdir -p $(CHECK)
	@runner=$$(mktemp '$(CHECK)/cloud-$(CLOUD).XXXXXXXX') && \
		trap 'rm -f "$$runner"' EXIT && cp test/cloud "$$runner" && chmod 700 "$$runner" && \
		HOWL=$(HOWL) SSH_SK_PROVIDER=$(CURDIR)/$(TEST_SK) CLOUD_MODE=$(or $(CLOUD_MODE),build) \
		POSTURE_KNOWN='$(filter-out ?boot-secure-boot boot-rollback-protected boot-ipe-enforced,$(POSTURE_KNOWN))' \
		"$$runner" $(CLOUD) $(FORM) $(ARCH)
check-compose: slot
	@OUT=$(OUT) FORM=$(FORM) ARCH=$(ARCH) \
		FORM_TOOL=$(abspath $(FORM_TOOL)) TAR=$(TAR) test/check-compose

# EROFS_OPTS must match the options lib/image.zig gives mkfs.erofs.
EROFS_OPTS = -b 4096 -zzstd,level=5 -C65536 -Efragments
check-updater check-updater-staged check-updater-published: | _check-shared
	@$(MAKE) --no-print-directory DISABLE=$(CHECK_DISABLE) $(if $(filter %-staged,$@),STAGED=1) $(if $(filter %-published,$@),PUBLISHED=1 FORM=test/published-form,FORM=prod) _check-updater
_check-updater: $(VERITY_BIN)
	@mkdir -p $(CHECK)/update-$(FORM) && $(MAKE) --no-print-directory slot >$(CHECK)/update-$(FORM)/build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/update-$(FORM)/build.log; echo "FAIL   update build: see $(CHECK)/update-$(FORM)/build.log"; exit 1; }
	@CHECK=$(CHECK) FORM=$(FORM) OUT=$(OUT) TAR=$(TAR) DEBUGFS=$(DEBUGFS) SLOTS=$(SLOTS_UUID) PRUNE='$(call form_list,prune)' \
		EROFS_OPTS='$(EROFS_OPTS)' VERITY=$(VERITY_BIN) CONSOLE=$(CONSOLE) STAGED='$(STAGED)' PUBLISHED='$(PUBLISHED)' \
		test/check-updater $(QEMU) -smp 2 -m 2048 -no-reboot -device virtio-rng-pci -netdev user,id=n0 \
		-device virtio-net-pci,netdev=n0,romfile=

ci:
	test/lima-ci

# Signed UKIs travel with the exact root they seal, not a locally composed root.
.PHONY: check-updater-uki check-image-updater-uki
check-updater-uki: check-image-updater-uki
# clean keeps the locks, so the next build is the same as the last.
clean:
	rm -rf $(filter-out $(LOCK),$(wildcard build/*))
# help prints this file's opening comment, up to its first empty line.
help:
	@sed -n '2,/^$$/s/^# \{0,1\}//p' Makefile

# BEGIN: lint-install .
LINTERS := yamllint-lint zig-lint doc-lint man-lint code-lint
FIXERS := zig-fix doc-fix
.PHONY: lint _lint fix $(LINTERS) $(FIXERS)
lint: _lint
_lint:
	@$(MAKE) --no-print-directory -k -j4 $(LINTERS)
fix:
	@status=0; for t in $(FIXERS); do $(MAKE) $$t || status=1; done; exit $$status

# What builds, tests and releases werewolf is Zig (CONTRIBUTING.md). Python and Go
# are only what a form runs; WORKLOAD_CODE names them. code-lint refuses any
# other Python or Go file, Python script, or Python a build step writes inline.
# Each needs its language: the example apps; onnx's checks drive Python's own
# onnxruntime and ctypes, which nothing but Python can; opencanary's and
# paperless's sitecustomize patch those apps' interpreters as they start;
# webshell's launcher loads its packaged pure Python framework with the
# hardened interpreter; and
# vuln-console is the vuln-demo form's Go helper.
WORKLOAD_CODE = examples/go/main.go forms/python-example/rootfs/usr/lib/app/main.py \
	forms/webshell-example/rootfs/usr/lib/app/webshell.py forms/onnx/rootfs/usr/lib/onnx/check.py \
	forms/webshell-example/rootfs/usr/lib/app/serve.py \
	forms/onnx/rootfs/usr/lib/libffi-static/check.py \
	forms/opencanary/rootfs/oci/opencanary/opencanary/sitecustomize.py \
	forms/paperless/rootfs/usr/lib/paperless/lib/python3.13/site-packages/sitecustomize.py \
	$(wildcard forms/vuln-demo/melange/*.go) forms/vuln-demo/melange/go.mod forms/vuln-demo/melange/go.sum
code-lint:
	@cd $(LINT_ROOT) && bad=$$( { git ls-files -co --exclude-standard -- '*.py' '*.pyc' '*.go' '*go.mod' '*go.sum'; \
		git grep --untracked -lE '^#!.*python' -- ':!docs'; } | sort -u | while read -r f; do \
		[ -e "$$f" ] && case " $(WORKLOAD_CODE) " in (*" $$f "*) ;; (*) echo "$$f" ;; esac; done; \
		git grep --untracked -nE 'python[0-9.]* +(-[A-Za-z]+ +)*(-c|-)( |$$)|python[0-9.]* +[a-z]+/' -- \
		Makefile .github tools test release boot ':!*.md'); \
	[ -z "$$bad" ] || { echo 'code-lint: first-party Python or Go; write it in Zig (CONTRIBUTING.md):' >&2; \
		printf '%s\n' "$$bad" | sed 's/^/  /' >&2; exit 1; }
LINT_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

YAMLLINT_VERSION ?= 1.37.1
YAMLLINT_ROOT := $(LINT_ROOT)/out/linters/yamllint-$(YAMLLINT_VERSION)
YAMLLINT_BIN := $(YAMLLINT_ROOT)/dist/bin/yamllint
$(YAMLLINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/yamllint-*
	curl -sSfL https://github.com/adrienverge/yamllint/archive/refs/tags/v$(YAMLLINT_VERSION).tar.gz | tar -C $(LINT_ROOT)/out/linters -zxf -
	cd $(YAMLLINT_ROOT) && pip3 install --target dist . || pip install --target dist .
yamllint-lint: $(YAMLLINT_BIN)
	PYTHONPATH=$(YAMLLINT_ROOT)/dist $(YAMLLINT_BIN) $(YAML_SOURCES)
# END: lint-install .

# zigfix --check uses Zig's AstGen, including functions nothing calls.
# Prune generated trees before descending: image roots contain millions of files.
source_find = find . -type d \( -name .git -o -path './build' -o -path './out' -o -path './.zig-cache' -o -path './.claude' $(1) \) -prune -o -type f $(2) -print
ZIG_SOURCES := $(shell $(call source_find,,-name '*.zig'))
YAML_SOURCES := $(shell $(call source_find,-o -path './dist' -o -path './config',\( -name '*.yaml' -o -name '*.yml' -o -name '.yamllint' \)))
ZIGFIX := $(LINT_ROOT)/out/tools/zigfix
$(ZIGFIX): tools/zigfix.zig
	mkdir -p $(dir $@)
	zig build-exe -O Debug -femit-bin=$@ tools/zigfix.zig
# The sha256s are those of ziglint's checksums.txt when it was pinned.
ZIGLINT_VERSION ?= 0.5.3
ZIGLINT_PLATFORM := $(subst arm64,aarch64,$(shell uname -m))-$(if $(filter Darwin,$(HOST_OS)),macos,linux)
ZIGLINT_SHA256_aarch64-macos := 5fae98d6052b42ac07a8cb211036a633ebcd90db0ad40ebbadfbec96195bff13
ZIGLINT_SHA256_aarch64-linux := 110203d2e2332bfd5e2972f00cf731a215cf953e3eb4e14a17d8f7f80eeab26d
ZIGLINT_SHA256_x86_64-linux := 7560bf5ad36170ae1560505a5e273c83376534feccad23a9f7be716f94853539
ZIGLINT_ROOT := $(LINT_ROOT)/out/linters/ziglint-$(ZIGLINT_VERSION)
ZIGLINT_BIN := $(ZIGLINT_ROOT)/ziglint
$(ZIGLINT_BIN):
	@[ -n "$(ZIGLINT_SHA256_$(ZIGLINT_PLATFORM))" ] || { echo "no ziglint $(ZIGLINT_VERSION) for $(ZIGLINT_PLATFORM)" >&2; exit 1; }
	mkdir -p $(ZIGLINT_ROOT)
	curl -sSfL -o $(ZIGLINT_ROOT)/ziglint.tar.gz https://github.com/rockorager/ziglint/releases/download/v$(ZIGLINT_VERSION)/ziglint-$(ZIGLINT_PLATFORM).tar.gz
	echo "$(ZIGLINT_SHA256_$(ZIGLINT_PLATFORM))  $(ZIGLINT_ROOT)/ziglint.tar.gz" | shasum -a 256 -c -
	tar -C $(ZIGLINT_ROOT) -xzf $(ZIGLINT_ROOT)/ziglint.tar.gz ziglint
	rm $(ZIGLINT_ROOT)/ziglint.tar.gz
zig-lint: $(ZIGFIX) $(ZIGLINT_BIN)
	$(ZIGFIX) --check $(ZIG_SOURCES)
	$(ZIGLINT_BIN) $(ZIG_SOURCES)
zig-fix: $(ZIGFIX)
	$(ZIGFIX) $(ZIG_SOURCES)

DOC_SOURCES := $(shell $(call source_find,-o -path './dist',-name '*.md'))
man-lint: $(MAN_PAGES)
	mandoc -Tlint -Wwarning $(MAN_PAGES)
DOC_CHECK := $(LINT_ROOT)/out/tools/doc-check
$(DOC_CHECK): tools/doc-check.zig
	mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -femit-bin=$@ tools/doc-check.zig
doc-lint: $(DOC_CHECK)
	$(DOC_CHECK) $(DOC_SOURCES)
	@test/example selftest
	@for f in $(FORMS); do test/example check $$f >/dev/null || exit 1; done
doc-fix: $(DOC_CHECK)
	$(DOC_CHECK) --fix $(DOC_SOURCES)

# Public fixture storage tests; source image and verity parameters must match.
DATA_TRANSFER_IMAGE ?= build/$(ARCH)/postgresql/slot/root.erofs
DATA_TRANSFER_VERITY ?= build/$(ARCH)/postgresql/verity/verity
DATA_TRANSFER_KERNEL ?= build/$(ARCH)/postgresql/slot/vmlinuz
.PHONY: check-data-transfer-helper
.PHONY: check-data-transfer
.PHONY: check-data-export
check-data-export: check-data-transfer
# This private runtime replaces init for one networkless storage operation.
# Its real boot, confinement and archive checks are the dedicated helper suite.
.PHONY: check-shellfree-data-transfer-helper
check-shellfree-data-transfer-helper: check-data-transfer-helper

build/host/data-app-check: cmd/howl/data-app-check.zig $(wildcard cmd/howl/*.zig) $(wildcard lib/data-transfer*.zig)
	@mkdir -p $(dir $@)
	t=$@.$$$$ && zig build-exe -O ReleaseSafe $(call HOST_ZIG_MODULES,$<) -femit-bin=$$t && mv -f $$t $@

check-data-transfer: check-data-transfer-helper build/host/data-app-check build/$(ARCH)/transfer-control
	build/host/data-app-check $(HOWL) build/$(ARCH)/transfer-control
build/host/data-transfer-check: cmd/howl/data-transfer-check.zig cmd/howl/data-helper.zig $(wildcard lib/data-transfer*.zig)
	@mkdir -p $(dir $@)
	t=$@.$$$$ && zig build-exe -O ReleaseSafe $(call ZIG_MODULES,$<) -femit-bin=$$t && mv -f $$t $@

build/$(ARCH)/transfer-control: test/transfer-control.zig
	@mkdir -p $(dir $@)
	zig build-exe $(PROGRAM_FLAGS) -target $(ARCH)-linux-musl $< -femit-bin=$@
build/$(ARCH)/transfer-encrypted/init: test/transfer-encrypted-init.zig $(wildcard lib/data-transfer*.zig)
	@mkdir -p $(dir $@)
	zig build-exe $(PROGRAM_FLAGS) -target $(ARCH)-linux-musl $(call ZIG_MODULES,$<) -femit-bin=$@
check-data-transfer-helper: $(HOWL) build/host/data-transfer-check build/$(ARCH)/transfer-boundaries.cpio build/$(ARCH)/transfer-encrypted/init
	$(HOWL) _build --with postgresql --arch $(ARCH) --disable=secureboot,tpm,ipe slot
	$(HOWL) _build --with data-transfer-helper --arch $(ARCH) transfer_helper
	bsdtar -cf build/$(ARCH)/transfer-encrypted.cpio --format newc --uid 0 --gid 0 --numeric-owner @build/$(ARCH)/data-transfer-helper/rootfs.tar @build/$(ARCH)/data-transfer-helper/overlay.tar -C build/$(ARCH)/transfer-encrypted init
	zstd -1 -q -T1 -f --rm build/$(ARCH)/transfer-encrypted.cpio -o build/$(ARCH)/transfer-encrypted.cpio.zst
	build/host/data-transfer-check $(DATA_TRANSFER_KERNEL) build/$(ARCH)/data-transfer-helper/helper.cpio.zst $(DATA_TRANSFER_IMAGE) $(DATA_TRANSFER_VERITY) build/$(ARCH)/transfer-boundaries.cpio $(HOWL) build/$(ARCH)/transfer-encrypted.cpio.zst

# Linux kernel enforcement is checked in its own networkless disposable VM.
build/$(ARCH)/transfer-boundaries.cpio: cmd/data-transfer/data-transfer.zig test/transfer-boundary-init.zig $(wildcard lib/*.zig)
	@mkdir -p build/$(ARCH)/transfer-boundaries
	zig test -O ReleaseSafe -target $(ARCH)-linux-musl --test-no-exec $(call ZIG_MODULES,cmd/data-transfer/data-transfer.zig) -femit-bin=build/$(ARCH)/transfer-boundaries/checks
	zig build-exe -O ReleaseSafe -target $(ARCH)-linux-musl $(call ZIG_MODULES,test/transfer-boundary-init.zig) -femit-bin=build/$(ARCH)/transfer-boundaries/init
	@mkdir -p build/$(ARCH)/transfer-boundaries/usr/lib/werewolf
	zig build-exe -O ReleaseSafe -target $(ARCH)-linux-musl $(call ZIG_MODULES,cmd/data-transfer/data-transfer.zig) -femit-bin=build/$(ARCH)/transfer-boundaries/usr/lib/werewolf/data-transfer
	bsdtar -cf $@ --format newc --uid 0 --gid 0 --numeric-owner -C build/$(ARCH)/transfer-boundaries init checks usr
