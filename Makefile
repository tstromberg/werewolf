# werewolf: a Wolfi userland on an Alpine kernel, for virtual machines.
# This Makefile builds, tests and releases werewolf. howl builds and runs
# machines (cmd/howl/README.md).
#
#   make install-deps     install apko, Zig, QEMU and the rest, after asking
#   make howl             build build/host/howl; make install puts it on PATH
#   make test             run every unit test, in seconds
#   make lint             check Zig, YAML and docs; make fix repairs what it can
#   make hooks            run test, lint and check-sshd before each commit
#   make -j check         boot every form and a slot in parallel, and attack each
#   make check-FORM       check one form; check-shellfree-FORM checks it as shipped
#   make check-one        boot FORM REPEAT times, to chase a flake
#   make check-updater    run a whole update, over the network
#   make check-gcp        check prod-ssh on GCP; also check-aws and check-azure
#   make ci               run CI's check job in an Ubuntu VM under Lima
#   make image|slot|disk  build FORM's initramfs, bite slot or UEFI disk
#   make bite-me          take over this Debian, Ubuntu, Fedora or Rocky VM
#   make list-forms       list the forms and the forms each includes
#   make relock           resolve FORM's packages again
#   make dist             build the released forms, unsigned (docs/releases.md)
#   make posture          build posture; on Linux, run it here as root
#   make clean            remove build/, except the package locks
#
# FORM picks the form (default sshd), ARCH the arch (default this machine's).
# DEV=1 adds a shell, for debugging, never for release. See docs/testing.md.

# := runs uname once; ARCH ?= $(shell ...) would run it at every use.
HOST_ARCH := $(shell uname -m | sed 's/arm64/aarch64/;s/amd64/x86_64/')
ARCH ?= $(HOST_ARCH)
HOST_OS := $(shell uname -s)

FORM ?= $(if $(filter bite-me,$(MAKECMDGOALS)),prod-ssh,sshd)
FORM_TOOL = build/host/form
FORM_TOOL_SOURCES = tools/form.zig lib/form.zig lib/compose.zig lib/package.zig lib/allow.zig lib/sshd.zig lib/service.zig lib/seal.zig lib/settings.zig
# compose_modules NAME is lib/compose.zig as module NAME, with its imports.
compose_modules = --dep form --dep seal --dep service --dep package -M$(1)=lib/compose.zig -Mpackage=lib/package.zig \
	--dep allow --dep sshd -Mform=lib/form.zig -Mallow=lib/allow.zig --dep settings -Msshd=lib/sshd.zig \
	--dep seal --dep settings -Mservice=lib/service.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig
FORM_TOOL_MODULES = --dep form --dep compose -Mroot=tools/form.zig $(call compose_modules,compose)
COMPOSE_MODULES = $(call compose_modules,root)
HOWL = build/host/howl
FORM_REF := $(FORM)
override FORM := $(notdir $(patsubst %/,%,$(FORM)))
# These goals need no form tool, and install-deps runs before there is a Zig.
FORMLESS = install-deps install uninstall howl $(HOWL) clean help
ifeq ($(filter-out $(FORMLESS),$(or $(MAKECMDGOALS),all)),)
FORM_ASK = :
else
FORM_ASK = $(FORM_TOOL)
# make asks the tool as it reads this file, so build it first.
FORM_TOOL_BUILT := $(shell [ -x $(FORM_TOOL) ] && [ -z "$$(find $(FORM_TOOL_SOURCES) -newer $(FORM_TOOL))" ] || \
	{ mkdir -p build/host && zig build-exe -O ReleaseSafe $(FORM_TOOL_MODULES) -femit-bin=$(FORM_TOOL).$$$$ >&2 && \
		mv $(FORM_TOOL).$$$$ $(FORM_TOOL); })
ifeq ($(wildcard $(FORM_TOOL)),)
$(error no $(FORM_TOOL), as zig says above; `make install-deps` installs zig)
endif
CHAIN := $(shell $(FORM_TOOL) names $(FORM_REF))
ifeq ($(CHAIN),)
$(error no form $(FORM_REF), as build/host/form says above; `make list-forms` lists them)
endif
endif
FORM_DIRS := $(shell $(FORM_ASK) dirs $(FORM_REF))
FORM_DIR := $(lastword $(FORM_DIRS))
FORM_FILES := $(wildcard $(addsuffix /apko.yaml,$(FORM_DIRS)) $(addsuffix /form.yaml,$(FORM_DIRS)))
# form_list KEY is form.yaml's KEY along the chain; form_check KEY, its check: KEY.
form_list = $(shell $(FORM_ASK) list $(FORM_REF) $(1))
form_check = $(shell $(FORM_ASK) check $(FORM_REF) $(1))
KERNEL_ARGS := $(shell $(FORM_ASK) cmdline $(FORM_REF) $(ARCH))
ifeq ($(KERNEL_ARGS)$(filter :,$(FORM_ASK)),)
$(error form $(FORM) has no kernel arguments, as build/host/form says above)
endif

BUILD = build/$(ARCH)
APP ?=
DEV ?=
OUT = $(BUILD)/$(FORM)$(if $(DEV),-dev)$(if $(APP),-app)$(if $(PUBLISHED),-published)
TAR ?= $(shell command -v bsdtar || echo tar)
SHA256 ?= $(shell command -v sha256sum || echo shasum -a 256)
.DELETE_ON_ERROR:

# A target named _NAME is a step of another target.
.PHONY: all install uninstall install-deps precommit hooks image slot disk bite-me list-forms test \
	programs packages posture howl cve-tiers relock release-inputs dist clean help ci check check-forms \
	check-shellfree check-integrity check-cloud check-native check-one check-adhoc check-bastion \
	check-slot check-compose check-updater check-updater-staged check-updater-release check-nodata \
	check-lease check-static check-unsigned check-verity check-deadman check-metadata check-persist \
	check-dist check-gcp check-aws check-azure seal-learn $(OUT)/disk.qcow2

all: image
install-deps:
	@tools/install-deps
precommit:
	@tools/git-hooks/pre-commit
hooks:
	git config core.hooksPath tools/git-hooks
	@echo "hooks: git runs tools/git-hooks/pre-commit before each commit: test, lint, check-sshd"

# howl builds the images (docs/design/howl-build.md). FREEZE=1 pins packages to
# the locks; PUBLISHED=1 takes the programs from werewolf's apk repository.
HOWL_BUILD = FREEZE=$(FREEZE) $(HOWL) _build --verbose --with $(FORM_REF) --arch $(ARCH) \
	--build $(BUILD) --programs $(PROGRAMS) $(if $(DEV),--dev) $(if $(APP),--app-root $(APP)) \
	$(if $(PUBLISHED),--published)
image slot: $(HOWL)
	$(HOWL_BUILD) $@
disk: $(HOWL)
	$(HOWL_BUILD) $(if $(DISK),--disk $(DISK)) $(if $(DISK_MIB),--disk-mib $(DISK_MIB)) $(if $(DISK_ARGS),--disk-args "$(DISK_ARGS)") disk
# A released disk never takes DISK_ARGS.
$(OUT)/disk.qcow2: $(HOWL)
	$(HOWL_BUILD) $(if $(DISK_MIB),--disk-mib $(DISK_MIB)) qcow2

# apko locks pin every package for both arches. howl resolves stale locks itself;
# these rules serve relock and release-inputs, which need only apko and the form tool.
LOCK = build/lock
FORM_LOCK = $(LOCK)/$(FORM)$(if $(DEV),-dev)$(if $(PUBLISHED),-published).lock.json
BOOT_LOCKS = $(LOCK)/kernel.lock.json $(LOCK)/boot.lock.json
LOCKS = $(FORM_LOCK) $(BOOT_LOCKS)
DEV_PACKAGES = busybox-full $(call form_list,dev)
FORM_APKO = $(BUILD)/form/$(FORM)$(if $(DEV),-dev)$(if $(PUBLISHED),-published).yaml
# A published config names werewolf's key by the file name its index's
# signature gives, beside the config (cmd/howl/packages.zig does the same).
PACKAGES_KEY = $(BUILD)/keys/werewolf-packages.rsa.pub
# apko_retry COMMAND retries COMMAND after 15, 30 and 45 s if it cannot reach
# the package server, which refuses bursts of requests (HTTP 403) for a while.
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
$(FORM_APKO): $(FORM_FILES) $(FORM_TOOL) $(if $(PUBLISHED),$(PACKAGES_KEY))
	mkdir -p $(dir $@) && $(FORM_TOOL) apko $(FORM_REF) \
		$(if $(PUBLISHED),--published ../keys/$(notdir $(PACKAGES_KEY))) $(if $(DEV),$(DEV_PACKAGES)) >$@.tmp && \
		{ cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@; }
$(PACKAGES_KEY): release/packages.pub
	mkdir -p $(dir $@) && cp $< $@
$(BOOT_LOCKS): $(LOCK)/%.lock.json: boot/%.yaml
	$(call apko_lock,$<)
relock:
	rm -f $(LOCKS)
	$(MAKE) --no-print-directory FORM=$(FORM) $(LOCKS)

# Zig is pre-1.0, so insist on the version the code is written for.
ZIG_VERSION = 0.17.0
PROGRAMS = build/$(ARCH)/programs
CMDS := $(filter-out howl,$(patsubst cmd/%/,%,$(wildcard cmd/*/)))
# program_bin NAME is where cmd/NAME is built; form_bin DIR, where forms/F/cmd/P is.
program_bin = $(PROGRAMS)/$(1)/$(or $(PROGRAM_AT_$(1)),usr/lib/werewolf/$(1))
PROGRAM_AT_init = init
PROGRAM_AT_bite-cleanup = usr/bin/bite-cleanup
PROGRAM_AT_popen-shim = usr/lib/werewolf/popen-shim.so
form_bin = $(PROGRAMS)/forms/$(notdir $(patsubst %/cmd/$(notdir $(1)),%,$(1)))/usr/lib/werewolf/$(notdir $(1))
FORM_CMDS := $(sort $(patsubst %/,%,$(wildcard forms/*/cmd/*/) $(foreach d,$(FORM_DIRS),$(wildcard $(d)/cmd/*/))))
POSTURE_BIN = $(call program_bin,posture)
define zig_check
@[ "$$(zig version)" = "$(ZIG_VERSION)" ] || \
	{ echo "$< is written for zig $(ZIG_VERSION), not $$(zig version)" >&2; exit 1; }
mkdir -p $(dir $@)
endef

# A program may import any library; a library, only what its --dep flags name.
LIB_MODULES = --dep seal -Msandbox=lib/sandbox.zig -Mbroker=lib/broker.zig -Mdm=lib/dm.zig \
	-Mverity=lib/verity.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig \
	-Mupdate-policy=lib/update-policy.zig -Mnetwork=lib/network.zig -Mhostkey=lib/hostkey.zig \
	--dep allow --dep sshd -Mform=lib/form.zig --dep seal -Maudit=lib/audit.zig \
	--dep seal --dep settings -Mservice=lib/service.zig -Mallow=lib/allow.zig -Mcve=lib/cve.zig \
	--dep network -Mcmdline=lib/cmdline.zig --dep settings -Msshd=lib/sshd.zig --dep form --dep seal \
	--dep service --dep package -Mcompose=lib/compose.zig -Mpackage=lib/package.zig -Mimage=lib/image.zig \
	-Mgpt=boot/gpt.zig
ZIG_MODULES = --dep sandbox --dep broker --dep dm --dep verity --dep seal --dep settings --dep update-policy \
	--dep network --dep hostkey --dep form --dep audit --dep service --dep allow --dep cve --dep cmdline \
	--dep sshd --dep compose --dep package --dep image --dep gpt -Mroot=$(1) $(LIB_MODULES)

# program NAME, BINARY, DIR is the rule that builds DIR (default cmd/NAME) into BINARY.
define program
$(2): $(or $(3),cmd/$(1))/$(1).zig $$(wildcard $(or $(3),cmd/$(1))/*.zig) $$(wildcard lib/*.zig)
	$$(zig_check)
	zig build-exe -O ReleaseSafe -fstrip -target $$(ARCH)-linux-musl $$(call ZIG_MODULES,$$<) -femit-bin=$$@
endef
$(foreach p,$(filter-out popen-shim,$(CMDS)),$(eval $(call program,$(p),$(call program_bin,$(p)))))
$(foreach c,$(FORM_CMDS),$(eval $(call program,$(notdir $(c)),$(call form_bin,$(c)),$(c))))
# pg-init preloads popen-shim.so into initdb, so it links glibc as initdb does.
$(call program_bin,popen-shim): cmd/popen-shim/popen-shim.zig
	$(zig_check)
	zig build-lib -dynamic -O ReleaseSafe -fstrip -target $(ARCH)-linux-gnu -lc -femit-bin=$@ $<

# howl makes programs before it builds an image.
programs: $(foreach p,$(CMDS),$(call program_bin,$(p))) $(foreach c,$(FORM_CMDS),$(call form_bin,$(c)))

VERITY_BIN = build/host/verity
$(VERITY_BIN): tools/verity.zig lib/verity.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe --dep verity -Mroot=$< -Mverity=lib/verity.zig -femit-bin=$@

# howl is built under a temporary name and renamed, so a check running it
# never finds an empty file, which a shell would run as a script that passes.
howl: $(HOWL)
$(HOWL): cmd/howl/howl.zig $(wildcard cmd/howl/*.zig) lib/settings.zig lib/update-policy.zig lib/network.zig \
	lib/form.zig lib/allow.zig lib/service.zig lib/seal.zig lib/sshd.zig lib/compose.zig lib/package.zig \
	lib/verity.zig lib/image.zig boot/gpt.zig
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

# Each file's tests are a target, so make -j test runs them in parallel.
PROGRAM_SOURCES = $(foreach d,$(wildcard cmd/* forms/*/cmd/*),$(d)/$(notdir $(d)).zig)
TEST_SOURCES = lib/sandbox.zig lib/seal.zig lib/dm.zig lib/verity.zig lib/settings.zig lib/update-policy.zig \
	lib/network.zig lib/cmdline.zig lib/hostkey.zig lib/audit.zig lib/form.zig lib/compose.zig lib/package.zig \
	lib/allow.zig lib/service.zig lib/cve.zig lib/sshd.zig lib/image.zig tools/form.zig tools/package.zig \
	boot/gpt.zig tools/cve-tiers.zig tools/test-sk.zig tools/doc-check.zig $(PROGRAM_SOURCES)
test: $(addprefix _test/,$(TEST_SOURCES)) _test/howl-smoke
	@echo "test: $(words $(TEST_SOURCES)) suites passed, and howl's lines"
_test/lib/sandbox.zig _test/lib/audit.zig: _test/%: ; zig test --dep seal -Mroot=$* -Mseal=lib/seal.zig
_test/lib/cmdline.zig: ; zig test --dep network -Mroot=lib/cmdline.zig -Mnetwork=lib/network.zig
_test/lib/form.zig: ; zig test --dep allow --dep sshd -Mroot=lib/form.zig -Mallow=lib/allow.zig --dep settings \
		-Msshd=lib/sshd.zig -Msettings=lib/settings.zig
_test/lib/sshd.zig: ; zig test --dep settings -Mroot=lib/sshd.zig -Msettings=lib/settings.zig
_test/lib/service.zig: ; zig test --dep seal --dep settings -Mroot=lib/service.zig -Mseal=lib/seal.zig \
		-Msettings=lib/settings.zig
_test/tools/form.zig: ; zig test $(FORM_TOOL_MODULES)
_test/lib/compose.zig: ; zig test $(COMPOSE_MODULES)
_test/tools/package.zig: ; zig test --dep package -Mroot=tools/package.zig -Mpackage=lib/package.zig
_test/tools/cve-tiers.zig: ; zig test $(call ZIG_MODULES,tools/cve-tiers.zig)
_test/cmd/popen-shim/popen-shim.zig: ; zig test cmd/popen-shim/popen-shim.zig -lc
_test/tools/test-sk.zig: ; zig test tools/test-sk.zig -lc
_test/cmd/%.zig: ; zig test $(call ZIG_MODULES,cmd/$*.zig)
_test/forms/%.zig: ; zig test $(call ZIG_MODULES,forms/$*.zig)
_test/%.zig: ; zig test $*.zig
_test/howl-smoke: $(HOWL)
	@test/howl-smoke $(HOWL) $(BUILD)

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
$(PACKAGE_TOOL): tools/package.zig lib/package.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe --dep package -Mroot=$< -Mpackage=lib/package.zig -femit-bin=$@
packages: $(PACKAGE_TOOL) programs
	@[ -n "$(PACKAGE_TIME)" ] || { echo "packages: no commit time; set PACKAGE_TIME" >&2; exit 1; }
	rm -rf $(PACKAGES)/$(ARCH) $(PACKAGES)/empty && mkdir -p $(PACKAGES)/$(ARCH) $(PACKAGES)/empty
	$(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) $(PACKAGES)/empty werewolf-format $(PACKAGE_FORMAT)-r0 $(ARCH) 0 \
		"werewolf's format $(PACKAGE_FORMAT) (lib/compose.zig)"
	for p in $(CMDS); do $(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) $(PROGRAMS)/$$p werewolf-$$p - \
		$(ARCH) $(PACKAGE_TIME) "werewolf's $$p (cmd/$$p)" depend:werewolf-format=$(PACKAGE_FORMAT) || exit 1; done
	$(PACKAGE_TOOL) index $(PACKAGES)/$(ARCH) -
	@echo "packages: $(words $(CMDS)) in $(PACKAGES)/$(ARCH); sign APKINDEX.member, then build/host/package sign"

# cve-tiers reads the NVD key in the recipe, so make never prints it (tools/README.md).
CVE_TIERS_BIN = build/host/cve-tiers
NVD_API_KEY_FILE ?= $(HOME)/.tok/werewolf-nvd
$(CVE_TIERS_BIN): tools/cve-tiers.zig lib/cve.zig lib/update-policy.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe $(call ZIG_MODULES,$<) -femit-bin=$@
cve-tiers: $(CVE_TIERS_BIN) $(LOCK)/kernel.lock.json
	mkdir -p build/tiers && FORM_TOOL=$(FORM_TOOL) release/origins build/tiers/origins
	@kernel=$$(sed -n 's|.*"url": "[^"]*/$(ARCH)/\(linux-virt-[^/]*\)\.apk".*|\1|p' $(LOCK)/kernel.lock.json) && \
	NVD_API_KEY=$${NVD_API_KEY:-$$(cat $(NVD_API_KEY_FILE))} \
	$(CVE_TIERS_BIN) "$$kernel" build/tiers/origins build/tiers/nvd build/tiers/in build/tiers/cve-tiers.json

ifneq ($(filter bite-me,$(MAKECMDGOALS)),)
ifneq ($(HOST_OS)-$(HOST_ARCH),Linux-$(ARCH))
$(error bite-me runs on the Linux $(ARCH) machine it takes over)
endif
endif
bite-me: slot
	$(if $(filter 0,$(shell id -u)),,sudo) ./bite -i $(if $(wildcard config/*),--config config) $(OUT)/slot
list-forms:
	@$(FORM_TOOL) tree

# CI releases these forms when release-inputs changes (docs/releases.md). dist
# pins packages to the locks (FREEZE=1), so two runners agree byte for byte.
RELEASE_FORMS = $(shell $(FORM_ASK) released)
DIST_DIRECT_FORMS = minimal
DIST = dist
RELEASE_SOURCES = Makefile forms boot cmd lib tools/form.zig release/image.pub release/tiers.pub release/advisories \
	release/packages.pub
# Releases take werewolf's programs from its repository (howl build does), so
# their locks are the published ones: a newly published program is an input.
RELEASE_LOCKS = $(addprefix $(LOCK)/,$(addsuffix -published.lock.json,$(RELEASE_FORMS)) kernel.lock.json boot.lock.json)
# The inputs are a digest of the sources' bytes and exec bits, and every package's URL.
release-inputs:
	rm -f $(RELEASE_LOCKS)
	$(MAKE) --no-print-directory -j $(addprefix _lock/,$(RELEASE_FORMS)) $(BOOT_LOCKS)
	{ echo "tree $$({ find $(RELEASE_SOURCES) -type f ! -name .DS_Store | LC_ALL=C sort | xargs $(SHA256); \
		find $(RELEASE_SOURCES) -type f -perm -100 | LC_ALL=C sort; } | $(SHA256) | cut -c1-64)"; \
	  sed -n 's|.*"url": "\([^"]*\.apk\)".*|\1|p' $(RELEASE_LOCKS) | LC_ALL=C sort -u; } >$(LOCK)/inputs
	@echo "inputs: $$($(SHA256) < $(LOCK)/inputs | cut -c1-16), $$(grep -c '^https' $(LOCK)/inputs) packages"
_lock/%:
	@$(MAKE) --no-print-directory PUBLISHED=1 FORM=$* $(LOCK)/$*-published.lock.json
dist:
	for f in $(RELEASE_FORMS); do $(MAKE) --no-print-directory FREEZE=1 FORM=$$f _dist-form || exit 1; done
# howl build always builds in build/ARCH, without DEV or APP, so refuse them.
_dist-form: $(HOWL)
	@[ "$(BUILD)" = build/$(ARCH) ] && [ -z "$(DEV)$(APP)" ] || \
		{ echo "_dist-form: a release builds in build/$(ARCH), without DEV or APP (howl build --app)" >&2; exit 1; }
	FREEZE=$(FREEZE) $(HOWL) build --verbose --with $(FORM_REF) --arch $(ARCH) -o $(DIST)

# check-NAME builds what it boots, then runs test/check-NAME (docs/testing.md).
# Machines share nothing, so make -j check runs them in parallel.
MACHINE = $(if $(filter aarch64,$(ARCH)),virt,q35)
CONSOLE = $(if $(filter aarch64,$(ARCH)),ttyAMA0,ttyS0)
# Without KVM, HVF or NVMM (some CI runners, FreeBSD), QEMU emulates.
ifeq ($(ARCH),$(HOST_ARCH))
ACCEL = $(if $(filter Darwin,$(HOST_OS)),hvf,$(if $(wildcard /dev/kvm),kvm,$(if $(wildcard /dev/nvmm),nvmm,tcg)))
CPU = $(if $(filter tcg,$(ACCEL)),max,host)
else
ACCEL = tcg
CPU = max
endif
# An aarch64 guest with EL2 starts KVM unless kvm-arm.mode=none, so checks get
# EL2 where QEMU can lend it, and posture proves the argument holds.
EL2 = $(if $(filter aarch64,$(ARCH)),$(shell echo quit | qemu-system-aarch64 -M virt,virtualization=on -accel $(ACCEL) -cpu $(CPU) -nodefaults -display none -monitor stdio -S >/dev/null 2>&1 && echo ,virtualization=on))
QEMU = qemu-system-$(ARCH) -M $(MACHINE)$(EL2) -accel $(ACCEL) -cpu $(CPU) -nographic

FORMS := $(patsubst forms/%/apko.yaml,%,$(wildcard forms/*/apko.yaml))
CHECK = $(BUILD)/check$(if $(SEAL_LEARN),-learn)
# test/checks needs a root shell on the console, so checks build with DEV=1.
CHECK_MAKE = $(MAKE) --no-print-directory DEV=1
# 1 GiB keeps forms lean, unless their check: memory says more. An offline form
# gets no way out (restrict=on). Direct boot needs no boot ROM, and CI has none.
CHECK_MEMORY := $(or $(call form_check,memory),1024)
CHECK_OFFLINE := $(if $(filter true,$(call form_check,offline)),$(,)restrict=on)
CHECK_QEMU = $(QEMU) -smp 2 -m $(CHECK_MEMORY) -no-reboot -device virtio-rng-pci \
	-netdev user,id=n0$(CHECK_OFFLINE) -device virtio-net-pci,netdev=n0,romfile=
# A stall panics, and the panic ends QEMU, so a hang fails in seconds with the
# kernel's reason. A machine in use rides out a slow moment instead.
CHECK_STALLS = rcupdate.rcu_cpu_stall_timeout=20 sysctl.kernel.panic_on_rcu_stall=1 \
	sysctl.kernel.hung_task_timeout_secs=120 sysctl.kernel.hung_task_panic=1 sysctl.kernel.softlockup_panic=1
SEAL_ARGS = $(if $(SEAL_LEARN),werewolf.seal=learn)
CHECK_BOOT = console=$(CONSOLE) $(KERNEL_ARGS) panic=1 werewolf.debug=1 werewolf.check=1 $(CHECK_STALLS) $(SEAL_ARGS)
CHECK_CMDLINE = $(CHECK_BOOT) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3
# The posture failures test/boot expects: test/posture-known's and the form's weaknesses.
POSTURE_KNOWN_KIND := $(shell awk -v b=$(if $(DEV),dev,*) -v a=$(ARCH) '$$1 == b || $$1 == a { $$1 = ""; k = k $$0 } END { print k }' test/posture-known)
export POSTURE_KNOWN := $(POSTURE_KNOWN_KIND) $(shell $(FORM_ASK) weaknesses $(FORM_REF))
# A check script's environment (docs/testing.md). Homebrew keeps debugfs off PATH.
VICTIM_UUID = 0e7e1f00-c4ec-4b00-8000-00000000c4ec
DEBUGFS = $(firstword $(shell command -v debugfs) $(wildcard /opt/homebrew/opt/e2fsprogs/sbin/debugfs /usr/local/opt/e2fsprogs/sbin/debugfs))
CHECK_ENV = CHECK=$(CHECK) FORM=$(FORM) OUT=$(OUT) KERNEL=$(BUILD)/vmlinuz BOOT='$(CHECK_BOOT)' \
	CMDLINE='$(CHECK_CMDLINE)' VICTIM=$(VICTIM_UUID) DEBUGFS=$(DEBUGFS) HOWL=$(HOWL) TAR=$(TAR)
# built NAME, COMMAND logs COMMAND to CHECK/NAME-build.log, and shows its tail on failure.
built = mkdir -p $(CHECK) && $(2) >$(CHECK)/$(1)-build.log 2>&1 || \
	{ tail -n 20 $(CHECK)/$(1)-build.log; echo "FAIL   $(1) build: see $(CHECK)/$(1)-build.log"; exit 1; }
# What every check needs, built once, before the forms build in parallel.
_check-shared: $(HOWL) $(TEST_SK)
	@$(call built,shared,$(MAKE) --no-print-directory FORM=minimal DEV=1 APP= image)

# CI runs each group as a job (.github/workflows/check.yml). SHARD=K/N runs
# every Nth form from the Kth, in name order.
ifneq ($(SHARD),)
ifeq ($(shell echo '$(SHARD)' | awk -F/ '/^[1-9][0-9]*\/[1-9][0-9]*$$/ && $$1 <= $$2'),)
$(error SHARD=$(SHARD): K/N, the Kth of N, 1 <= K <= N)
endif
endif
shard = $(if $(SHARD),$(shell echo $(sort $(1)) | tr ' ' '\n' | \
	awk -F/ -v s=$(SHARD) 'BEGIN { split(s, a, "/") } (NR - 1) % a[2] == a[1] - 1'),$(1))
check-forms:     $(addprefix check-,$(call shard,$(FORMS)))
check-shellfree: $(addprefix check-shellfree-,$(call shard,$(FORMS)))
check-integrity: check-slot check-unsigned check-verity check-deadman
# check-adhoc pulls an OCI image, too slowly on emulated arm64.
check-cloud:     check-metadata check-nodata check-lease check-static $(if $(filter aarch64-tcg,$(ARCH)-$(ACCEL)),,check-adhoc)
check: check-forms check-shellfree check-integrity check-cloud check-persist
	@echo "check: every form, and a slot, passed"

NATIVE_FORMS := $(filter-out $(shell $(FORM_ASK) having native false),$(FORMS))
.PHONY: $(addprefix check-native-,$(NATIVE_FORMS))
check-native: $(addprefix check-native-,$(call shard,$(NATIVE_FORMS)))
$(addprefix check-native-,$(NATIVE_FORMS)): check-native-%: | _check-shared
	@$(call built,$*-native,$(MAKE) --no-print-directory FORM=$* DEV= slot)
	@$(MAKE) --no-print-directory FORM=$* DEV= _check-native
_check-native:
	@test/cage $(FORM) $(OUT)/slot/root.erofs $(CHECK)/$(FORM)-native.log
seal-learn: | _check-shared
	-@$(MAKE) --no-print-directory -k SEAL_LEARN=1 $(addprefix check-,$(FORMS)) check-slot check-persist \
		check-nodata check-lease check-static check-unsigned check-metadata
	@test/seal-learn $(BUILD)/check-learn

REPEAT ?= 10
check-one: | _check-shared
	@$(call built,$(FORM),$(CHECK_MAKE) FORM=$(FORM) image)
	@test/check-one $(REPEAT) $(CHECK) $(FORM) $(CHECK_MAKE) FORM=$(FORM) _check-form

check-%: | _check-shared
	@$(call built,$*,$(CHECK_MAKE) FORM=$* image)
	@$(CHECK_MAKE) FORM=$* _check-form
# Each form's ports get their own host ports, so forms boot in parallel.
check_port = $(shell echo $(FORMS) | tr ' ' '\n' | grep -n -x '$(2)' | cut -d: -f1 | awk '{ print $(1) + $$1 }')
CHECK_SSH := $(if $(filter 22,$(shell $(FORM_ASK) listens $(FORM_REF))),$(call check_port,22200,$(FORM)))
CHECK_WEB_PORT := $(call form_check,web)
CHECK_WEB := $(if $(CHECK_WEB_PORT),$(call check_port,23200,$(FORM)))
CHECK_FWD = $(if $(CHECK_SSH),$(,)hostfwd=tcp:127.0.0.1:$(CHECK_SSH)-:22$(if $(CHECK_WEB),$(,)hostfwd=tcp:127.0.0.1:$(CHECK_WEB)-:$(CHECK_WEB_PORT)))
# The forms booted again on the disks they left (docs/testing.md).
AGAIN_FORMS ?= minimal sshd prod-ssh gitea vaultwarden demo
ifeq ($(AGAIN_FORMS),all)
override AGAIN_FORMS := $(FORMS)
endif
_check-form: $(HOWL) $(TEST_SK)
	@$(CHECK_ENV) FORM_REF=$(FORM_REF) FORM_DIR=$(FORM_DIR) SKIP='$(call form_check,skip)' \
		AGAIN=$(filter $(AGAIN_FORMS),$(FORM)) SSH_PORT=$(CHECK_SSH) SSH_SK_PROVIDER=$(CURDIR)/$(TEST_SK) \
		KEPT_KEYS=$(CHECK_KEPT_KEYS) GITEA_PORT=$(CHECK_WEB) test/check-form \
		$(subst user$(,)id=n0,user$(,)id=n0$(CHECK_FWD),$(CHECK_QEMU))

check-adhoc: $(HOWL) | _check-shared
	@mkdir -p $(CHECK) && rm -rf $(BUILD)/adhoc/check-oci
	@$(HOWL) form --with prod --oci web=cgr.dev/chainguard/nginx --web.listen tcp/8080 --web.write /var/lib/nginx/tmp -o $(BUILD)/adhoc/check-oci >$(CHECK)/check-oci-form.log 2>&1 || \
		{ tail -n 20 $(CHECK)/check-oci-form.log; echo "FAIL   check-oci form: see $(CHECK)/check-oci-form.log"; exit 1; }
	@$(call built,check-oci,$(CHECK_MAKE) FORM=$(BUILD)/adhoc/check-oci image)
	@$(CHECK_MAKE) FORM=$(BUILD)/adhoc/check-oci _check-form

# Rules of their own, so check-% takes neither check-bastion nor check-shellfree-FORM.
check-bastion: $(HOWL) $(TEST_SK) | _check-shared
	@test/bastion-form $(CHECK) $(FORM_TOOL) $(CURDIR)/$(TEST_SK)
	@$(call built,bastion,$(CHECK_MAKE) FORM=$(CHECK)/bastion-check image)
	@$(CHECK_MAKE) FORM=$(CHECK)/bastion-check CHECK_SSH=$(call check_port,22200,bastion) CHECK_KEPT_KEYS=1 _check-form
$(addprefix check-shellfree-,$(FORMS)): check-shellfree-%: | _check-shared
	@$(call built,$*-shellfree,$(MAKE) --no-print-directory FORM=$* DEV= image)
	@$(MAKE) --no-print-directory FORM=$* DEV= _check-shellfree
_check-shellfree:
	@$(CHECK_ENV) CONSOLE=$(wildcard $(FORM_DIR)/test/console) test/check-shellfree $(CHECK_QEMU)

# These boot what a form's check built, so they follow it. The slot is
# minimal's, which has no updater to reach the network once it commits.
check-lease check-nodata check-metadata: | _check-shared check-prod
	@$(CHECK_MAKE) FORM=prod _$@
check-static check-verity: | _check-shared check-minimal
	@$(CHECK_MAKE) FORM=minimal _$@
check-slot: | _check-shared check-minimal
	@$(call built,slot,$(CHECK_MAKE) FORM=minimal slot)
	@$(CHECK_MAKE) FORM=minimal _check-slot
# check-slot builds the same slot in the same place, so these follow it.
check-deadman: | _check-shared check-minimal check-slot
	@$(call built,deadman,$(CHECK_MAKE) FORM=minimal slot)
	@$(CHECK_MAKE) FORM=minimal _check-deadman
check-unsigned: | _check-shared check-minimal check-slot
	@$(CHECK_MAKE) FORM=minimal _check-unsigned
_check-lease _check-nodata _check-static _check-verity _check-slot _check-deadman _check-unsigned: $(HOWL)
	@$(CHECK_ENV) test/$(@:_%=%) $(CHECK_QEMU)
_check-metadata:
	@$(CHECK_ENV) ARCH=$(ARCH) FIRMWARE=$(if $(filter aarch64,$(ARCH)),$(UEFI_FIRMWARE)) \
		test/check-metadata $(QEMU) -smp 2 -m 1024 -no-reboot -device virtio-rng-pci

# Each run copies x86_64's UEFI variables, so a boot that writes them, or dies
# mid-write, spares the template. splash-time=0 skips arm64 edk2's 5 s countdown.
UEFI_FIRMWARE = $(firstword $(wildcard $(if $(filter aarch64,$(ARCH)), \
	/opt/homebrew/share/qemu/edk2-aarch64-code.fd /usr/local/share/qemu/edk2-aarch64-code.fd \
	/usr/share/qemu/edk2-aarch64-code.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd, \
	/opt/homebrew/share/qemu/edk2-x86_64-code.fd /usr/local/share/qemu/edk2-x86_64-code.fd \
	/usr/share/qemu/edk2-x86_64-code.fd /usr/share/ovmf/OVMF.fd)))
UEFI_VARS = $(firstword $(wildcard /opt/homebrew/share/qemu/edk2-i386-vars.fd /usr/local/share/qemu/edk2-i386-vars.fd \
	/usr/share/qemu/edk2-i386-vars.fd /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd))
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
_check-dist:
	@$(UEFI_ENV) DIST=$(DIST) test/check-dist qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) \
		-nographic -smp 2 -m 2048 -snapshot -no-reboot $(UEFI_FLAGS) -device virtio-rng-pci \
		-netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0,romfile=

# check-persist boots without EL2, since edk2 under HVF with it never reaches
# the boot manager, and offline, so the updater builds no slot mid-test. CI
# checks demo in its forms jobs, so it sets PERSIST_AFTER= to boot it once.
PERSIST_ARGS = console=$(CONSOLE) werewolf.debug=1 werewolf.check=1 $(CHECK_STALLS) $(SEAL_ARGS)
PERSIST_AFTER ?= check-demo
check-persist: | _check-shared $(PERSIST_AFTER)
ifeq ($(ARCH)-$(ACCEL),aarch64-tcg)
	@echo "skip   persist            emulated arm64 (no EL2): UEFI boot too slow; x86_64 covers it"
else
	@[ -n "$(UEFI_FIRMWARE)" ] || { echo "FAIL   persist            no UEFI firmware for $(ARCH) (edk2 or OVMF)"; exit 1; }
	@[ "$(ARCH)" = aarch64 ] || [ -n "$(UEFI_VARS)" ] || { echo "FAIL   persist            no UEFI variables template for $(ARCH) (edk2-i386-vars.fd or OVMF_VARS.fd)"; exit 1; }
	@rm -f $(CHECK)/persist.img
	@$(call built,persist,$(CHECK_MAKE) FORM=demo disk DISK=$(CHECK)/persist.img DISK_MIB=2048 DISK_ARGS="$(PERSIST_ARGS)")
	@$(CHECK_MAKE) FORM=demo _check-persist
endif
_check-persist:
	@$(UEFI_ENV) test/check-persist qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -nographic \
		-smp 2 -m 2048 -no-reboot -device virtio-rng-pci $(UEFI_FLAGS) \
		-netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0,romfile= \
		-drive file=$(CHECK)/persist.img,format=raw,if=virtio

check-gcp check-aws check-azure: check-%:
	@$(MAKE) --no-print-directory FORM=prod-ssh CLOUD=$* _check-cloud
_check-cloud: $(HOWL)
	@test/cloud $(CLOUD) $(FORM) $(ARCH)
check-compose: slot
	@OUT=$(OUT) FORM=$(FORM) ARCH=$(ARCH) DEV=$(DEV) LOCK=$(FORM_LOCK) VENDOR=$(BUILD)/vendor \
		FORM_TOOL=$(abspath $(FORM_TOOL)) TAR=$(TAR) test/check-compose

# EROFS_OPTS must match the options lib/image.zig gives mkfs.erofs.
EROFS_OPTS = -b 4096 -zzstd,level=9 -C65536 -Eall-fragments,dedupe
check-updater check-updater-staged: | _check-shared
	@$(MAKE) --no-print-directory FORM=prod DEV=1 $(if $(filter %-staged,$@),STAGED=1) _check-updater
check-updater-release: | _check-shared
	@$(MAKE) --no-print-directory FORM=prod-ssh _check-updater
_check-updater: $(VERITY_BIN)
	@mkdir -p $(CHECK)/update-$(FORM) && $(MAKE) --no-print-directory slot >$(CHECK)/update-$(FORM)/build.log 2>&1 || \
		{ tail -n 20 $(CHECK)/update-$(FORM)/build.log; echo "FAIL   update build: see $(CHECK)/update-$(FORM)/build.log"; exit 1; }
	@CHECK=$(CHECK) FORM=$(FORM) OUT=$(OUT) TAR=$(TAR) VICTIM=$(VICTIM_UUID) PRUNE='$(call form_list,prune)' \
		EROFS_OPTS='$(EROFS_OPTS)' VERITY=$(VERITY_BIN) CONSOLE=$(CONSOLE) SEAL_ARGS='$(SEAL_ARGS)' STAGED='$(STAGED)' \
		test/check-updater $(QEMU) -smp 2 -m 2048 -no-reboot -device virtio-rng-pci -netdev user,id=n0 \
		-device virtio-net-pci,netdev=n0,romfile=

ci:
	test/lima-ci
# clean keeps the locks, so the next build is the same as the last.
clean:
	rm -rf $(filter-out $(LOCK),$(wildcard build/*))
# help prints this file's opening comment, up to its first empty line.
help:
	@sed -n '2,/^$$/s/^# \{0,1\}//p' Makefile

# BEGIN: lint-install .
LINTERS := yamllint-lint zig-lint doc-lint bite-key-lint
FIXERS := zig-fix
.PHONY: lint _lint fix $(LINTERS) $(FIXERS)
lint: _lint
_lint:
	@status=0; for t in $(LINTERS); do $(MAKE) $$t || status=1; done; exit $$status
fix:
	@status=0; for t in $(FIXERS); do $(MAKE) $$t || status=1; done; exit $$status
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
	PYTHONPATH=$(YAMLLINT_ROOT)/dist $(YAMLLINT_ROOT)/dist/bin/yamllint .
# END: lint-install .

# zig ast-check also checks the functions nothing calls, which a build skips.
ZIG_SOURCES = $(shell find . -name '*.zig' -not -path './build/*' -not -path './out/*' -not -path './.zig-cache/*' -not -path './.claude/*')
ZIGFIX := $(LINT_ROOT)/out/tools/zigfix
$(ZIGFIX): tools/zigfix.zig
	mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -femit-bin=$@ tools/zigfix.zig
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
	@status=0; for f in $(ZIG_SOURCES); do zig ast-check $$f >/dev/null || status=1; done; exit $$status
	$(ZIGFIX) --check $(ZIG_SOURCES)
	$(ZIGLINT_BIN) $(ZIG_SOURCES)
zig-fix: $(ZIGFIX)
	$(ZIGFIX) $(ZIG_SOURCES)

DOC_SOURCES = $(shell find . -name '*.md' -not -path './build/*' -not -path './out/*' -not -path './dist/*' -not -path './.zig-cache/*' -not -path './.claude/*')
DOC_CHECK := $(LINT_ROOT)/out/tools/doc-check
$(DOC_CHECK): tools/doc-check.zig
	mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -femit-bin=$@ tools/doc-check.zig
doc-lint: $(DOC_CHECK)
	$(DOC_CHECK) $(DOC_SOURCES)

# bite checks a downloaded release against its own copy of the release key.
bite-key-lint:
	@sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' bite | cmp -s - release/image.pub || \
		{ echo "bite: its release key differs from release/image.pub"; exit 1; }
