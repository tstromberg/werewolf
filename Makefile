# werewolf: a Wolfi userland on an Alpine kernel, for virtual machines.
# howl builds, boots and removes machines: `make howl`, then
# build/host/howl run --with FORM (cmd/howl/README.md). This file is for
# working on werewolf: its programs, tests, checks and releases.
#
#   make install-deps     install apko, Zig, QEMU, erofs-utils and the rest,
#                         after asking (tools/install-deps; gmake on the BSDs)
#   make howl             build/host/howl; make install puts it on your PATH
#   make test             every unit test, in seconds, no VM
#   make lint             check the Zig and YAML; make fix repairs what it can
#   make hooks            have git run test, lint and check-sshd before a commit
#   make check            boot every form and a slot under QEMU and attack each
#                         (docs/testing.md); make -j check boots them side by side
#   make check-FORM       one form, with a shell for the checks;
#                         check-shellfree-FORM boots it as it ships
#   make check-updater    a whole update, from Wolfi and Alpine
#   make check-gcp        prod-ssh on a GCP VM, then deleted; check-aws, check-azure
#   make ci               CI's check job, in an Ubuntu VM under Lima
#   make image|slot|disk  howl's build of FORM in build/ARCH/FORM: a direct boot's
#                         initramfs, bite's slot, or a UEFI disk (DISK, DISK_MIB
#                         and DISK_ARGS: its path, size and kernel arguments)
#   make bite-me          on a Debian, Ubuntu, Fedora or Rocky VM: build a slot
#                         and take the VM over with it (docs/bite.md)
#   make list-forms       each form and the forms it includes
#   make relock           resolve FORM's packages again; FREEZE=1 pins to them
#   make dist             the released forms' files, unsigned, in dist/;
#                         release-inputs, check-dist and cve-tiers: docs/releases.md
#   make posture          build posture; on Linux, run it here with sudo
#   make clean            remove build/, but for the package locks
#
# FORM picks the form (default sshd; bite-me's prod-ssh). DEV=1 adds a shell,
# for debugging, never for release. ARCH defaults to this machine's.

# Asked once: `ARCH ?= $(shell ...)` would ask at every use of $(ARCH).
HOST_ARCH := $(shell uname -m | sed 's/arm64/aarch64/;s/amd64/x86_64/')
ARCH ?= $(HOST_ARCH)
HOST_OS := $(shell uname -s)

# --- forms --------------------------------------------------------------------
# A form is forms/NAME (forms/README.md), or a directory outside the tree,
# `make FORM=../myapp`. build/host/form answers make's questions about one
# (tools/form.zig); howl reads forms itself.
FORM ?= $(if $(filter bite-me,$(MAKECMDGOALS)),prod-ssh,sshd)
FORM_TOOL = build/host/form
FORM_TOOL_SOURCES = tools/form.zig lib/form.zig lib/compose.zig lib/allow.zig lib/sshd.zig lib/service.zig lib/seal.zig lib/settings.zig
FORM_TOOL_MODULES = --dep form --dep compose -Mroot=tools/form.zig \
	--dep form --dep seal --dep service -Mcompose=lib/compose.zig \
	--dep allow --dep sshd -Mform=lib/form.zig -Mallow=lib/allow.zig --dep settings -Msshd=lib/sshd.zig \
	--dep seal --dep settings -Mservice=lib/service.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig
COMPOSE_MODULES = --dep form --dep seal --dep service -Mroot=lib/compose.zig \
	--dep allow --dep sshd -Mform=lib/form.zig -Mallow=lib/allow.zig --dep settings -Msshd=lib/sshd.zig \
	--dep seal --dep settings -Mservice=lib/service.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig
HOWL = build/host/howl
FORM_REF := $(FORM)
override FORM := $(notdir $(patsubst %/,%,$(FORM)))
# Goals that ask nothing of a form leave the tool be: install-deps installs
# the Zig it is built with.
FORMLESS = install-deps install uninstall howl $(HOWL) clean help
ifeq ($(filter-out $(FORMLESS),$(or $(MAKECMDGOALS),all)),)
FORM_ASK = :
else
FORM_ASK = $(FORM_TOOL)
# Built before anything else is read, in milliseconds when it is current.
FORM_TOOL_BUILT := $(shell [ -x $(FORM_TOOL) ] && [ -z "$$(find $(FORM_TOOL_SOURCES) -newer $(FORM_TOOL))" ] || \
	{ mkdir -p build/host && zig build-exe -O ReleaseSafe $(FORM_TOOL_MODULES) \
		-femit-bin=$(FORM_TOOL).$$$$ >&2 && mv $(FORM_TOOL).$$$$ $(FORM_TOOL); })
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
# form_list KEY: form.yaml's KEY along the chain; form_check KEY: the form's
# own check KEY.
form_list = $(shell $(FORM_ASK) list $(FORM_REF) $(1))
form_check = $(shell $(FORM_ASK) check $(FORM_REF) $(1))
# The kernel arguments the image asks for (lib/compose.zig), which the
# checks boot it with.
KERNEL_ARGS := $(shell $(FORM_ASK) cmdline $(FORM_REF) $(ARCH))
ifeq ($(KERNEL_ARGS)$(filter :,$(FORM_ASK)),)
$(error form $(FORM) has no kernel arguments, as build/host/form says above)
endif

BUILD = build/$(ARCH)
# APP: an application staged as howl's --app stages one (cmd/howl/app.zig),
# laid over the image. An image with one builds apart.
APP ?=
DEV ?=
OUT = $(BUILD)/$(FORM)$(if $(DEV),-dev)$(if $(APP),-app)
TAR ?= $(shell command -v bsdtar || echo tar)
SHA256 ?= $(shell command -v sha256sum || echo shasum -a 256)

# A recipe that fails takes what it half-made with it, or the next make
# would find it newer than its sources and call it built.
.DELETE_ON_ERROR:

# A target whose name starts with _ is a step another target runs.
.PHONY: all install uninstall install-deps precommit hooks image slot disk bite-me list-forms \
	test programs packages posture howl cve-tiers relock release-inputs dist clean help ci \
	check check-forms check-shellfree check-integrity check-cloud check-native check-one \
	check-adhoc check-bastion check-slot check-compose check-updater check-updater-staged \
	check-updater-release check-nodata check-lease check-static check-unsigned check-verity \
	check-deadman check-metadata check-persist check-dist check-gcp check-aws check-azure seal-learn

all: image

install-deps:
	@tools/install-deps

# What a commit must pass, as git's pre-commit hook runs it.
precommit:
	@tools/git-hooks/pre-commit

hooks:
	git config core.hooksPath tools/git-hooks
	@echo "hooks: git runs tools/git-hooks/pre-commit before each commit: test, lint, check-sshd"

# The tutorials' compiled applications and melange's packages, which howl's
# build has make build for the image (cmd/howl/packages.zig).
include examples/build.mk
include melange.mk

# --- the image ----------------------------------------------------------------
# howl builds it (cmd/howl/build.zig, docs/design/howl-build.md); these
# targets ask it to, at make's paths. FREEZE=1 pins every package to its
# lock. DISK, DISK_MIB and DISK_ARGS say where the disk goes, its size, and
# what else goes on its kernel command line: howl's defaults are
# OUT/disk.img, 8 GiB (cmd/howl/disk.zig's default_mib) and nothing.
HOWL_BUILD = FREEZE=$(FREEZE) $(HOWL) _build --verbose --with $(FORM_REF) --arch $(ARCH) \
	--build $(BUILD) --programs $(PROGRAMS) $(if $(DEV),--dev) $(if $(APP),--app-root $(APP))
.PHONY: $(OUT)/disk.qcow2
image slot: $(HOWL)
	$(HOWL_BUILD) $@
disk: $(HOWL)
	$(HOWL_BUILD) $(if $(DISK),--disk $(DISK)) $(if $(DISK_MIB),--disk-mib $(DISK_MIB)) $(if $(DISK_ARGS),--disk-args "$(DISK_ARGS)") disk
# The disk a release publishes, of DISK_MIB but never with DISK_ARGS.
$(OUT)/disk.qcow2: $(HOWL)
	$(HOWL_BUILD) $(if $(DISK_MIB),--disk-mib $(DISK_MIB)) qcow2
# The kernel alone, for melange's VM, if it is missing.
$(BUILD)/vmlinuz: | $(HOWL)
	$(HOWL_BUILD) kernel

# --- locks --------------------------------------------------------------------
# Every package in an image is pinned by an apko lock, for both arches: the
# form's, the kernel's (boot/kernel.yaml) and systemd-boot's for a disk
# (boot/boot.yaml). howl resolves a lock that is missing or older than its
# config as it builds. These rules resolve them for relock and
# release-inputs, which CI runs every 15 minutes with only apko and the
# form tool. DEV=1 builds lock busybox-full, and form.yaml's dev packages
# (a check's clients), apart.
LOCK = build/lock
FORM_LOCK = $(LOCK)/$(FORM)$(if $(DEV),-dev).lock.json
LOCKS = $(FORM_LOCK) $(LOCK)/kernel.lock.json $(LOCK)/boot.lock.json
DEV_PACKAGES = busybox-full $(call form_list,dev)
FORM_APKO = $(BUILD)/form/$(FORM)$(if $(DEV),-dev).yaml

# apko_retry COMMAND: COMMAND, tried again 15, 30 and 45 seconds on when it
# fails to reach the package server, which turns a burst of requests away
# for a few seconds (HTTP 403). Any other failure fails at once.
APKO_NETWORK = status code (403|408|429|5[0-9][0-9])|connection reset|i/o timeout|TLS handshake|deadline exceeded|unexpected EOF|failed to fetch
apko_retry = o=$(CURDIR)/$@.apko && for t in 1 2 3 4; do \
	{ $(1); echo $$? >$$o.rc; } 2>&1 | tee $$o; rc=$$(cat $$o.rc); \
	if [ "$$rc" = 0 ]; then rm -f $$o $$o.rc; break; fi; \
	if ! grep -Eq '$(APKO_NETWORK)' $$o || [ $$t -eq 4 ]; then rm -f $$o $$o.rc; exit 1; fi; \
	echo "apko could not reach the package server; trying again in $$((t * 15))s" >&2; sleep $$((t * 15)); done
# apko_lock CONFIG, from CONFIG's directory, where apko resolves its paths.
apko_lock = mkdir -p $(LOCK) && cd $(dir $(1)) && \
	$(call apko_retry,apko lock --arch aarch64$(,)x86_64 --output $(CURDIR)/$@ $(notdir $(1)))
, := ,

$(FORM_LOCK): $(FORM_FILES) | $(FORM_APKO)
	$(call apko_lock,$(FORM_APKO))
# Replaced only when it says something new, as howl replaces it.
$(FORM_APKO): $(FORM_FILES) $(FORM_TOOL)
	mkdir -p $(dir $@) && $(FORM_TOOL) apko $(FORM_REF) $(if $(DEV),$(DEV_PACKAGES)) >$@.tmp && \
		{ cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@; }
$(LOCK)/kernel.lock.json: boot/kernel.yaml
	$(call apko_lock,$<)
$(LOCK)/boot.lock.json: boot/boot.yaml
	$(call apko_lock,$<)

relock:
	rm -f $(LOCKS)
	$(MAKE) --no-print-directory FORM=$(FORM) $(LOCKS)

# --- programs -----------------------------------------------------------------
# werewolf's programs, cmd/NAME and a form's own forms/F/cmd/NAME, each
# built into a directory of its own under PROGRAMS, which howl lays into
# images (docs/programs.md). Zig is pre-1.0, so the build insists on the
# version the code is written for.
ZIG_VERSION = 0.17.0
PROGRAMS = build/$(ARCH)/programs
CMDS := $(filter-out howl,$(patsubst cmd/%/,%,$(wildcard cmd/*/)))
# program_bin NAME: where cmd/NAME is built; form_bin DIR: where a form's
# own program, F/cmd/P, is.
program_bin = $(PROGRAMS)/$(1)/$(or $(PROGRAM_AT_$(1)),usr/lib/werewolf/$(1))
PROGRAM_AT_init = init
PROGRAM_AT_stage0 = init
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

# The libraries a program may import (lib/README.md), and boot/gpt.zig, the
# boot disk's partition table, compiled with it as ReleaseSafe; a library
# imports another as its --dep says.
LIB_MODULES = --dep seal -Msandbox=lib/sandbox.zig -Mbroker=lib/broker.zig -Mdm=lib/dm.zig \
	-Mverity=lib/verity.zig -Mseal=lib/seal.zig -Msettings=lib/settings.zig \
	-Mupdate-policy=lib/update-policy.zig -Mnetwork=lib/network.zig -Mhostkey=lib/hostkey.zig \
	--dep allow --dep sshd -Mform=lib/form.zig --dep seal -Maudit=lib/audit.zig \
	--dep seal --dep settings -Mservice=lib/service.zig -Mallow=lib/allow.zig -Mcve=lib/cve.zig \
	--dep network -Mcmdline=lib/cmdline.zig --dep settings -Msshd=lib/sshd.zig \
	--dep form --dep seal --dep service -Mcompose=lib/compose.zig -Mpackage=lib/package.zig \
	-Mimage=lib/image.zig -Mgpt=boot/gpt.zig
ZIG_MODULES = --dep sandbox --dep broker --dep dm --dep verity --dep seal --dep settings \
	--dep update-policy --dep network --dep hostkey --dep form --dep audit --dep service \
	--dep allow --dep cve --dep cmdline --dep sshd --dep compose --dep package --dep image \
	--dep gpt -Mroot=$(1) $(LIB_MODULES)

# program NAME, BINARY, DIR: the rule that builds DIR, cmd/NAME unless
# given, into BINARY.
define program
$(2): $(or $(3),cmd/$(1))/$(1).zig $$(wildcard $(or $(3),cmd/$(1))/*.zig) $$(wildcard lib/*.zig)
	$$(zig_check)
	zig build-exe -O ReleaseSafe -fstrip -target $$(ARCH)-linux-musl $$(call ZIG_MODULES,$$<) -femit-bin=$$@
endef
$(foreach p,$(filter-out popen-shim,$(CMDS)),$(eval $(call program,$(p),$(call program_bin,$(p)))))
$(foreach c,$(FORM_CMDS),$(eval $(call program,$(notdir $(c)),$(call form_bin,$(c)),$(c))))
# pg-init preloads popen-shim.so into initdb in place of a shell, so it is
# built against glibc, as initdb is.
$(call program_bin,popen-shim): cmd/popen-shim/popen-shim.zig
	$(zig_check)
	zig build-lib -dynamic -O ReleaseSafe -fstrip -target $(ARCH)-linux-gnu -lc -femit-bin=$@ $<

# Every program: what howl has make compile before it builds an image. A
# form outside forms/ adds its own.
programs: $(foreach p,$(CMDS),$(call program_bin,$(p))) $(foreach c,$(FORM_CMDS),$(call form_bin,$(c)))

VERITY_BIN = build/host/verity
$(VERITY_BIN): tools/verity.zig lib/verity.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe --dep verity -Mroot=$< -Mverity=lib/verity.zig -femit-bin=$@

# The howl command, for this machine, not the image. Built beside itself and
# renamed over it, under a name of the shell's pid: a build while it runs
# (a check rebuilds it) never leaves an empty file, which a shell would run
# as an empty script, and two builds at once write two files.
howl: $(HOWL)
$(HOWL): cmd/howl/howl.zig $(wildcard cmd/howl/*.zig) lib/settings.zig lib/update-policy.zig \
	lib/network.zig lib/form.zig lib/allow.zig lib/service.zig lib/seal.zig lib/sshd.zig \
	lib/compose.zig lib/verity.zig lib/image.zig boot/gpt.zig
	$(zig_check)
	t=$@.$$$$ && zig build-exe -O ReleaseSafe $(call ZIG_MODULES,$<) -femit-bin=$$t && mv -f $$t $@

# howl on your PATH: in the first of INSTALL_DIRS on it that is yours to
# write, else in ~/.local/bin, with a word that it is not on your PATH. It
# runs in a werewolf checkout. Once called werewolf: that goes. install-deps
# first, order-only, so make -j keeps the order.
INSTALL_DIRS = $(HOME)/bin $(HOME)/.local/bin /usr/local/bin
$(HOWL): | $(if $(filter install,$(MAKECMDGOALS)),install-deps)
install: install-deps $(HOWL)
	@set -e; bindir=; \
	for d in $(INSTALL_DIRS); do \
		if echo "$$PATH" | tr ':' '\n' | grep -qx "$$d" && [ -d "$$d" ] && [ -w "$$d" ]; then bindir=$$d; break; fi; \
	done; \
	if [ -z "$$bindir" ]; then \
		bindir=$(HOME)/.local/bin; mkdir -p "$$bindir"; \
		echo "install: $$bindir is not on your PATH; add it"; \
	fi; \
	install -m 755 $(HOWL) "$$bindir/howl.new" && mv -f "$$bindir/howl.new" "$$bindir/howl"; \
	echo "installed $$bindir/howl"; \
	for d in $(INSTALL_DIRS); do \
		[ -x "$$d/werewolf" ] && "$$d/werewolf" 2>&1 | grep -q 'usage: werewolf build FORM' && \
			rm -f "$$d/werewolf" && echo "removed $$d/werewolf, as howl was once called"; \
	done; true

# Removes a howl that answers as this one does, never another program.
uninstall:
	@for d in $(INSTALL_DIRS); do \
		[ -x "$$d/howl" ] || continue; \
		if "$$d/howl" 2>&1 | grep -q 'usage: howl build FORM'; then \
			rm -f "$$d/howl" && echo "removed $$d/howl"; \
		else echo "uninstall: $$d/howl is another program; left it"; fi; \
	done

# A security key in software (tools/test-sk.zig), so a check logs in to a
# machine that takes security keys alone. This host's, never an image's.
TEST_SK = build/host/test-sk.so
$(TEST_SK): tools/test-sk.zig
	$(zig_check)
	t=$@.$$$$ && zig build-lib -dynamic -O ReleaseSafe -lc -femit-bin=$$t $< && mv -f $$t $@

# --- tests --------------------------------------------------------------------
# Each file's tests, a target of its own so `make -j test` runs them side by
# side, with the modules it is built with.
PROGRAM_SOURCES = $(foreach d,$(wildcard cmd/* forms/*/cmd/*),$(d)/$(notdir $(d)).zig)
TEST_SOURCES = lib/sandbox.zig lib/seal.zig lib/dm.zig lib/verity.zig lib/settings.zig \
	lib/update-policy.zig lib/network.zig lib/cmdline.zig lib/hostkey.zig lib/audit.zig \
	lib/form.zig lib/compose.zig lib/package.zig lib/allow.zig lib/service.zig lib/cve.zig lib/sshd.zig \
	lib/image.zig tools/form.zig tools/package.zig boot/gpt.zig \
	tools/cve-tiers.zig tools/test-sk.zig tools/doc-check.zig $(PROGRAM_SOURCES)
test: $(addprefix _test/,$(TEST_SOURCES)) _test/howl-smoke
	@echo "test: $(words $(TEST_SOURCES)) suites passed, and howl's lines"
_test/lib/sandbox.zig:
	zig test --dep seal -Mroot=lib/sandbox.zig -Mseal=lib/seal.zig
_test/lib/cmdline.zig:
	zig test --dep network -Mroot=lib/cmdline.zig -Mnetwork=lib/network.zig
_test/lib/audit.zig:
	zig test --dep seal -Mroot=lib/audit.zig -Mseal=lib/seal.zig
_test/lib/form.zig:
	zig test --dep allow --dep sshd -Mroot=lib/form.zig -Mallow=lib/allow.zig --dep settings \
		-Msshd=lib/sshd.zig -Msettings=lib/settings.zig
_test/lib/sshd.zig:
	zig test --dep settings -Mroot=lib/sshd.zig -Msettings=lib/settings.zig
_test/lib/service.zig:
	zig test --dep seal --dep settings -Mroot=lib/service.zig -Mseal=lib/seal.zig \
		-Msettings=lib/settings.zig
_test/tools/form.zig:
	zig test $(FORM_TOOL_MODULES)
_test/lib/compose.zig:
	zig test $(COMPOSE_MODULES)
_test/tools/package.zig:
	zig test --dep package -Mroot=tools/package.zig -Mpackage=lib/package.zig
_test/tools/cve-tiers.zig:
	zig test $(call ZIG_MODULES,tools/cve-tiers.zig)
_test/cmd/popen-shim/popen-shim.zig:
	zig test cmd/popen-shim/popen-shim.zig -lc
_test/tools/test-sk.zig:
	zig test tools/test-sk.zig -lc
_test/cmd/%.zig:
	zig test $(call ZIG_MODULES,cmd/$*.zig)
_test/forms/%.zig:
	zig test $(call ZIG_MODULES,forms/$*.zig)
_test/%.zig:
	zig test $*.zig

# The lines the README and the docs advertise, run as a user runs them, as
# far as a line goes with nothing built or booted: -h and -n.
_test/howl-smoke: $(HOWL)
	@fail() { echo "howl-smoke: $$1"; exit 1; }; \
	$(HOWL) run -h >/dev/null 2>&1 || fail "howl run -h"; \
	$(HOWL) run -n 2>&1 | grep -q 'as it is' || fail "howl run -n should name its environment's form"; \
	$(HOWL) run --on qemu -n 2>&1 | grep -q 'prod-ssh as it is' || fail "howl run --on qemu -n should be prod-ssh"; \
	$(HOWL) run --on qemu -h >/dev/null 2>&1 || fail "howl run --on qemu -h"; \
	$(HOWL) create smoke --with prod -h >/dev/null 2>&1 || fail "howl create smoke --with prod -h"; \
	$(HOWL) create web --with python --app ./myapp -h >/dev/null 2>&1 || fail "README: howl create web --with python --app ./myapp"; \
	$(HOWL) run --with webshell-example -n 2>&1 | grep -q 'as it is' || fail "README: howl run --with webshell-example"; \
	$(HOWL) run --with example-go -n 2>&1 | grep -q 'as it is' || fail "examples: howl run --with example-go"; \
	$(HOWL) create web --with example-python --on gcp -h >/dev/null 2>&1 || fail "examples: howl create web --with example-python --on gcp"; \
	$(HOWL) pack --with prod -h >/dev/null 2>&1 || fail "howl pack --with prod -h"; \
	out=$$($(HOWL) run --with caddy,valkey -n 2>&1) || fail "howl run --with caddy,valkey -n: $$out"; \
	echo "$$out" | grep -q 'with: \[caddy, valkey\]' || fail "run --with caddy,valkey -n did not show the form: $$out"; \
	out=$$($(HOWL) run --with caddy -n 2>&1) || fail "howl run --with caddy -n: $$out"; \
	echo "$$out" | grep -q 'as it is' || fail "one form alone should run as it is: $$out"; \
	rm -rf $(BUILD)/adhoc/smoke; \
	$(HOWL) form --with caddy --package curl -o $(BUILD)/adhoc/smoke -n >/dev/null 2>&1 || fail "howl form -n"; \
	[ ! -e $(BUILD)/adhoc/smoke ] || fail "form -n left $(BUILD)/adhoc/smoke"; \
	! $(HOWL) run caddy >/dev/null 2>&1 || fail "howl run caddy (a positional form) was taken"; \
	! $(HOWL) _build --with minimal --disk-args x slot >/dev/null 2>&1 || fail "_build took --disk-args without disk"; \
	echo "howl-smoke: the advertised lines take their forms"

# posture (docs/posture.md) assumes nothing of werewolf: run here, as root,
# it says how this Linux protects itself. Elsewhere, a binary to copy over.
posture: $(POSTURE_BIN)
ifeq ($(HOST_OS)-$(HOST_ARCH),Linux-$(ARCH))
	$(if $(filter 0,$(shell id -u)),,sudo) $(POSTURE_BIN)
else
	@echo "$(POSTURE_BIN): copy it to a Linux $(ARCH) machine and run it there, as root"
endif

# werewolf's programs as apk packages (lib/package.zig;
# docs/design/custom-updates.md), versioned by HEAD's commit time, with
# APKINDEX.member, the bytes a key holder signs. Nothing here holds a key.
PACKAGE_TOOL = build/host/package
PACKAGES = $(BUILD)/packages
PACKAGE_TIME ?= $(shell git log -1 --format=%ct 2>/dev/null)
PACKAGE_PROGRAMS = $(filter-out stage0,$(CMDS))
$(PACKAGE_TOOL): tools/package.zig lib/package.zig
	$(zig_check)
	zig build-exe -O ReleaseSafe --dep package -Mroot=$< -Mpackage=lib/package.zig -femit-bin=$@
packages: $(PACKAGE_TOOL) programs
	@[ -n "$(PACKAGE_TIME)" ] || { echo "packages: no commit time; set PACKAGE_TIME" >&2; exit 1; }
	rm -rf $(PACKAGES)/$(ARCH) && mkdir -p $(PACKAGES)/$(ARCH)
	for p in $(PACKAGE_PROGRAMS); do \
		$(PACKAGE_TOOL) pack $(PACKAGES)/$(ARCH) $(PROGRAMS)/$$p werewolf-$$p - $(ARCH) $(PACKAGE_TIME) \
			"werewolf's $$p (cmd/$$p)" || exit 1; \
	done
	$(PACKAGE_TOOL) index $(PACKAGES)/$(ARCH) -
	@echo "packages: $(words $(PACKAGE_PROGRAMS)) in $(PACKAGES)/$(ARCH); sign APKINDEX.member, then build/host/package sign"

# The CVE tiers feed (docs/design/update-policy.md), which CI builds and
# signs with release/tiers; here, unsigned, in build/tiers. NVD's scores
# stay in build/tiers/nvd, so a second run asks only for what changed. The
# key never reaches the command line make prints.
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

# On the machine to take over: build its slot and install it with bite -i,
# which opens a shell in the new root and offers to reboot into it
# (docs/bite.md). config/, if there is one, joins the config tar.
ifneq ($(filter bite-me,$(MAKECMDGOALS)),)
ifneq ($(HOST_OS)-$(HOST_ARCH),Linux-$(ARCH))
$(error bite-me runs on the Linux $(ARCH) machine it takes over)
endif
endif
bite-me: slot
	$(if $(filter 0,$(shell id -u)),,sudo) ./bite -i $(if $(wildcard config/*),--config config) $(OUT)/slot

list-forms:
	@$(FORM_TOOL) tree

# --- release ------------------------------------------------------------------
# CI publishes these forms for both arches (docs/releases.md); lib/compose.zig
# names them. release-inputs resolves their locks afresh and digests what a
# release is built from; CI builds only when that changes. dist writes each
# form's files as a release names them, with its manifest, unsigned, pinned
# (FREEZE=1) to those locks, so the two runners of an arch match byte for
# byte. minimal is released whole, for direct boot, without a disk.
RELEASE_FORMS = $(shell $(FORM_ASK) released)
DIST_DIRECT_FORMS = minimal
DIST = dist
RELEASE_SOURCES = Makefile melange.mk forms boot cmd lib tools/form.zig release/image.pub release/tiers.pub release/advisories
RELEASE_LOCKS = $(addprefix $(LOCK)/,$(addsuffix .lock.json,$(RELEASE_FORMS) kernel boot))
release-inputs:
	rm -f $(RELEASE_LOCKS)
	$(MAKE) --no-print-directory -j $(addprefix _lock/,$(RELEASE_FORMS)) $(LOCK)/kernel.lock.json $(LOCK)/boot.lock.json
	{ echo "tree $$(src='$(RELEASE_SOURCES)'; \
		{ find $$src -type f ! -name .DS_Store | LC_ALL=C sort | xargs $(SHA256); \
		  find $$src -type f -perm -100 | LC_ALL=C sort; } | $(SHA256) | cut -c1-64)"; \
	  sed -n 's|.*"url": "\([^"]*\.apk\)".*|\1|p' \
		$(RELEASE_LOCKS) | LC_ALL=C sort -u; \
	} > $(LOCK)/inputs
	@echo "inputs: $$($(SHA256) < $(LOCK)/inputs | cut -c1-16), $$(grep -c '^https' $(LOCK)/inputs) packages"
_lock/%:
	@$(MAKE) --no-print-directory FORM=$* $(LOCK)/$*.lock.json

dist:
	for f in $(RELEASE_FORMS); do $(MAKE) --no-print-directory FREEZE=1 FORM=$$f _dist-form || exit 1; done

# howl build writes build/ARCH, and never a DEV or APP build.
_dist-form: $(HOWL)
	@[ "$(BUILD)" = build/$(ARCH) ] && [ -z "$(DEV)$(APP)" ] || \
		{ echo "_dist-form: a release builds in build/$(ARCH), without DEV or APP (howl build --app)" >&2; exit 1; }
	FREEZE=$(FREEZE) $(HOWL) build --verbose --with $(FORM_REF) --arch $(ARCH) -o $(DIST)

# --- checks -------------------------------------------------------------------
# `make check` boots every form under QEMU, then a slot as bite leaves one,
# and runs test/checks on each as root on its console (test/boot). Each
# machine gets a blank disk and a config disk of its own, and nothing
# listens on the host, so `make -j check` runs them side by side. The config
# holds data.key, a fixed test key, and what form.yaml's check and the
# form's test/config say. Logs are in build/ARCH/check (docs/testing.md).
ifeq ($(ARCH),aarch64)
MACHINE = virt
CONSOLE = ttyAMA0
else
MACHINE = q35
CONSOLE = ttyS0
endif
# Without /dev/kvm (some CI runners), and on FreeBSD, QEMU emulates; NetBSD
# accelerates with NVMM once loaded: experimental.
ifeq ($(ARCH),$(HOST_ARCH))
ACCEL = $(if $(filter Darwin,$(HOST_OS)),hvf,$(if $(wildcard /dev/kvm),kvm,$(if $(wildcard /dev/nvmm),nvmm,tcg)))
CPU = $(if $(filter tcg,$(ACCEL)),max,host)
else
ACCEL = tcg
CPU = max
endif
# Given EL2, an aarch64 guest starts its own KVM unless told not to
# (kvm-arm.mode=none), so the checks boot with EL2 wherever the host can
# lend it, and posture proves the argument holds. QEMU, started paused and
# told to quit, says in milliseconds whether it can.
EL2 = $(if $(filter aarch64,$(ARCH)),$(shell echo quit | qemu-system-aarch64 -M virt,virtualization=on -accel $(ACCEL) -cpu $(CPU) -nodefaults -display none -monitor stdio -S >/dev/null 2>&1 && echo ,virtualization=on))
QEMU = qemu-system-$(ARCH) -M $(MACHINE)$(EL2) -accel $(ACCEL) -cpu $(CPU) -nographic

FORMS := $(patsubst forms/%/apko.yaml,%,$(wildcard forms/*/apko.yaml))
CHECK = $(BUILD)/check$(if $(SEAL_LEARN),-learn)
# Every form is checked built with DEV=1, as test/checks needs a root shell
# on the console, and booted as it ships (check-shellfree-%), where its
# posture may fail only as its form.yaml's weaknesses excuse.
CHECK_MAKE = $(MAKE) --no-print-directory DEV=1
SHELLFREE_FORMS = $(FORMS)
SHELLFREE_CHECKS = $(addprefix check-shellfree-,$(SHELLFREE_FORMS))
# 1 GB keeps a form's memory honest, unless its check's memory says more. A
# form whose check is offline (restrict=on) has no way out, as a daemon
# that would reach its service on the Internet and exit when refused.
# romfile=: direct boot needs no network boot ROM, and CI has none.
CHECK_MEMORY := $(or $(call form_check,memory),1024)
CHECK_OFFLINE := $(if $(filter true,$(call form_check,offline)),$(,)restrict=on)
CHECK_QEMU = $(QEMU) -smp 2 -m $(CHECK_MEMORY) -no-reboot -device virtio-rng-pci \
	-netdev user,id=n0$(CHECK_OFFLINE) -device virtio-net-pci,netdev=n0,romfile=
# panic=1 with -no-reboot ends QEMU at a panic, and a stall panics, so a run
# fails in seconds with the kernel's reason. werewolf.check=1 adds
# posture's attacks. Only here: a machine in use rides out a slow moment.
CHECK_STALLS = rcupdate.rcu_cpu_stall_timeout=20 sysctl.kernel.panic_on_rcu_stall=1 \
	sysctl.kernel.hung_task_timeout_secs=120 sysctl.kernel.hung_task_panic=1 sysctl.kernel.softlockup_panic=1
# SEAL_LEARN=1 (make seal-learn): what no promise allows is allowed, and said.
SEAL_ARGS = $(if $(SEAL_LEARN),werewolf.seal=learn)
CHECK_BOOT = console=$(CONSOLE) $(KERNEL_ARGS) panic=1 werewolf.debug=1 werewolf.check=1 $(CHECK_STALLS) $(SEAL_ARGS)
CHECK_CMDLINE = $(CHECK_BOOT) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3
# The posture checks test/boot expects to fail: test/posture-known's for a
# DEV=1 or shipped build and the arch, and the form's weaknesses.
POSTURE_KNOWN_KIND := $(shell awk -v b=$(if $(DEV),dev,*) -v a=$(ARCH) '$$1 == b || $$1 == a { $$1 = ""; k = k $$0 } END { print k }' test/posture-known)
export POSTURE_KNOWN := $(POSTURE_KNOWN_KIND) $(shell $(FORM_ASK) weaknesses $(FORM_REF))
# Those test/cage expects to fail in a container too, which shares the
# host's kernel and has nspawn's mounts (CAGE_HARDEN_HOST=1 raises the
# host's sysctls where it may).
export POSTURE_KNOWN_NATIVE = files-root-readonly files-root-verity files-nosuid-everywhere files-noexec-everywhere files-nodev-everywhere files-nosymfollow-everywhere files-system-writes processes-mem-attack
# built NAME, COMMAND: COMMAND, its output in CHECK/NAME-build.log, whose
# tail a failure shows.
built = $(2) >$(CHECK)/$(1)-build.log 2>&1 || \
	{ tail -n 20 $(CHECK)/$(1)-build.log; echo "FAIL   $(1) build: see $(CHECK)/$(1)-build.log"; exit 1; }
# What every check shares, built once before forms build side by side: howl,
# the software security key, the programs, the kernel and stage0's /init,
# with minimal's DEV=1 image, which half the checks boot.
CHECK_SHARED = _check-shared
_check-shared: $(HOWL) $(TEST_SK)
	@mkdir -p $(CHECK)
	@$(call built,shared,$(MAKE) --no-print-directory FORM=minimal DEV=1 APP= image)
# minimal has no updater, which would fetch from the network once committed.
CHECK_SLOT_FORM = minimal
VICTIM_UUID = 0e7e1f00-c4ec-4b00-8000-00000000c4ec
# debugfs, from e2fsprogs, which Homebrew keeps off the PATH.
DEBUGFS = $(firstword $(shell command -v debugfs) $(wildcard /opt/homebrew/opt/e2fsprogs/sbin/debugfs /usr/local/opt/e2fsprogs/sbin/debugfs))

# Groups, so CI (.github/workflows/check.yml) runs each as a job and a
# failure names its area. SHARD=K/N runs the Kth of N slices of forms,
# shellfree and native: every Nth form from the Kth, in name order.
ifneq ($(SHARD),)
ifeq ($(shell echo '$(SHARD)' | awk -F/ '/^[1-9][0-9]*\/[1-9][0-9]*$$/ && $$1 <= $$2'),)
$(error SHARD=$(SHARD): K/N, the Kth of N, 1 <= K <= N)
endif
endif
shard = $(if $(SHARD),$(shell echo $(sort $(1)) | tr ' ' '\n' | \
	awk -F/ -v s=$(SHARD) 'BEGIN { split(s, a, "/") } (NR - 1) % a[2] == a[1] - 1'),$(1))
check-forms:     $(addprefix check-,$(call shard,$(FORMS)))
check-shellfree: $(addprefix check-shellfree-,$(call shard,$(SHELLFREE_FORMS)))
check-integrity: check-slot check-unsigned check-verity check-deadman
# The ad-hoc form pulls its OCI image; not on emulated arm64, too slow there.
check-cloud:     check-metadata check-nodata check-lease check-static $(if $(filter aarch64-tcg,$(ARCH)-$(ACCEL)),,check-adhoc)
check: check-forms check-shellfree check-integrity check-cloud check-persist
	@echo "check: every form, and a slot, passed"

# Each form's root under systemd-nspawn on this kernel, no VM, judged by its
# posture (test/cage): the fast half of the arm64 checks, as built to ship.
# A form's form.yaml may say `check: native: false`, and why.
NATIVE_FORMS := $(filter-out $(shell $(FORM_ASK) having native false),$(FORMS))
NATIVE_CHECKS = $(addprefix check-native-,$(NATIVE_FORMS))
.PHONY: $(NATIVE_CHECKS)
check-native: $(addprefix check-native-,$(call shard,$(NATIVE_FORMS)))
$(NATIVE_CHECKS): check-native-%: | $(CHECK_SHARED)
	@mkdir -p $(CHECK)
	@$(call built,$*-native,$(MAKE) --no-print-directory FORM=$* DEV= slot)
	@$(MAKE) --no-print-directory FORM=$* DEV= _check-native
_check-native:
	@test/cage $(FORM) $(OUT)/slot/root.erofs $(CHECK)/$(FORM)-native.log

# What the forms' services need that their pledges do not promise: the
# checks' boots, learning (docs/design/pledge.md), then each call once.
SEAL_LEARN_CHECKS = $(addprefix check-,$(FORMS)) check-slot check-persist check-nodata check-lease check-static check-unsigned check-metadata
seal-learn: | $(CHECK_SHARED)
	-@$(MAKE) --no-print-directory -k SEAL_LEARN=1 $(SEAL_LEARN_CHECKS)
	@grep -aho 'seal-watch: {"event":"learned"[^}]*}' $(BUILD)/check-learn/*.log | \
		sed 's/.*"call":"\([^"]*\)","promise":"\([^"]*\)","service":"\([^"]*\)","exe":"\([^"]*\)".*/\3 \2 \1 \4/' | \
		LC_ALL=C sort -u | awk 'BEGIN { print "service promise call program" } { print }' | column -t

# make check-one FORM=prod REPEAT=20: a flake chased, each failing boot's
# console kept as FORM-one-N.log; ACCEL=tcg rules the hypervisor out.
REPEAT ?= 10
check-one: | $(CHECK_SHARED)
	@mkdir -p $(CHECK)
	@$(call built,$(FORM),$(CHECK_MAKE) FORM=$(FORM) image)
	@failed=0; for i in $$(seq $(REPEAT)); do \
		$(CHECK_MAKE) FORM=$(FORM) _check-form >$(CHECK)/$(FORM)-one.out 2>&1 || { \
			failed=$$((failed + 1)); cp $(CHECK)/$(FORM).log $(CHECK)/$(FORM)-one-$$i.log; \
			echo "boot $$i of $(REPEAT):"; grep -E -A6 '^FAIL' $(CHECK)/$(FORM)-one.out | head -8; }; \
	done; echo "$(FORM): $$failed of $(REPEAT) boots failed"; [ $$failed -eq 0 ]

check-%: | $(CHECK_SHARED)
	@mkdir -p $(CHECK)
	@$(call built,$*,$(CHECK_MAKE) FORM=$* image)
	@$(CHECK_MAKE) FORM=$* _check-form

# An ad-hoc form (docs/design/adhoc.md): a stock OCI image, pulled with crane.
check-adhoc: $(HOWL) | $(CHECK_SHARED)
	@mkdir -p $(CHECK) && rm -rf $(BUILD)/adhoc/check-oci
	@$(HOWL) form --with prod --oci web=cgr.dev/chainguard/nginx --web.listen tcp/8080 --web.write /var/lib/nginx/tmp -o $(BUILD)/adhoc/check-oci >$(CHECK)/check-oci-form.log 2>&1 || \
		{ tail -n 20 $(CHECK)/check-oci-form.log; echo "FAIL   check-oci form: see $(CHECK)/check-oci-form.log"; exit 1; }
	@$(call built,check-oci,$(CHECK_MAKE) FORM=$(BUILD)/adhoc/check-oci image)
	@$(CHECK_MAKE) FORM=$(BUILD)/adhoc/check-oci _check-form

# A form that serves ssh gives root two keys, a key file and the software
# security key's: one that takes security keys alone must log the second in
# and refuse the first (test/boot). CHECK_KEPT_KEYS: made already, baked in.
# check_keys PREFIX: PREFIX-key and PREFIX-sk-key.
check_keys = rm -f $(1)-key $(1)-key.pub $(1)-sk-key $(1)-sk-key.pub && \
	ssh-keygen -q -t ed25519 -N '' -C werewolf-check -f $(1)-key && \
	ssh-keygen -q -t ed25519-sk -w $(CURDIR)/$(TEST_SK) -N '' -C werewolf-check-sk -f $(1)-sk-key
_check-form: $(HOWL) $(TEST_SK)
	@rm -f $(CHECK)/$(FORM).img && dd if=/dev/zero of=$(CHECK)/$(FORM).img bs=1048576 count=0 seek=1024 2>/dev/null
	@rm -rf $(CHECK)/$(FORM)-config && mkdir -p $(CHECK)/$(FORM)-config && \
		head -c 64 /dev/zero | tr '\0' k >$(CHECK)/$(FORM)-config/data.key && \
		$(if $(CHECK_SSH),$(if $(CHECK_KEPT_KEYS),,$(call check_keys,$(CHECK)/$(FORM)) &&) \
			cat $(CHECK)/$(FORM)-key.pub $(CHECK)/$(FORM)-sk-key.pub >$(CHECK)/$(FORM)-config/authorized_keys &&) \
		$(if $(wildcard $(FORM_DIR)/test/config),$(FORM_DIR)/test/config $(CHECK)/$(FORM)-config &&) \
		$(HOWL) pack --with $(FORM_REF) -o $(CHECK)/$(FORM)-config.tar --config $(CHECK)/$(FORM)-config >/dev/null
	@awk '$(foreach c,$(call form_check,skip),$$2 != "$(c)" &&) 1' test/checks $(wildcard $(FORM_DIR)/test/checks) >$(CHECK)/$(FORM)-checks
	@SSH_MODE=$(FORM) SSH_PORT=$(CHECK_SSH) SSH_KEY=$(CHECK)/$(FORM)-key SSH_SK_KEY=$(CHECK)/$(FORM)-sk-key SSH_SK_PROVIDER=$(CURDIR)/$(TEST_SK) GITEA_PORT=$(CHECK_WEB) test/boot $(FORM) $(CHECK)/$(FORM)-checks $(CHECK)/$(FORM).log $(CHECK_FORM_QEMU)
	@$(if $(filter $(AGAIN_FORMS),$(FORM)),$(CHECK_MAKE) FORM=$(FORM) _check-form-again,:)

# The second boot, from the disk the first left, for forms chosen for what
# they keep: minimal nothing, sshd a host key, prod-ssh one under an
# updater, gitea and vaultwarden an application's data, demo PostgreSQL's.
# AGAIN_FORMS=all boots every form twice.
AGAIN_FORMS ?= minimal sshd prod-ssh gitea vaultwarden demo
ifeq ($(AGAIN_FORMS),all)
override AGAIN_FORMS := $(FORMS)
endif
_check-form-again:
	@SSH_MODE=$(FORM) SSH_PORT=$(CHECK_SSH) SSH_KEY=$(CHECK)/$(FORM)-key SSH_SK_KEY=$(CHECK)/$(FORM)-sk-key SSH_SK_PROVIDER=$(CURDIR)/$(TEST_SK) GITEA_PORT=$(CHECK_WEB) test/boot $(FORM)-again test/checks-again $(CHECK)/$(FORM)-again.log $(CHECK_FORM_QEMU)
	@! grep -a -E 'werewolf: (formatting|making LUKS2) ' $(CHECK)/$(FORM)-again.log || \
		{ echo "FAIL   $(FORM)-again        formatted the disk its first boot left"; exit 1; }
	@# A host key kept in /data on the first boot is the one the second offers.
	@a=$$(grep -a '"event":"host-key"' $(CHECK)/$(FORM).log | grep -a 'kept in /data' | \
		grep -ao '"fingerprint":"[^"]*"' | head -n 1); \
	b=$$(grep -a '"event":"host-key"' $(CHECK)/$(FORM)-again.log | grep -ao '"fingerprint":"[^"]*"' | head -n 1); \
	[ -z "$$a" ] || [ "$$a" = "$$b" ] || \
		{ echo "FAIL   $(FORM)-again        host key not kept: [$$a] then [$$b]"; exit 1; }

# The bastion as an operator makes one, on a form naming two users, their
# keys made here and baked in: check, root's security key in test/boot,
# reaching 127.0.0.1:22, and narrow, reaching 127.0.0.2:22, which check must
# not (forms/bastion/test/checks). An explicit rule, so check-% is not used.
CHECK_BASTION = $(CHECK)/bastion-check
CHECK_BASTION_SSH = $(shell echo $(FORMS) | tr ' ' '\n' | grep -n -x bastion | cut -d: -f1 | awk '{ print 22200 + $$1 }')
check-bastion: $(HOWL) $(TEST_SK) | $(CHECK_SHARED)
	@mkdir -p $(CHECK) && rm -rf $(CHECK_BASTION) && mkdir -p $(CHECK_BASTION)/test && \
		$(call check_keys,$(CHECK_BASTION)) && $(call check_keys,$(CHECK)/bastion-narrow) && \
		cp forms/bastion/test/checks $(CHECK_BASTION)/test/checks && \
		echo '# make check-bastion: the bastion, with two users.' >$(CHECK_BASTION)/apko.yaml && \
		{ echo 'base: bastion' && echo 'bastion:' && echo '  users:' && \
		echo '    check:' && echo "      keys: [\"$$(cut -d' ' -f1,2 $(CHECK_BASTION)-sk-key.pub)\"]" && \
		echo '      destinations: [127.0.0.1:22]' && \
		echo '    narrow:' && echo "      keys: [\"$$(cut -d' ' -f1,2 $(CHECK)/bastion-narrow-sk-key.pub)\"]" && \
		echo '      destinations: [127.0.0.2:22]' && \
		echo 'weaknesses:' && $(FORM_TOOL) excuses bastion | sed 's/^\([^ ]*\) \(.*\)/  \1: "\2"/'; \
		} >$(CHECK_BASTION)/form.yaml
	@$(call built,bastion,$(CHECK_MAKE) FORM=$(CHECK_BASTION) image)
	@$(CHECK_MAKE) FORM=$(CHECK_BASTION) CHECK_SSH=$(CHECK_BASTION_SSH) CHECK_KEPT_KEYS=1 _check-form

# Every form booted as it ships, judged by its posture line and its
# test/console. A static pattern, so check-% is not used.
$(SHELLFREE_CHECKS): check-shellfree-%: | $(CHECK_SHARED)
	@mkdir -p $(CHECK)
	@$(call built,$*-shellfree,$(MAKE) --no-print-directory FORM=$* DEV= image)
	@$(MAKE) --no-print-directory FORM=$* DEV= _check-shellfree-boot
_check-shellfree-boot:
	@rm -f $(CHECK)/$(FORM)-shellfree.img && dd if=/dev/zero of=$(CHECK)/$(FORM)-shellfree.img bs=1048576 count=0 seek=1024 2>/dev/null
	@test/boot $(FORM)-shellfree $(or $(wildcard $(FORM_DIR)/test/console),-) $(CHECK)/$(FORM)-shellfree.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_CMDLINE) werewolf.data=vda" \
		-drive file=$(CHECK)/$(FORM)-shellfree.img,format=raw,if=virtio

# A form that serves ssh is logged into from here, through port 22
# forwarded from a port of its own, and gitea's web API likewise, from a
# range of its own, so forms boot side by side.
FORM_LISTENS := $(shell $(FORM_ASK) listens $(FORM_REF))
CHECK_SSH := $(if $(filter 22,$(FORM_LISTENS)),$(shell echo $(FORMS) | tr ' ' '\n' | grep -n -x '$(FORM)' | cut -d: -f1 | awk '{ print 22200 + $$1 }'))
CHECK_WEB_PORT := $(call form_check,web)
CHECK_WEB := $(if $(CHECK_WEB_PORT),$(shell echo $(FORMS) | tr ' ' '\n' | grep -n -x '$(FORM)' | cut -d: -f1 | awk '{ print 23200 + $$1 }'))
CHECK_FORM_QEMU = $(if $(CHECK_SSH),$(subst user$(,)id=n0,user$(,)id=n0$(,)hostfwd=tcp:127.0.0.1:$(CHECK_SSH)-:22$(if $(CHECK_WEB),$(,)hostfwd=tcp:127.0.0.1:$(CHECK_WEB)-:$(CHECK_WEB_PORT)),$(CHECK_QEMU)),$(CHECK_QEMU)) \
	-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_CMDLINE) werewolf.data=vda" \
	-drive file=$(CHECK)/$(FORM).img,format=raw,if=virtio \
	-drive file=$(CHECK)/$(FORM)-config.tar,format=raw,if=virtio,readonly=on

# The checks below boot what a form's own check built, so they follow it.
# prod with no werewolf.ip: its address from QEMU's DHCP server.
check-lease: | $(CHECK_SHARED) check-prod
	@$(CHECK_MAKE) FORM=prod _check-lease-boot
_check-lease-boot:
	@test/boot lease test/checks-lease $(CHECK)/lease.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_BOOT)"
	@grep -a -q 'dhcp-client: {.*"event":"bound"' $(CHECK)/lease.log || \
		{ echo "FAIL   lease              no \"bound\" event on the console"; exit 1; }

# minimal, which has no DHCP client: its address from the config tar's
# network file, as howl pack --ip writes it.
check-static: | $(CHECK_SHARED) check-minimal
	@$(CHECK_MAKE) FORM=minimal _check-static-boot
_check-static-boot: $(HOWL)
	@$(HOWL) pack --with minimal -o $(CHECK)/static-config.tar \
		--ip 10.0.2.15/24 --gw 10.0.2.2 --dns 10.0.2.3 >/dev/null
	@test/boot static test/checks-static $(CHECK)/static.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_BOOT)" \
		-drive file=$(CHECK)/static-config.tar,format=raw,if=virtio,readonly=on

# A root image changed after its build must not boot: stage0 must refuse
# minimal's root.erofs with one byte of its superblock changed, before erofs
# uses it. dm-verity's own line varies by kernel, so it is checked loosely.
check-verity: | $(CHECK_SHARED) check-minimal
	@$(CHECK_MAKE) FORM=minimal _check-verity-boot
_check-verity-boot:
	@rm -rf $(CHECK)/verity && mkdir -p $(CHECK)/verity && cp $(OUT)/slot/root.erofs $(CHECK)/verity/ && \
		printf x | dd of=$(CHECK)/verity/root.erofs bs=1 seek=1024 conv=notrunc 2>/dev/null && \
		(cd $(CHECK)/verity && $(TAR) -cf - --format newc --uid 0 --gid 0 --numeric-owner root.erofs) | \
		zstd -1 -q -c | cat $(OUT)/slot/stage0.zst - >$(CHECK)/verity.zst && rm -r $(CHECK)/verity
	@! test/boot verity - $(CHECK)/verity.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(CHECK)/verity.zst -append "$(CHECK_CMDLINE)" >/dev/null
	@grep -a -q 'stage0: cannot mount /root.erofs' $(CHECK)/verity.log || \
		{ echo "FAIL   verity             stage0 did not refuse the changed image; see $(CHECK)/verity.log"; exit 1; }
	@! grep -a -q 'handing over to runit' $(CHECK)/verity.log || \
		{ echo "FAIL   verity             the changed image booted; see $(CHECK)/verity.log"; exit 1; }
	@grep -a -E -q 'device-mapper: verity:.* corrupted|cannot read erofs superblock' $(CHECK)/verity.log || \
		{ echo "FAIL   verity             no dm-verity corruption reported; see $(CHECK)/verity.log"; exit 1; }
	@echo "pass   verity             a changed root image does not boot"

# A slot that boots but never commits is taken back: stage0's deadman, 20 s
# here (werewolf.deadman, which only a DEV build takes), reboots it and says
# why, with no loader named, so nothing commits. After check-slot, which
# builds the same slot in the same place.
check-deadman: | $(CHECK_SHARED) check-$(CHECK_SLOT_FORM) check-slot
	@mkdir -p $(CHECK)
	@$(call built,deadman,$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) DEV=1 slot)
	@$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) DEV=1 _check-deadman-boot
_check-deadman-boot:
	@rm -rf $(CHECK)/deadman $(CHECK)/deadman.img && mkdir -p $(CHECK)/deadman/var/lib/werewolf/a && \
		cp $(OUT)/slot/root.erofs $(CHECK)/deadman/var/lib/werewolf/a/ && \
		mke2fs -q -F -t ext4 -U $(VICTIM_UUID) -d $(CHECK)/deadman $(CHECK)/deadman.img 128M && rm -r $(CHECK)/deadman
	@# Not test/boot, which would check the machine and power it off.
	@timeout 180 $(CHECK_QEMU) -kernel $(OUT)/slot/vmlinuz -initrd $(OUT)/slot/stage0.zst \
		-append "$(CHECK_CMDLINE) init=/init werewolf.slot=a werewolf.victim=$(VICTIM_UUID):/var/lib/werewolf werewolf.deadman=20" \
		-drive file=$(CHECK)/deadman.img,format=raw,if=virtio </dev/null >$(CHECK)/deadman.log 2>&1; \
		[ $$? -ne 124 ] || { echo "FAIL   deadman            no reset in 180 s; see $(CHECK)/deadman.log"; exit 1; }
	@grep -a -q 'stage0: the deadman waits 20s' $(CHECK)/deadman.log || \
		{ echo "FAIL   deadman            stage0 did not take werewolf.deadman; see $(CHECK)/deadman.log"; exit 1; }
	@grep -a -q 'stage0: slot a did not commit in 20s; rebooting into the last good slot' $(CHECK)/deadman.log || \
		{ echo "FAIL   deadman            the deadman did not say why; see $(CHECK)/deadman.log"; exit 1; }
	@! grep -a -q 'reboot: Power down' $(CHECK)/deadman.log || \
		{ echo "FAIL   deadman            the machine powered off rather than reset; see $(CHECK)/deadman.log"; exit 1; }
	@! grep -a -q 'slot-keep: healthy' $(CHECK)/deadman.log || \
		{ echo "FAIL   deadman            the slot committed; see $(CHECK)/deadman.log"; exit 1; }
	@echo "pass   deadman            a slot that does not commit is rebooted, and says why"

# An unsigned module offered at boot is refused, by init on a RAM root and
# by stage0 on a slot: test/unsign cuts evdev's signature off, in a cpio
# the kernel unpacks last.
check-unsigned: | $(CHECK_SHARED) check-minimal check-slot
	@$(CHECK_MAKE) FORM=minimal _check-unsigned-boot
	@$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) _check-unsigned-slot
_check-unsigned-boot:
	@test/unsign $(OUT)/modules.tar evdev $(CHECK)/unsigned-$(FORM).cpio.zst
	@cat $(OUT)/initramfs.zst $(CHECK)/unsigned-$(FORM).cpio.zst >$(CHECK)/unsigned-$(FORM).zst
	@test/boot unsigned test/checks-unsigned $(CHECK)/unsigned.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(CHECK)/unsigned-$(FORM).zst -append "$(CHECK_CMDLINE)"
_check-unsigned-slot:
	@test/unsign $(OUT)/modules.tar evdev $(CHECK)/unsigned-$(FORM).cpio.zst
	@cat $(OUT)/slot/stage0.zst $(CHECK)/unsigned-$(FORM).cpio.zst >$(CHECK)/unsigned-$(FORM).zst
	@cp $(CHECK)/victim.img $(CHECK)/unsigned-victim.img
	@test/boot unsigned-slot test/checks-unsigned $(CHECK)/unsigned-slot.log $(CHECK_QEMU) \
		-kernel $(OUT)/slot/vmlinuz -initrd $(CHECK)/unsigned-$(FORM).zst \
		-append "$(CHECK_CMDLINE) init=/init werewolf.slot=a werewolf.victim=$(VICTIM_UUID):/var/lib/werewolf werewolf.grubenv=$(VICTIM_UUID):/boot/grub/grubenv" \
		-drive file=$(CHECK)/unsigned-victim.img,format=raw,if=virtio

# prod against a stand-in metadata server (test/metadata), seven ways: a
# good config on GCP, AWS, Hetzner and Azure taken, a hostile one refused
# whole, and no cloud, or Hyper-V that is not Azure, never asked
# (test/cloud-boot). arm64 guests have SMBIOS only under UEFI.
CLOUD_FIRMWARE = $(if $(filter aarch64,$(ARCH)),$(firstword $(wildcard \
	/opt/homebrew/share/qemu/edk2-aarch64-code.fd /usr/local/share/qemu/edk2-aarch64-code.fd \
	/usr/share/qemu/edk2-aarch64-code.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd)))
METADATA_QEMU = $(QEMU) -smp 2 -m 1024 -no-reboot -device virtio-rng-pci \
	-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_BOOT)"
METADATA_BOOTS = "gcp good metadata" "aws good metadata" "hetzner good metadata" "azure good metadata" \
	"gcp hostile metadata-refused" "none good metadata-refused" "hyperv good metadata-refused"
check-metadata: | $(CHECK_SHARED) check-prod
	@$(CHECK_MAKE) FORM=prod _check-metadata-boots
_check-metadata-boots:
	@[ "$(ARCH)" != aarch64 ] || [ -n "$(CLOUD_FIRMWARE)" ] || \
		{ echo "FAIL   metadata           no UEFI firmware for arm64 (edk2-aarch64-code.fd)"; exit 1; }
	@failed=0; for b in $(METADATA_BOOTS); do set -- $$b; \
		test/cloud-boot meta-$$1-$$2 $$1 $$2 test/checks-$$3 $(CHECK)/meta-$$1-$$2.log "$(CLOUD_FIRMWARE)" $(METADATA_QEMU) || failed=1; \
	done; exit $$failed

# UEFI firmware for the disk boots: aarch64's edk2 loads with -bios;
# x86_64's OVMF is read-only code and writable variables, a per-run copy so
# a boot that writes NVRAM, or a power cut mid-write, leaves the template
# be. No wait at the boot menu: arm64's edk2 counts 5 s down otherwise.
UEFI_FIRMWARE = $(firstword $(wildcard $(if $(filter aarch64,$(ARCH)), \
	/opt/homebrew/share/qemu/edk2-aarch64-code.fd /usr/local/share/qemu/edk2-aarch64-code.fd \
	/usr/share/qemu/edk2-aarch64-code.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd, \
	/opt/homebrew/share/qemu/edk2-x86_64-code.fd /usr/local/share/qemu/edk2-x86_64-code.fd \
	/usr/share/qemu/edk2-x86_64-code.fd /usr/share/ovmf/OVMF.fd)))
UEFI_VARS = $(firstword $(wildcard \
	/opt/homebrew/share/qemu/edk2-i386-vars.fd /usr/local/share/qemu/edk2-i386-vars.fd \
	/usr/share/qemu/edk2-i386-vars.fd /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd))
UEFI_VARS_COPY = $(CHECK)/ovmf-vars.fd
UEFI_FLAGS = -boot menu=on,splash-time=0 $(if $(filter aarch64,$(ARCH)),-bios $(UEFI_FIRMWARE),\
	-drive if=pflash,format=raw,unit=0,readonly=on,file=$(UEFI_FIRMWARE) \
	-drive if=pflash,format=raw,unit=1,file=$(UEFI_VARS_COPY))
uefi-vars = $(if $(filter aarch64,$(ARCH)),:,cp $(UEFI_VARS) $(UEFI_VARS_COPY))

# The release's disks, booted as published after `make dist`, under UEFI,
# judged by the posture line on the serial port. -snapshot leaves the bytes
# be; a network with no way out keeps the updater from replacing them. Not
# on emulated arm64, where edk2 never reaches systemd-boot in time.
DIST_DISK_QEMU = qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -nographic \
	-smp 2 -m 2048 -snapshot -no-reboot $(UEFI_FLAGS) -device virtio-rng-pci \
	-netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0,romfile=
check-dist:
ifeq ($(ARCH)-$(ACCEL),aarch64-tcg)
	@echo "skip   dist               emulated arm64 (no EL2): UEFI boot too slow; x86_64 covers it"
else
	@failed=0; for f in $(filter-out $(DIST_DIRECT_FORMS),$(RELEASE_FORMS)); do \
		$(MAKE) --no-print-directory FORM=$$f _check-dist-disk || failed=1; \
	done; exit $$failed
endif
_check-dist-disk:
	@[ -n "$(UEFI_FIRMWARE)" ] || { echo "FAIL   dist-$(FORM)     no UEFI firmware for $(ARCH) (edk2 or OVMF)"; exit 1; }
	@[ "$(ARCH)" = aarch64 ] || [ -n "$(UEFI_VARS)" ] || { echo "FAIL   dist-$(FORM)     no UEFI variables template for $(ARCH)"; exit 1; }
	@[ -f $(DIST)/$(FORM)-$(ARCH)-disk.qcow2 ] || \
		{ echo "FAIL   dist-$(FORM)     no $(DIST)/$(FORM)-$(ARCH)-disk.qcow2: make dist first"; exit 1; }
	@mkdir -p $(CHECK)
	@$(uefi-vars)
	@test/boot dist-$(FORM) - $(CHECK)/dist.log $(DIST_DISK_QEMU) \
		-drive file=$(DIST)/$(FORM)-$(ARCH)-disk.qcow2,format=qcow2,if=virtio

# prod-ssh on a real cloud as howl create makes it (test/cloud): an image, a
# machine judged from its serial port and an ssh login, a second create with
# a new config, then all of it deleted. Each needs its CLI logged in and
# costs a few cents; not part of check.
check-gcp check-aws check-azure: check-%:
	@$(MAKE) --no-print-directory FORM=prod-ssh CLOUD=$* _check-cloud
_check-cloud: $(HOWL)
	@test/cloud $(CLOUD) $(FORM) $(ARCH)

# prod's LUKS2 disk, as its own check left it, booted with no data.key:
# refused, not formatted again.
check-nodata: | $(CHECK_SHARED) check-prod
	@$(CHECK_MAKE) FORM=prod _check-nodata-boot
_check-nodata-boot:
	@cp $(CHECK)/prod.img $(CHECK)/nodata.img
	@test/boot nodata test/checks-nodata $(CHECK)/nodata.log $(CHECK_QEMU) \
		-kernel $(BUILD)/vmlinuz -initrd $(OUT)/initramfs.zst -append "$(CHECK_CMDLINE) werewolf.data=vda" \
		-drive file=$(CHECK)/nodata.img,format=raw,if=virtio

# The slot path, as bite leaves it: stage0 finding root.erofs by filesystem
# UUID on a small ext4 victim, /victim read-only, bite-cleanup deleting the
# distro beside it, and commit making the slot GRUB's default.
check-slot: | $(CHECK_SHARED) check-$(CHECK_SLOT_FORM)
	@mkdir -p $(CHECK)
	@$(call built,slot,$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) slot)
	@$(CHECK_MAKE) FORM=$(CHECK_SLOT_FORM) _check-slot-boot
_check-slot-boot:
	@rm -rf $(CHECK)/victim $(CHECK)/victim.img
	@mkdir -p $(CHECK)/victim/var/lib/werewolf/a $(CHECK)/victim/boot/grub $(CHECK)/victim/boot/werewolf/a
	@cp $(OUT)/slot/root.erofs $(CHECK)/victim/var/lib/werewolf/a/
	@# A stand-in for the kernel bite lays beside GRUB's directory.
	@echo kernel >$(CHECK)/victim/boot/werewolf/a/vmlinuz
	@# A distro: what bite-cleanup must delete, a name that only begins like
	@# one it keeps, links that lead out, and (below) a file it may not delete.
	@v=$(CHECK)/victim; mkdir -p $$v/etc $$v/home/user/.ssh $$v/var/log $$v/var/lib/werewolf2 && \
		echo ID=debian >$$v/etc/os-release && echo secret >$$v/home/user/.ssh/id && echo log >$$v/var/log/syslog && \
		echo nameserver 10.0.2.3 >$$v/etc/resolv.conf && \
		touch $$v/bootx && ln -s /run/werewolf $$v/etc/escape && ln -s ../../.. $$v/var/lib/up
	@env=$(CHECK)/victim/boot/grub/grubenv; \
		printf '# GRUB Environment Block\nsaved_entry=werewolf-b\nnext_entry=werewolf-a\n' >$$env; \
		head -c $$((1024 - $$(wc -c <$$env))) /dev/zero | tr '\0' '#' >>$$env
	@mke2fs -q -F -t ext4 -U $(VICTIM_UUID) -d $(CHECK)/victim $(CHECK)/victim.img 128M
	@# resolv.conf immutable, as some cloud agents leave it.
	@d="$(DEBUGFS)"; img=$(CHECK)/victim.img; [ -n "$$d" ] || { echo "FAIL   slot               no debugfs (e2fsprogs)"; exit 1; }; \
		flags() { "$$d" -R "stat /etc/resolv.conf" $$img 2>/dev/null | sed -n 's/.*Flags: \(0x[0-9a-f]*\).*/\1/p'; }; \
		f=$$(flags); [ -n "$$f" ] && "$$d" -w -R "set_inode_field /etc/resolv.conf flags $$((f | 0x10))" $$img 2>/dev/null && \
		f=$$(flags) && [ -n "$$f" ] && [ $$((f & 0x10)) -ne 0 ] || \
		{ echo "FAIL   slot               /etc/resolv.conf not made immutable"; exit 1; }
	@test/boot slot test/checks $(CHECK)/slot.log $(CHECK_QEMU) \
		-kernel $(OUT)/slot/vmlinuz -initrd $(OUT)/slot/stage0-bitten.zst \
		-append "$(CHECK_CMDLINE) init=/init werewolf.slot=a werewolf.victim=$(VICTIM_UUID):/var/lib/werewolf werewolf.grubenv=$(VICTIM_UUID):/boot/grub/grubenv" \
		-drive file=$(CHECK)/victim.img,format=raw,if=virtio
	@grep -a -o 'saved_entry=werewolf-[ab]' $(CHECK)/victim.img | sort -u | grep -qx saved_entry=werewolf-a || \
		{ echo "FAIL   slot               GRUB's default is not werewolf-a after commit"; exit 1; }
	@echo "pass   slot               GRUB's default is werewolf-a"

# PostgreSQL's data must outlive a reboot and a power cut: the demo as it
# ships, on its own disk, booted three times under UEFI (test/checks-persist,
# -again, -cut). Without EL2: edk2 under HVF with it never reaches the boot
# manager. No way out (restrict=on), so the updater builds no slot mid-test.
# Skipped on emulated arm64, where it could only time out; x86_64 covers it.
# CI's forms jobs check demo on their own, so pass PERSIST_AFTER=.
PERSIST_QEMU = qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -nographic \
	-smp 2 -m 2048 -no-reboot -device virtio-rng-pci $(UEFI_FLAGS) \
	-netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0,romfile= \
	-drive file=$(CHECK)/persist.img,format=raw,if=virtio
PERSIST_ARGS = console=$(CONSOLE) werewolf.debug=1 werewolf.check=1 $(CHECK_STALLS) $(SEAL_ARGS)
PERSIST_AFTER ?= check-demo
check-persist: | $(CHECK_SHARED) $(PERSIST_AFTER)
ifeq ($(ARCH)-$(ACCEL),aarch64-tcg)
	@echo "skip   persist            emulated arm64 (no EL2): UEFI boot too slow; x86_64 covers it"
else
	@mkdir -p $(CHECK)
	@[ -n "$(UEFI_FIRMWARE)" ] || { echo "FAIL   persist            no UEFI firmware for $(ARCH) (edk2 or OVMF)"; exit 1; }
	@[ "$(ARCH)" = aarch64 ] || [ -n "$(UEFI_VARS)" ] || { echo "FAIL   persist            no UEFI variables template for $(ARCH) (edk2-i386-vars.fd or OVMF_VARS.fd)"; exit 1; }
	@rm -f $(CHECK)/persist.img
	@$(call built,persist,$(CHECK_MAKE) FORM=demo disk DISK=$(CHECK)/persist.img DISK_MIB=2048 DISK_ARGS="$(PERSIST_ARGS)")
	@$(CHECK_MAKE) FORM=demo _check-persist-boot
endif
_check-persist-boot:
	@$(uefi-vars)
	@test/boot persist test/checks-persist $(CHECK)/persist.log $(PERSIST_QEMU)
	@POWER_CUT=1 test/boot persist-again test/checks-persist-again $(CHECK)/persist-again.log $(PERSIST_QEMU)
	@test/boot persist-cut test/checks-persist-cut $(CHECK)/persist-cut.log $(PERSIST_QEMU)
	@echo "pass   persist            $$(grep -a -c 'pg-init: removed the lock the last boot left' $(CHECK)/persist-cut.log) stale lock(s) removed after the cut"

# check-compose: the form composed again as a machine's updater composes it
# (cmd/slot-update), from the chain its image stages, over
# wolfi-baselayout's accounts. Its ro and records must be the build's.
CHECK_COMPOSE = $(OUT)/check-compose
BASELAYOUT_URL = $(shell sed -n 's|.*"url": "\([^"]*/$(ARCH)/wolfi-baselayout-[^"]*\.apk\)".*|\1|p' $(FORM_LOCK))
check-compose: slot
	@[ -n "$(BASELAYOUT_URL)" ] || { echo "check-compose: $(FORM_LOCK) names no wolfi-baselayout" >&2; exit 1; }
	@rm -rf $(CHECK_COMPOSE) && mkdir -p $(CHECK_COMPOSE)/image/etc $(BUILD)/vendor/baselayout && \
	pkg=$(BUILD)/vendor/baselayout/$(notdir $(BASELAYOUT_URL)) && \
	{ [ -s $$pkg ] || { curl -sSfL -o $$pkg.tmp $(BASELAYOUT_URL) && mv $$pkg.tmp $$pkg; }; } && \
	for f in passwd group shadow; do $(TAR) -xzOf $$pkg etc/$$f > $(CHECK_COMPOSE)/image/etc/$$f || exit 1; done
	@cd $(OUT)/meta/usr/share/werewolf && $(abspath $(FORM_TOOL)) compose $(FORM) $(ARCH) posture-known \
		$(abspath $(CHECK_COMPOSE))/image $(abspath $(CHECK_COMPOSE))/ro $(abspath $(CHECK_COMPOSE))/meta $(if $(DEV),dev)
	@entries() { (cd $$1 && $(TAR) -cf - --format=mtree --options='!all,type,mode,link,sha256' $$2 | sed 1d | LC_ALL=C sort); }; \
	entries $(OUT)/ro . > $(CHECK_COMPOSE)/build.ro && entries $(CHECK_COMPOSE)/ro . > $(CHECK_COMPOSE)/again.ro && \
	recs=$$(cd $(CHECK_COMPOSE)/meta/usr/share/werewolf && ls) && \
	entries $(OUT)/meta/usr/share/werewolf "$$recs" > $(CHECK_COMPOSE)/build.meta && \
	entries $(CHECK_COMPOSE)/meta/usr/share/werewolf "$$recs" > $(CHECK_COMPOSE)/again.meta && \
	if diff $(CHECK_COMPOSE)/build.ro $(CHECK_COMPOSE)/again.ro && diff $(CHECK_COMPOSE)/build.meta $(CHECK_COMPOSE)/again.meta; \
	then echo "PASS   check-compose $(FORM): composed again from its staged chain, as the build made it"; \
	else echo "FAIL   check-compose $(FORM): the lines above differ (<: the build, >: composed again)"; exit 1; fi

# A whole update, over the network, so not in check (test/update): a form
# on slot a of a disk, its record claiming the kernel before its own,
# updates itself to slot b, which must boot and commit. check-updater: prod
# with DEV=1, which follows no releases, so builds from Wolfi and Alpine;
# -staged cuts the power once the update is staged; -release: prod-ssh,
# which installs CI's latest signed release.
CHECK_UPDATE = $(CHECK)/update-$(FORM)
# What the form leaves out of its packages, and mkfs.erofs's options, as
# lib/compose.zig and lib/image.zig give them to howl's build.
PRUNE = $(call form_list,prune)
EROFS_OPTS = -b 4096 -zzstd,level=9 -C65536 -Eall-fragments,dedupe
check-updater: | $(CHECK_SHARED)
	@$(MAKE) --no-print-directory FORM=prod DEV=1 _check-updater
check-updater-staged: | $(CHECK_SHARED)
	@$(MAKE) --no-print-directory FORM=prod DEV=1 STAGED=1 _check-updater
check-updater-release: | $(CHECK_SHARED)
	@$(MAKE) --no-print-directory FORM=prod-ssh _check-updater
_check-updater:
	@mkdir -p $(CHECK_UPDATE)
	@$(MAKE) --no-print-directory slot >$(CHECK_UPDATE)/build.log 2>&1 || \
		{ tail -n 20 $(CHECK_UPDATE)/build.log; echo "FAIL   update build: see $(CHECK_UPDATE)/build.log"; exit 1; }
	@$(MAKE) --no-print-directory _check-updater-boot
_check-updater-boot: $(VERITY_BIN)
	@rm -rf $(CHECK_UPDATE)/claim $(CHECK_UPDATE)/victim $(CHECK_UPDATE)/victim.img
	@mkdir -p $(CHECK_UPDATE)/claim/usr/share/werewolf $(CHECK_UPDATE)/victim/var/lib/werewolf/a $(CHECK_UPDATE)/victim/boot/grub
	@# linux-virt-6.18.55-r0 claims linux-virt-6.18.54-r0.
	@awk -F. '{ split($$3, z, "-"); if (z[1] < 1) exit 1; printf "%s.%s.%d-%s\n", $$1, $$2, z[1] - 1, z[2] }' \
		$(OUT)/meta/usr/share/werewolf/kernel >$(CHECK_UPDATE)/claim/usr/share/werewolf/kernel
	@printf '#mtree\n./ type=dir uid=0 gid=0 uname=root gname=root mode=0755 time=0.0\n' >$(CHECK_UPDATE)/root.mtree
	@$(TAR) -C $(CHECK_UPDATE)/claim -cf $(CHECK_UPDATE)/claim.tar --uid 0 --gid 0 --numeric-owner usr/share/werewolf/kernel
	@$(TAR) -cf $(CHECK_UPDATE)/root.tar --uid 0 --gid 0 --numeric-owner $(foreach p,$(PRUNE),--exclude $(p)) \
		@$(CHECK_UPDATE)/root.mtree @$(OUT)/rootfs.tar @$(OUT)/overlay.tar @$(CHECK_UPDATE)/claim.tar
	@mkfs.erofs $(EROFS_OPTS) -T0 -U 00000000-0000-0000-0000-000000000000 --tar=f \
		$(CHECK_UPDATE)/victim/var/lib/werewolf/a/root.erofs $(CHECK_UPDATE)/root.tar >/dev/null
	@rm -rf $(CHECK_UPDATE)/root.tar $(CHECK_UPDATE)/verity && mkdir -p $(CHECK_UPDATE)/verity
	@$(VERITY_BIN) $(CHECK_UPDATE)/victim/var/lib/werewolf/a/root.erofs $(CHECK_UPDATE)/verity/verity
	@env=$(CHECK_UPDATE)/victim/boot/grub/grubenv; \
		printf '# GRUB Environment Block\nsaved_entry=werewolf-b\nnext_entry=werewolf-a\n' >$$env; \
		head -c $$((1024 - $$(wc -c <$$env))) /dev/zero | tr '\0' '#' >>$$env
	@mke2fs -q -F -t ext4 -U $(VICTIM_UUID) -d $(CHECK_UPDATE)/victim $(CHECK_UPDATE)/victim.img 3G
	@# The build's stage0, then this root's /verity in a cpio of its own.
	@cp $(OUT)/slot/vmlinuz $(CHECK_UPDATE)/
	@(cd $(CHECK_UPDATE)/verity && $(TAR) -cf - --format newc --uid 0 --gid 0 --numeric-owner verity) | \
		zstd -q -c | cat $(OUT)/slot/stage0.zst - >$(CHECK_UPDATE)/stage0.zst
	@STAGED='$(STAGED)' test/update $(CHECK_UPDATE) \
		"console=$(CONSOLE) panic=1 $$(cat $(OUT)/slot/cmdline) $(SEAL_ARGS) werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3 init=/init werewolf.victim=$(VICTIM_UUID):/var/lib/werewolf werewolf.grubenv=$(VICTIM_UUID):/boot/grub/grubenv" \
		$(QEMU) -smp 2 -m 2048 -no-reboot -device virtio-rng-pci -netdev user,id=n0 -device virtio-net-pci,netdev=n0,romfile=

# CI's check job, here, in an Ubuntu VM like GitHub's runners (test/lima-ci).
ci:
	test/lima-ci

# The locks stay: they make the next build the same as the last.
clean:
	rm -rf $(filter-out $(LOCK),$(wildcard build/*))

# The comment that opens this file, to its first empty line.
help:
	@sed -n '2,/^$$/s/^# \{0,1\}//p' Makefile

# BEGIN: lint-install .
# http://github.com/codeGROOVE-dev/lint-install

.PHONY: lint
lint: _lint

LINT_ARCH := $(shell uname -m)
LINT_OS := $(shell uname)
LINT_OS_LOWER := $(shell echo $(LINT_OS) | tr '[:upper:]' '[:lower:]')
LINT_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# shellcheck and hadolint lack arm64 native binaries: rely on x86-64 emulation
ifeq ($(LINT_OS),Darwin)
	ifeq ($(LINT_ARCH),arm64)
		LINT_ARCH=x86_64
	endif
endif

LINTERS :=
FIXERS :=

YAMLLINT_VERSION ?= 1.37.1
YAMLLINT_ROOT := $(LINT_ROOT)/out/linters/yamllint-$(YAMLLINT_VERSION)
YAMLLINT_BIN := $(YAMLLINT_ROOT)/dist/bin/yamllint
$(YAMLLINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/yamllint-*
	curl -sSfL https://github.com/adrienverge/yamllint/archive/refs/tags/v$(YAMLLINT_VERSION).tar.gz | tar -C $(LINT_ROOT)/out/linters -zxf -
	cd $(YAMLLINT_ROOT) && pip3 install --target dist . || pip install --target dist .

LINTERS += yamllint-lint
yamllint-lint: $(YAMLLINT_BIN)
	PYTHONPATH=$(YAMLLINT_ROOT)/dist $(YAMLLINT_ROOT)/dist/bin/yamllint .

.PHONY: _lint $(LINTERS)
_lint:
	@exit_code=0; \
	for target in $(LINTERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

.PHONY: fix $(FIXERS)
fix:
	@exit_code=0; \
	for target in $(FIXERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

# END: lint-install .

# --- zig lint and fix -----------------------------------------------------------
# Kept out of lint-install's block above, which it rewrites. `make lint`
# checks werewolf's Zig three ways: zig ast-check, which checks every
# function, called or not; tools/zigfix --check, zig fmt's layout with lines
# held to 100 and nothing the standard library deprecates; and ziglint, with
# the Style Guide's naming rules (.ziglint.zon). `make fix` runs zigfix.
ZIG_SOURCES = $(shell find . -name '*.zig' -not -path './build/*' -not -path './out/*' -not -path './.zig-cache/*' -not -path './.claude/*')

ZIGFIX := $(LINT_ROOT)/out/tools/zigfix
$(ZIGFIX): tools/zigfix.zig
	mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -femit-bin=$@ tools/zigfix.zig

# ziglint's release for this machine, checked against the sha256 each
# release's checksums.txt gave when it was pinned.
ZIGLINT_VERSION ?= 0.5.3
ZIGLINT_PLATFORM := $(subst arm64,aarch64,$(shell uname -m))-$(if $(filter Darwin,$(LINT_OS)),macos,linux)
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

.PHONY: zig-lint zig-fix
LINTERS += zig-lint
zig-lint: $(ZIGFIX) $(ZIGLINT_BIN)
	@status=0; for f in $(ZIG_SOURCES); do zig ast-check $$f >/dev/null || status=1; done; exit $$status
	$(ZIGFIX) --check $(ZIG_SOURCES)
	$(ZIGLINT_BIN) $(ZIG_SOURCES)

FIXERS += zig-fix
zig-fix: $(ZIGFIX)
	$(ZIGFIX) $(ZIG_SOURCES)

# doc-check holds the markdown to CONTRIBUTING.md's rules: every relative
# link and anchor resolves, a program's README stays within 100 lines and a
# design doc within 120, and no line starts with TODO.
DOC_SOURCES = $(shell find . -name '*.md' -not -path './build/*' -not -path './out/*' -not -path './dist/*' -not -path './.zig-cache/*' -not -path './.claude/*')
DOC_CHECK := $(LINT_ROOT)/out/tools/doc-check
$(DOC_CHECK): tools/doc-check.zig
	mkdir -p $(dir $@)
	zig build-exe -O ReleaseSafe -femit-bin=$@ tools/doc-check.zig

.PHONY: doc-lint
LINTERS += doc-lint
doc-lint: $(DOC_CHECK)
	$(DOC_CHECK) $(DOC_SOURCES)

# bite checks a downloaded release against its own copy of the release key.
.PHONY: bite-key-lint
LINTERS += bite-key-lint
bite-key-lint:
	@sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' bite | cmp -s - release/image.pub || \
		{ echo "bite: its release key differs from release/image.pub"; exit 1; }
