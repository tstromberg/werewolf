# Included by the root Makefile: packages Wolfi does not ship, each a
# melange recipe in Wolfi's style, built in Wolfi's environment from
# sources whose sha256 melange checks, then unpacked over the image like a
# form's files. A form keeps its recipes in forms/NAME/melange/, and has
# those of every form in its chain. The machine's updater carries the
# files forward as it does a form's; the Wolfi libraries they link must
# be among the form's packages, which the build checks, so Wolfi's fixes
# to those reach the machine with the rest. A recipe Wolfi would take is
# also a pull request to wolfi-dev/os: once Wolfi ships the package, the
# form names it and the recipe goes. One Wolfi will not take stays here.
#
# melange builds in a sandbox or a VM. On Linux, bubblewrap (bwrap). On
# macOS, its QEMU runner, booted from werewolf's own Alpine kernel
# ($(BUILD)/vmlinuz) and a guest made by `melange initramfs`, with the
# kernel's modules added under /usr/lib/modules: melange's own
# QEMU_KERNEL_MODULES writes them under /lib, which replaces the guest's
# /lib -> usr/lib link and leaves it without its loader.
#
#   make _build-apk RECIPE=PATH   one recipe's packages, for its author
#                                 (howl build-apk RECIPE)
VENDOR = build/vendor
APKS = $(VENDOR)/packages/$(ARCH)
MELANGE_GUEST = $(VENDOR)/melange-guest-$(ARCH).cpio
MELANGE_QEMU = env QEMU_KERNEL_IMAGE=$(abspath $(BUILD)/vmlinuz) QEMU_BASE_INITRAMFS=$(abspath $(MELANGE_GUEST)) \
	melange build --runner qemu
MELANGE_LINUX := $(if $(shell command -v bwrap),melange build --runner bubblewrap,$(MELANGE_QEMU))
MELANGE := $(if $(filter Darwin,$(HOST_OS)),$(MELANGE_QEMU),$(MELANGE_LINUX))
MELANGE_NEEDS = $(if $(findstring --runner qemu,$(MELANGE)),$(MELANGE_GUEST) $(BUILD)/vmlinuz)
# Half the host's CPUs (a Rust build is most of a wait) and 8 GiB.
ifndef MELANGE_CPU
MELANGE_CPU := $(shell n=$$(getconf _NPROCESSORS_ONLN); echo $$(( n > 2 ? n / 2 : 1 )))
endif
MELANGE_MEMORY ?= 8Gi

$(MELANGE_GUEST): $(BUILD)/vmlinuz
	mkdir -p $(dir $@) && rm -rf $@.d && mkdir -p $@.d/usr/lib/modules
	melange initramfs --arch $(ARCH) --output $@.base
	cp -R $(BUILD)/kernel/x/lib/modules/. $@.d/usr/lib/modules/ && find $@.d -type l -delete
	(cd $@.d && $(TAR) --format newc --uid 0 --gid 0 --numeric-owner -cf - usr/lib/modules) | cat $@.base - >$@.tmp
	mv $@.tmp $@ && rm -rf $@.d $@.base

# The recipes of the form's chain, and RECIPE, for _build-apk.
FORM_RECIPES := $(wildcard $(addsuffix /melange/*.yaml,$(FORM_DIRS)))
MELANGE_RECIPES := $(sort $(FORM_RECIPES) $(RECIPE))

# melange_apks RECIPE: the files of the packages it makes, main and
# subpackages, as melange names them.
melange_apks = $(addprefix $(APKS)/,$(addsuffix .apk,$(shell melange query $(1) \
	'{{.Package.Name}}-{{.Package.Version}}-r{{.Package.Epoch}}{{$$v := print "-" .Package.Version "-r" .Package.Epoch}}{{range .Subpackages}} {{.Name}}{{$$v}}{{end}}' 2>/dev/null)))
# A stamp a recipe: a recipe's path, made a file name.
melange_stamp = $(VENDOR)/stamps/$(ARCH)/$(subst /,_,$(subst ../,up_,$(1))).built

# recipe RECIPE: the rule that builds its packages.
define melange_recipe
$(call melange_stamp,$(1)): $(1) $$(MELANGE_NEEDS)
	@[ -f $(1) ] || { echo "$(1): no such recipe" >&2; exit 1; }
	mkdir -p $(VENDOR)/packages $(VENDOR)/melange-tmp $$(dir $$@)
	TMPDIR=$$(abspath $(VENDOR))/melange-tmp $$(MELANGE) $(1) --arch $$(ARCH) \
		--cpu $$(MELANGE_CPU) --memory $$(MELANGE_MEMORY) \
		--out-dir $$(abspath $(VENDOR))/packages --cache-dir $$(abspath $(VENDOR))/melange-cache
	touch $$@
endef
$(foreach r,$(MELANGE_RECIPES),$(eval $(call melange_recipe,$(r))))

# check_links APK: every library it links (its so: depends) is in the
# form's packages.
define check_links
for so in $$($(TAR) -xzOf $(1) .PKGINFO | sed -n 's/^depend = so:\(.*\)/\1/p'); do \
	$(TAR) -tf $(OUT)/rootfs.tar | grep -q "/$$so$$" || \
		{ echo "$(1) links $$so, which no package of form $(FORM) provides" >&2; exit 1; }; \
done
endef

.PHONY: _build-apk
_build-apk: $(if $(RECIPE),$(call melange_stamp,$(RECIPE)))
	@[ -n "$(RECIPE)" ] || { echo "_build-apk: RECIPE=path/to/recipe.yaml" >&2; exit 1; }
	@for a in $(call melange_apks,$(RECIPE)); do \
		echo "$$a"; $(TAR) -xzOf $$a .PKGINFO | sed -n 's/^depend = so:/  links /p'; \
	done

ifneq ($(FORM_RECIPES),)
MELANGE_OUT = $(OUT)/melange
OVERLAY_DIRS += $(MELANGE_OUT)
$(OUT)/meta.stamp $(OUT)/overlay.tar: $(OUT)/melange.stamp

# Every package of every recipe of the chain, but its metadata, over the
# image, each checked for what it links.
$(OUT)/melange.stamp: $(foreach r,$(FORM_RECIPES),$(call melange_stamp,$(r))) $(OUT)/rootfs.tar
	rm -rf $(MELANGE_OUT) && mkdir -p $(MELANGE_OUT)
	@for a in $(foreach r,$(FORM_RECIPES),$(call melange_apks,$(r))); do \
		$(call check_links,$$a) && \
		$(TAR) -xzf $$a -C $(MELANGE_OUT) --exclude .PKGINFO --exclude '.SIGN.*' --exclude .melange.yaml || exit 1; \
		echo "melange: $$a"; \
	done
	touch $@
endif
