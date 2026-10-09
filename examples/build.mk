# The compiled tutorials' applications (examples/README.md), which howl's
# build has make compile on this host for an image with no toolchain
# (cmd/howl/packages.zig). Each arch has its own, in OUT/application;
# nothing is written into forms/.
EXAMPLE_LANGUAGE := $(patsubst example-%,%,$(filter example-go example-rust example-aspnet,$(FORM)))
RUSTC ?= rustup run stable rustc
EXAMPLE_OVERLAY := $(OUT)/application
EXAMPLE_BINARY := $(EXAMPLE_OVERLAY)/usr/lib/app/server

ifeq ($(EXAMPLE_LANGUAGE),aspnet)
$(OUT)/application.stamp: examples/aspnet/Program.cs examples/aspnet/App.csproj examples/build.mk
	dotnet publish examples/aspnet/App.csproj --configuration Release \
		--runtime linux-$(if $(filter aarch64,$(ARCH)),arm64,x64) \
		--self-contained false -p:UseAppHost=false \
		--artifacts-path $(abspath $(OUT)/dotnet) \
		--output $(abspath $(EXAMPLE_OVERLAY)/usr/lib/app)
	touch $@
endif

ifeq ($(EXAMPLE_LANGUAGE),go)
$(EXAMPLE_BINARY): examples/go/main.go examples/build.mk
	mkdir -p $(dir $@)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(if $(filter aarch64,$(ARCH)),arm64,amd64) \
		go build -trimpath -buildvcs=false -ldflags='-s -w' -o $@ $<
endif

ifeq ($(EXAMPLE_LANGUAGE),rust)
$(EXAMPLE_BINARY): examples/rust/main.rs examples/build.mk
	mkdir -p $(dir $@)
	$(RUSTC) --edition=2021 --target $(ARCH)-unknown-linux-musl \
		-C linker=rust-lld -C target-feature=+crt-static -C opt-level=2 \
		-C strip=symbols -o $@ $<
endif
