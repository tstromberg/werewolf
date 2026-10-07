# Read after the root Makefile. Reuse its image, firmware and QEMU settings.
.PHONY: example-image example-deploy-qemu example-deploy-gcp example-delete-gcp example-serial-gcp example-gcp-config
example-image: $(OUT)/disk.qcow2

QEMU_DISK ?= $(OUT)/qemu.qcow2
HTTP_PORT ?= 8080
UEFI_VARS_COPY = $(QEMU_DISK).vars.fd

# Preserve the running disk (including /data and automatic updates) across
# launches and source rebuilds. Use a new QEMU_DISK to test a new image.
example-deploy-qemu: example-image
	@test -n "$(UEFI_FIRMWARE)" || { echo 'Set UEFI_FIRMWARE to your edk2/OVMF firmware'; exit 1; }
	@test "$(ARCH)" = aarch64 || test -n "$(UEFI_VARS)" || { echo 'Set UEFI_VARS to the matching OVMF variables template'; exit 1; }
	@if test ! -f "$(QEMU_DISK)"; then cp "$(OUT)/disk.qcow2" "$(QEMU_DISK)"; \
		else echo 'Reusing $(QEMU_DISK); choose a new QEMU_DISK to deploy a rebuilt image'; fi
	@if test ! -f "$(UEFI_VARS_COPY)"; then $(uefi-vars); fi
	@echo 'http://127.0.0.1:$(HTTP_PORT)/ (Ctrl-a x exits; disk changes persist)'
	qemu-system-$(ARCH) -M $(MACHINE) -accel $(ACCEL) -cpu $(CPU) -nographic \
		-smp 2 -m 4096 $(UEFI_FLAGS) -device virtio-rng-pci \
		-netdev user,id=n0,hostfwd=tcp:127.0.0.1:$(HTTP_PORT)-:$(RUN_PORT) \
		-device virtio-net-pci,netdev=n0,romfile= \
		-drive file=$(QEMU_DISK),format=qcow2,if=virtio

GCP_PROJECT ?=
GCP_BUCKET ?=
GCP_ZONE ?= us-central1-a
GCP_NAME ?= werewolf-$(FORM)
GCP_IMAGE ?= $(GCP_NAME)-$(ARCH)
GCP_NETWORK ?= default
GCP_SOURCE_RANGES ?=
GCP_MACHINE ?= $(if $(filter aarch64,$(ARCH)),t2a-standard-1,e2-medium)
GCP_ARCH = $(if $(filter aarch64,$(ARCH)),ARM64,X86_64)
GCP_NIC = $(if $(filter aarch64,$(ARCH)),GVNIC,VIRTIO_NET)
GCLOUD = gcloud --project="$(GCP_PROJECT)"
GCP_WORK = $(OUT)/gcp

example-gcp-config:
	@test -n "$(GCP_PROJECT)" -a -n "$(GCP_BUCKET)" || \
		{ echo 'Set GCP_PROJECT and GCP_BUCKET (an existing bucket name, without gs://)'; exit 1; }
	@command -v gcloud >/dev/null

example-deploy-gcp: example-gcp-config
	@test -n "$(GCP_SOURCE_RANGES)" || { echo 'Set GCP_SOURCE_RANGES to your public IPv4 CIDR, e.g. 203.0.113.4/32'; exit 1; }
	@case "$(ARCH)" in x86_64|aarch64) ;; *) echo 'ARCH must be x86_64 or aarch64'; exit 1;; esac
	@if $(GCLOUD) compute instances describe "$(GCP_NAME)" --zone="$(GCP_ZONE)" >/dev/null 2>&1; then \
		echo 'Instance exists; choose a new GCP_NAME for a new deployment'; exit 1; fi
	$(MAKE) -f Makefile -f examples/vm.mk FORM=$(FORM) DEV= example-image
	mkdir -p $(GCP_WORK)/config
	qemu-img convert -f qcow2 -O raw $(OUT)/disk.qcow2 $(GCP_WORK)/disk.raw
	@if tar --version 2>/dev/null | grep -q 'GNU tar'; then \
		tar -C $(GCP_WORK) --format=oldgnu -Sczf $(GCP_WORK)/image.tar.gz disk.raw; \
		else COPYFILE_DISABLE=1 tar -C $(GCP_WORK) --format gnutar -czf $(GCP_WORK)/image.tar.gz disk.raw; fi
	printf '%s\n' '$(GCP_NAME)' >$(GCP_WORK)/config/hostname
	COPYFILE_DISABLE=1 tar -C $(GCP_WORK)/config --format=ustar -cf $(GCP_WORK)/config.tar hostname
	base64 <$(GCP_WORK)/config.tar >$(GCP_WORK)/config.b64
	$(GCLOUD) storage cp --if-generation-match=0 $(GCP_WORK)/image.tar.gz "gs://$(GCP_BUCKET)/$(GCP_IMAGE).tar.gz"
	$(GCLOUD) compute images create "$(GCP_IMAGE)" \
		--source-uri="gs://$(GCP_BUCKET)/$(GCP_IMAGE).tar.gz" \
		--architecture=$(GCP_ARCH) --guest-os-features=UEFI_COMPATIBLE,GVNIC
	$(GCLOUD) compute instances create "$(GCP_NAME)" --zone="$(GCP_ZONE)" \
		--machine-type="$(GCP_MACHINE)" --image="$(GCP_IMAGE)" \
		--network-interface="network=$(GCP_NETWORK),nic-type=$(GCP_NIC)" \
		--tags="$(GCP_NAME)" --no-service-account --no-scopes --no-shielded-secure-boot \
		--metadata-from-file=user-data=$(GCP_WORK)/config.b64
	$(GCLOUD) compute firewall-rules create "$(GCP_NAME)-http" --network="$(GCP_NETWORK)" \
		--allow=tcp:$(RUN_PORT) --source-ranges="$(GCP_SOURCE_RANGES)" --target-tags="$(GCP_NAME)"
	@addr=$$($(GCLOUD) compute instances describe "$(GCP_NAME)" --zone="$(GCP_ZONE)" \
		--format='get(networkInterfaces[0].accessConfigs[0].natIP)'); \
		echo "Booting: http://$$addr:$(RUN_PORT)/ (health: /health); use make serial-gcp to inspect boot"

example-serial-gcp: example-gcp-config
	$(GCLOUD) compute instances get-serial-port-output "$(GCP_NAME)" --zone="$(GCP_ZONE)"

# Explicit teardown only. Keep gcloud's confirmation prompts; no bucket deletion.
# Independent targets let make -k continue after a missing resource.
.PHONY: example-delete-gcp-instance example-delete-gcp-firewall example-delete-gcp-image example-delete-gcp-upload
example-delete-gcp: example-delete-gcp-instance example-delete-gcp-firewall example-delete-gcp-image example-delete-gcp-upload
example-delete-gcp-instance: example-gcp-config
	$(GCLOUD) compute instances delete "$(GCP_NAME)" --zone="$(GCP_ZONE)"
example-delete-gcp-firewall: example-gcp-config
	$(GCLOUD) compute firewall-rules delete "$(GCP_NAME)-http"
example-delete-gcp-image: example-gcp-config
	$(GCLOUD) compute images delete "$(GCP_IMAGE)"
example-delete-gcp-upload: example-gcp-config
	$(GCLOUD) storage rm "gs://$(GCP_BUCKET)/$(GCP_IMAGE).tar.gz"
