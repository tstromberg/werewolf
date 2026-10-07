# Invoke with make -C examples/LANGUAGE TARGET from the repository root.
.DEFAULT_GOAL := image
.PHONY: image deploy-qemu deploy-gcp delete-gcp serial-gcp
image deploy-qemu deploy-gcp delete-gcp serial-gcp:
	$(MAKE) -C ../.. -f Makefile -f examples/vm.mk FORM=$(FORM) DEV= example-$@
