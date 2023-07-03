.PHONY: debug
debug:
	cargo build

.PHONY: release
release:
	cargo build --release

.PHONY: clean
clean:
	cargo clean

.PHONY: vm
vm:
	vagrant up
