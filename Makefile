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

.PHONY: test
test:
	shellinspector --target 127.0.0.1:2222 --identity .vagrant/machines/default/virtualbox/private_key tests/*.inspect
