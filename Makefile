debug: target/debug/libpam_isolate.so

target/debug/libpam_isolate.so: src/lib.rs
	cargo build

release: target/release/libpam_isolate.so

target/release/libpam_isolate.so: src/lib.rs
	cargo build --release

clean:
	cargo clean
