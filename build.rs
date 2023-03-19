use std::collections::HashSet;
use std::env;
use std::path::PathBuf;

use bindgen::callbacks::{MacroParsingBehavior, ParseCallbacks};

// https://github.com/rust-lang/rust-bindgen/issues/687
const IGNORE_MACROS: [&str; 27] = [
    "MS_RDONLY",
    "MS_NOSUID",
    "MS_NODEV",
    "MS_NOEXEC",
    "MS_SYNCHRONOUS",
    "MS_REMOUNT",
    "MS_MANDLOCK",
    "MS_DIRSYNC",
    "MS_NOSYMFOLLOW",
    "MS_NOATIME",
    "MS_NODIRATIME",
    "MS_BIND",
    "MS_MOVE",
    "MS_REC",
    "MS_SILENT",
    "MS_POSIXACL",
    "MS_UNBINDABLE",
    "MS_PRIVATE",
    "MS_SLAVE",
    "MS_SHARED",
    "MS_RELATIME",
    "MS_KERNMOUNT",
    "MS_I_VERSION",
    "MS_STRICTATIME",
    "MS_LAZYTIME",
    "MS_ACTIVE",
    "MS_NOUSER",
];

#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> MacroParsingBehavior {
        if self.0.contains(name) {
            MacroParsingBehavior::Ignore
        } else {
            MacroParsingBehavior::Default
        }
    }
}

impl IgnoreMacros {
    fn new() -> Self {
        Self(IGNORE_MACROS.into_iter().map(|s| s.to_owned()).collect())
    }
}

fn main() {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .parse_callbacks(Box::new(IgnoreMacros::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("wrapper.rs"))
        .expect("Couldn't write bindings!");
}
