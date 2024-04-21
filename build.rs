use rustc_version::{Channel, version_meta};

fn main() {
    if let Channel::Nightly = version_meta().unwrap().channel {
        println!("cargo:rustc-cfg=nightly");
    }
}