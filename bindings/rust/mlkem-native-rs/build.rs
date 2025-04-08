use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let libdir_path = PathBuf::from(".")
        .canonicalize()
        .expect("cannot canonicalize path");

    println!("cargo:rustc-link-search={}", env::var("OUT_DIR").unwrap());

    println!("cargo:rustc-link-lib=mlkem512");
    println!("cargo:rustc-link-lib=mlkem768");
    println!("cargo:rustc-link-lib=mlkem1024");

    if !Command::new("make")
        .current_dir(libdir_path)
        .env("BUILD_DIR", env::var("OUT_DIR").unwrap())
        .output()
        .expect("could not compile mlkem-native")
        .status
        .success()
    {
        panic!("could not compile mlkem-native");
    }
}
