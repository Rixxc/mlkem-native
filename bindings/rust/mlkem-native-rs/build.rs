use std::env;
use std::path::PathBuf;

fn main() {
    let libdir_path = PathBuf::from(".")
        .canonicalize()
        .expect("cannot canonicalize path");

    let headers_path = libdir_path.join("mlkem/mlkem_native.h");
    let headers_path_str = headers_path.to_str().expect("Path is not a valid string");

    println!("cargo:rustc-link-search={}", env::var("OUT_DIR").unwrap());

    println!("cargo:rustc-link-lib=mlkem512");
    println!("cargo:rustc-link-lib=mlkem768");
    println!("cargo:rustc-link-lib=mlkem1024");

    if !make_cmd::make()
        .current_dir(libdir_path)
        .env("BUILD_DIR", env::var("OUT_DIR").unwrap())
        .output()
        .expect("could not compile mlkem-native")
        .status
        .success()
    {
        panic!("could not compile mlkem-native");
    }

    let bindings_level2 = bindgen::Builder::default()
        .header(headers_path_str)
        .clang_arg("-DMLK_CONFIG_PARAMETER_SET=512")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let bindings_level3 = bindgen::Builder::default()
        .header(headers_path_str)
        .clang_arg("-DMLK_CONFIG_PARAMETER_SET=768")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let bindings_level4 = bindgen::Builder::default()
        .header(headers_path_str)
        .clang_arg("-DMLK_CONFIG_PARAMETER_SET=1024")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings_level2.rs");
    bindings_level2
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings_level3.rs");
    bindings_level3
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings_level4.rs");
    bindings_level4
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
