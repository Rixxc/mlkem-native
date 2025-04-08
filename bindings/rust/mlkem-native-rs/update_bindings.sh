#!/usr/bin/env bash

if [ ! -d mlkem ] || [ ! -d bindings/rust/mlkem-native-rs ]; then
  echo "please run this script from the root of this repository"
  exit 1
fi

echo "generating bindings..."
bindgen mlkem/mlkem_native.h -- -DMLK_CONFIG_PARAMETER_SET=512 >bindings/rust/mlkem-native-rs/src/unsafe_bindings_level2.rs
bindgen mlkem/mlkem_native.h -- -DMLK_CONFIG_PARAMETER_SET=768 >bindings/rust/mlkem-native-rs/src/unsafe_bindings_level3.rs
bindgen mlkem/mlkem_native.h -- -DMLK_CONFIG_PARAMETER_SET=1024 >bindings/rust/mlkem-native-rs/src/unsafe_bindings_level4.rs
echo "done"
