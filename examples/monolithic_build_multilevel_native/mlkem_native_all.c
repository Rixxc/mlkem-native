/*
 * Copyright (c) 2024-2025 The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */

#define MLKEM_NATIVE_MULTILEVEL_BUILD

/* Three instances of mlkem-native for all security levels */

/* Include level-independent code */
#define MLKEM_NATIVE_MULTILEVEL_BUILD_WITH_SHARED 1
/* Include C files accompanying native code */
#define MLKEM_NATIVE_MONOBUILD_WITH_NATIVE_ARITH
#define MLKEM_NATIVE_MONOBUILD_WITH_NATIVE_FIPS202
/* Indicate that this is a monobuild */
#define MLKEM_NATIVE_MONOBUILD

#define MLKEM_K 2
#define MLKEM_NATIVE_CONFIG_FILE "multilevel_config.h"
#include "mlkem_native_monobuild.c"
#undef MLKEM_NATIVE_CONFIG_FILE

/* Exclude level-independent code */
#undef MLKEM_NATIVE_MULTILEVEL_BUILD_WITH_SHARED
#define MLKEM_NATIVE_MULTILEVEL_BUILD_NO_SHARED

#define MLKEM_K 3
#define MLKEM_NATIVE_CONFIG_FILE "multilevel_config.h"
#include "mlkem_native_monobuild.c"
#undef MLKEM_NATIVE_CONFIG_FILE

#define MLKEM_K 4
#define MLKEM_NATIVE_CONFIG_FILE "multilevel_config.h"
#include "mlkem_native_monobuild.c"
#undef MLKEM_NATIVE_CONFIG_FILE
