// Copyright (c) 2024 The mlkem-native project authors
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/*
 * Insert copyright notice
 */

/**
 * @file poly_frombytes_harness.c
 * @brief Implements the proof harness for poly_frombytes function.
 */

/*
 * Insert project header files that
 *   - include the declaration of the function
 *   - include the types needed to declare function arguments
 */
#include <poly.h>

/**
 * @brief Starting point for formal analysis
 *
 */
void harness(void)
{
  poly *a;
  uint8_t *r;

  /* Contracts for this function are in poly.h */
  poly_frombytes(a, r);
}
