/*
 * Automatically generated -- do not edit!
 *
 * This file was automatically generated from the original JSON source file
 * for the use in C test programs.  To make changes, modify the original
 * JSON source or (more rarely) the make-c-data script and run it again.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2020 Russ Allbery <eagle@eyrie.org>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * SPDX-License-Identifier: MIT
 */

#include <tests/data/passwords/tests.h>

extern const struct password_test history_tests[];
const struct password_test history_tests[] = {
    {

        "valid simple password",
        "someuser@EXAMPLE.ORG",
        "password",
        0,
        NULL,
        0,
    },
    {

        "repeating the same password",
        "someuser@EXAMPLE.ORG",
        "password",
        0,
        "Password was previously used",
        0,
    },
    {

        "different password works",
        "someuser@EXAMPLE.ORG",
        "password2",
        0,
        NULL,
        0,
    },
    {

        "now that one fails",
        "someuser@EXAMPLE.ORG",
        "password2",
        0,
        "Password was previously used",
        0,
    },
    {

        "previous password still fails",
        "someuser@EXAMPLE.ORG",
        "password",
        0,
        "Password was previously used",
        0,
    },
    {

        "succeeds for different user",
        "test@EXAMPLE.ORG",
        "password",
        0,
        NULL,
        0,
    },
    {

        "based on principal",
        "someuser@EXAMPLE.ORG",
        "someuser",
        0,
        "Password based on username or principal",
        0,
    },
};
