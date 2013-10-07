/*
 * Automatically generated -- do not edit!
 *
 * This file was automatically generated from the original JSON source file
 * for the use in C test programs.  To make changes, modify the original
 * JSON source or (more rarely) the make-c-data script and run it again.
 *
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <tests/data/passwords/tests.h>

const struct password_test length_tests[] = {
    {

        "password too short (limit 12)",
        "test@EXAMPLE.COM",
        "vUCZ2aX$Y.e",
        KADM5_PASS_Q_TOOSHORT,
        "password is too short",
    },
    {

        "sufficiently long password",
        "test@EXAMPLE.COM",
        "vUCZ2aX$Y.e1",
        0,
        NULL,
    },
    {

        "password in (unchecked) dictionary",
        "test@EXAMPLE.COM",
        "happenstance",
        0,
        NULL,
    },
};
