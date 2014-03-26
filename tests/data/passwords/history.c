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

const struct password_test history_tests[] = {
    {

        "valid simple password",
        "someuser@EXAMPLE.ORG",
        "password",
        0,
        NULL,
    },
    {

        "repeating the same password",
        "someuser@EXAMPLE.ORG",
        "password",
        0,
        "password was previously used",
    },
    {

        "different password works",
        "someuser@EXAMPLE.ORG",
        "password2",
        0,
        NULL,
    },
    {

        "now that one fails",
        "someuser@EXAMPLE.ORG",
        "password2",
        0,
        "password was previously used",
    },
    {

        "previous password still fails",
        "someuser@EXAMPLE.ORG",
        "password",
        0,
        "password was previously used",
    },
    {

        "succeeds for different user",
        "test@EXAMPLE.ORG",
        "password",
        0,
        NULL,
    },
    {

        "based on principal",
        "someuser@EXAMPLE.ORG",
        "someuser",
        0,
        "password based on username or principal",
    },
};
