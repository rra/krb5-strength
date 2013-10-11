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

const struct password_test principal_tests[] = {
    {

        "based on principal",
        "someuser@EXAMPLE.ORG",
        "someuser",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
    {

        "based on principal (reversed)",
        "someuser@EXAMPLE.ORG",
        "resuemos",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
    {

        "based on principal with digits",
        "someuser@EXAMPLE.ORG",
        "someuser123",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
    {

        "is full principal",
        "test@EXAMPLE.ORG",
        "test@EXAMPLE.ORG",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
    {

        "principal with leading digits",
        "someuser@EXAMPLE.ORG",
        "123someuser",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
    {

        "principal with leading and trailing digits",
        "someuser@EXAMPLE.ORG",
        "1someuser2",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
    {

        "is realm (lowercase)",
        "someuser@NEWEXAMPLE.ORG",
        "newexample",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
    {

        "is realm (lowercase) with digits",
        "someuser@NEWEXAMPLE.ORG",
        "newexample123",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
    {

        "is realm (lowercase) with leading digits",
        "someuser@NEWEXAMPLE.ORG",
        "123newexample",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
    {

        "is realm reversed",
        "someuser@NEWEXAMPLE.ORG",
        "ELPMAXEWEN",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
    {

        "is second realm with digits",
        "someuser@NEWEXAMPLE.ORG",
        "ORG1791520",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
    {

        "is whole realm (mixed case)",
        "someuser@NEWEXAMPLE.ORG",
        "NewExample.Org",
        KADM5_PASS_Q_GENERIC,
        "password based on username or principal",
    },
};
