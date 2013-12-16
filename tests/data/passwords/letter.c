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

const struct password_test letter_tests[] = {
    {

        "non-ASCII characters",
        "test@EXAMPLE.ORG",
        "عربى",
        KADM5_PASS_Q_GENERIC,
        "password contains non-ASCII or control characters",
    },
    {

        "control character",
        "test@EXAMPLE.ORG",
        "ouchDartetch",
        KADM5_PASS_Q_GENERIC,
        "password contains non-ASCII or control characters",
    },
    {

        "tab",
        "test@EXAMPLE.ORG",
        "	ouchDartetch",
        KADM5_PASS_Q_GENERIC,
        "password contains non-ASCII or control characters",
    },
    {

        "all alphabetic",
        "test@EXAMPLE.ORG",
        "ouchDartetch",
        KADM5_PASS_Q_CLASS,
        "password is only letters and spaces",
    },
    {

        "all alphabetic with spaces",
        "test@EXAMPLE.ORG",
        "the perils of all good dogs",
        KADM5_PASS_Q_CLASS,
        "password is only letters and spaces",
    },
    {

        "punctuation",
        "test@EXAMPLE.ORG",
        "the perils of all good dogs!",
        0,
        NULL,
    },
    {

        "digits",
        "test@EXAMPLE.ORG",
        "the perils 0of all good dogs",
        0,
        NULL,
    },
};
