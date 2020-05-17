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

extern const struct password_test letter_tests[];
const struct password_test letter_tests[] = {
    {

        "non-ASCII characters",
        "test@EXAMPLE.ORG",
        "عربى",
        KADM5_PASS_Q_GENERIC,
        "Password contains non-ASCII or control characters",
        0,
    },
    {

        "control character",
        "test@EXAMPLE.ORG",
        "ouchDartetch",
        KADM5_PASS_Q_GENERIC,
        "Password contains non-ASCII or control characters",
        0,
    },
    {

        "tab",
        "test@EXAMPLE.ORG",
        "	ouchDartetch",
        KADM5_PASS_Q_GENERIC,
        "Password contains non-ASCII or control characters",
        0,
    },
    {

        "all alphabetic",
        "test@EXAMPLE.ORG",
        "ouchDartetch",
        KADM5_PASS_Q_CLASS,
        "Password is only letters and spaces",
        0,
    },
    {

        "all alphabetic with spaces",
        "test@EXAMPLE.ORG",
        "the perils of all good dogs",
        KADM5_PASS_Q_CLASS,
        "Password is only letters and spaces",
        0,
    },
    {

        "punctuation",
        "test@EXAMPLE.ORG",
        "the perils of all good dogs!",
        0,
        NULL,
        0,
    },
    {

        "digits",
        "test@EXAMPLE.ORG",
        "the perils 0of all good dogs",
        0,
        NULL,
        0,
    },
    {

        "mindiff (1 character)",
        "test@EXAMPLE.ORG",
        "11111111111111111111",
        KADM5_PASS_Q_CLASS,
        "Password does not contain enough unique characters",
        0,
    },
    {

        "mindiff (2 characters)",
        "test@EXAMPLE.ORG",
        "1b1b1b1b1b1b1b1b1b1b",
        KADM5_PASS_Q_CLASS,
        "Password does not contain enough unique characters",
        0,
    },
    {

        "mindiff (3 characters)",
        "test@EXAMPLE.ORG",
        "1bc1bc1bc1bc1bc1bc1b",
        KADM5_PASS_Q_CLASS,
        "Password does not contain enough unique characters",
        0,
    },
    {

        "mindiff (4 characters)",
        "test@EXAMPLE.ORG",
        "1bcd1bcd1bcd1bcd1bcd",
        KADM5_PASS_Q_CLASS,
        "Password does not contain enough unique characters",
        0,
    },
    {

        "mindiff (5 characters)",
        "test@EXAMPLE.ORG",
        "1bcde1bcde1bcde1bcde",
        KADM5_PASS_Q_CLASS,
        "Password does not contain enough unique characters",
        0,
    },
    {

        "mindiff (6 characters)",
        "test@EXAMPLE.ORG",
        "1bcdef1bcdef1bcdef1b",
        KADM5_PASS_Q_CLASS,
        "Password does not contain enough unique characters",
        0,
    },
    {

        "mindiff (7 characters)",
        "test@EXAMPLE.ORG",
        "1cdbfge1cdbeg1fcdbef",
        KADM5_PASS_Q_CLASS,
        "Password does not contain enough unique characters",
        0,
    },
    {

        "mindiff (8 characters)",
        "test@EXAMPLE.ORG",
        "1dbegchf1cdbfgh1ebcd",
        0,
        NULL,
        0,
    },
    {

        "mindiff (9 characters)",
        "test@EXAMPLE.ORG",
        "bcd1fgei1bhdefchig1b",
        0,
        NULL,
        0,
    },
};
