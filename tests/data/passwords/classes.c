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

extern const struct password_test classes_tests[];
const struct password_test classes_tests[] = {
    {

        "no lowercase (11)",
        "test@EXAMPLE.ORG",
        "PASSWORD98!",
        KADM5_PASS_Q_CLASS,
        "Password must contain a lowercase letter",
        0,
    },
    {

        "no uppercase (11)",
        "test@EXAMPLE.ORG",
        "password98!",
        KADM5_PASS_Q_CLASS,
        "Password must contain an uppercase letter",
        0,
    },
    {

        "no digit (11)",
        "test@EXAMPLE.ORG",
        "passwordXX!",
        KADM5_PASS_Q_CLASS,
        "Password must contain a number",
        0,
    },
    {

        "no symbol (11)",
        "test@EXAMPLE.ORG",
        "passwordXX9",
        KADM5_PASS_Q_CLASS,
        "Password must contain a space or punctuation character",
        0,
    },
    {

        "all classes (11)",
        "test@EXAMPLE.ORG",
        "passwordX9!",
        0,
        NULL,
        0,
    },
    {

        "all classes with space (11)",
        "test@EXAMPLE.ORG",
        "pass wordX9",
        0,
        NULL,
        0,
    },
    {

        "no lowercase (15)",
        "test@EXAMPLE.ORG",
        "PASSWORD98!WORD",
        KADM5_PASS_Q_CLASS,
        "Password must contain a lowercase letter",
        0,
    },
    {

        "no uppercase (15)",
        "test@EXAMPLE.ORG",
        "password98!word",
        KADM5_PASS_Q_CLASS,
        "Password must contain an uppercase letter",
        0,
    },
    {

        "no digit (15)",
        "test@EXAMPLE.ORG",
        "passwordXX!word",
        KADM5_PASS_Q_CLASS,
        "Password must contain a number",
        0,
    },
    {

        "no symbol (12)",
        "test@EXAMPLE.ORG",
        "passwordXX9w",
        0,
        NULL,
        0,
    },
    {

        "no symbol (15)",
        "test@EXAMPLE.ORG",
        "passwordXX9word",
        0,
        NULL,
        0,
    },
    {

        "all classes (15)",
        "test@EXAMPLE.ORG",
        "passwordX9!word",
        0,
        NULL,
        0,
    },
    {

        "all classes with space (15)",
        "test@EXAMPLE.ORG",
        "pass wordX9word",
        0,
        NULL,
        0,
    },
    {

        "no lowercase (19)",
        "test@EXAMPLE.ORG",
        "PASSWORD98!WORDWORD",
        KADM5_PASS_Q_CLASS,
        "Password must contain a lowercase letter",
        0,
    },
    {

        "no uppercase (19)",
        "test@EXAMPLE.ORG",
        "password98!wordword",
        KADM5_PASS_Q_CLASS,
        "Password must contain an uppercase letter",
        0,
    },
    {

        "no digit (16)",
        "test@EXAMPLE.ORG",
        "passwordXX!wordw",
        0,
        NULL,
        0,
    },
    {

        "no digit (19)",
        "test@EXAMPLE.ORG",
        "passwordXX!wordword",
        0,
        NULL,
        0,
    },
    {

        "no symbol (19)",
        "test@EXAMPLE.ORG",
        "passwordXX9wordword",
        0,
        NULL,
        0,
    },
    {

        "all classes (19)",
        "test@EXAMPLE.ORG",
        "passwordX9!wordword",
        0,
        NULL,
        0,
    },
    {

        "all classes with space (19)",
        "test@EXAMPLE.ORG",
        "pass wordX9wordword",
        0,
        NULL,
        0,
    },
    {

        "no lowercase (20)",
        "test@EXAMPLE.ORG",
        "PASSWORD98!WORDWORDW",
        0,
        NULL,
        0,
    },
    {

        "no uppercase (20)",
        "test@EXAMPLE.ORG",
        "password98!wordwordw",
        0,
        NULL,
        0,
    },
    {

        "no digit (20)",
        "test@EXAMPLE.ORG",
        "passwordXX!wordwordw",
        0,
        NULL,
        0,
    },
    {

        "no symbol (20)",
        "test@EXAMPLE.ORG",
        "passwordXX9wordwordw",
        0,
        NULL,
        0,
    },
    {

        "all classes (20)",
        "test@EXAMPLE.ORG",
        "passwordX9!wordwordw",
        0,
        NULL,
        0,
    },
    {

        "all classes with space (20)",
        "test@EXAMPLE.ORG",
        "pass wordX9wordwordw",
        0,
        NULL,
        0,
    },
    {

        "only lowercase (24)",
        "test@EXAMPLE.ORG",
        "alllowercasewithclassreq",
        KADM5_PASS_Q_CLASS,
        "Password must contain 3 types of characters (lowercase, uppercase, numbers, symbols)",
        0,
    },
    {

        "lower and uppercase (24)",
        "test@EXAMPLE.ORG",
        "LowerUprcasewithclassreq",
        KADM5_PASS_Q_CLASS,
        "Password must contain 3 types of characters (lowercase, uppercase, numbers, symbols)",
        0,
    },
    {

        "lower, uppercase, symbols (24)",
        "test@EXAMPLE.ORG",
        "LowerUp!casewithclassreq",
        0,
        NULL,
        0,
    },
    {

        "only lowercase (25)",
        "test@EXAMPLE.ORG",
        "alllowercasewithclassreqr",
        0,
        NULL,
        0,
    },
};
