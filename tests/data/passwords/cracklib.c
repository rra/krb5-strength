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

extern const struct password_test cracklib_tests[];
const struct password_test cracklib_tests[] = {
    {

        "good password",
        "test@EXAMPLE.ORG",
        "known good password",
        0,
        NULL,
        0,
    },
    {

        "in dictionary",
        "test@EXAMPLE.ORG",
        "password",
        KADM5_PASS_Q_GENERIC,
        "it is based on a dictionary word",
        0,
    },
    {

        "in dictionary (longer)",
        "test@EXAMPLE.ORG",
        "bitterbane",
        KADM5_PASS_Q_GENERIC,
        "it is based on a dictionary word",
        0,
    },
    {

        "in dictionary (repeated)",
        "test@EXAMPLE.ORG",
        "stanfordstanford",
        KADM5_PASS_Q_GENERIC,
        "it is based on a (duplicated) dictionary word",
        1,
    },
    {

        "in dictionary (reversed)",
        "test@EXAMPLE.ORG",
        "enabrettib",
        KADM5_PASS_Q_GENERIC,
        "it is based on a (reversed) dictionary word",
        1,
    },
    {

        "seven characters",
        "test@EXAMPLE.ORG",
        "dfareas",
        KADM5_PASS_Q_GENERIC,
        "it is too short",
        1,
    },
    {

        "four characters",
        "test@EXAMPLE.ORG",
        "food",
        KADM5_PASS_Q_GENERIC,
        "it is too short",
        0,
    },
    {

        "three characters",
        "test@EXAMPLE.ORG",
        "foo",
        KADM5_PASS_Q_GENERIC,
        "it is WAY too short",
        0,
    },
    {

        "empty",
        "test@EXAMPLE.ORG",
        "",
        KADM5_PASS_Q_GENERIC,
        "it is WAY too short",
        0,
    },
    {

        "all whitespace",
        "test@EXAMPLE.ORG",
        "  	  		  ",
        KADM5_PASS_Q_GENERIC,
        "it does not contain enough DIFFERENT characters",
        0,
    },
    {

        "too simplistic",
        "test@EXAMPLE.ORG",
        "abcdefghi",
        KADM5_PASS_Q_GENERIC,
        "it is too simplistic/systematic",
        0,
    },
    {

        "not enough characters",
        "test@EXAMPLE.ORG",
        "22413411",
        KADM5_PASS_Q_GENERIC,
        "it does not contain enough DIFFERENT characters",
        0,
    },
    {

        "long password complexity",
        "test@EXAMPLE.ORG",
        "OwenDericksegregationistshumiliatemeningitis'smainmast",
        0,
        NULL,
        0,
    },
};
