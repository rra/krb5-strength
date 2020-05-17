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

extern const struct password_test cdb_tests[];
const struct password_test cdb_tests[] = {
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
        KADM5_PASS_Q_DICT,
        "Password found in list of common passwords",
        0,
    },
    {

        "in dictionary (longer)",
        "test@EXAMPLE.ORG",
        "bitterbane",
        KADM5_PASS_Q_DICT,
        "Password found in list of common passwords",
        0,
    },
    {

        "in dictionary (drop first)",
        "test@EXAMPLE.ORG",
        "1bitterbane",
        KADM5_PASS_Q_DICT,
        "Password found in list of common passwords",
        0,
    },
    {

        "in dictionary (drop last)",
        "test@EXAMPLE.ORG",
        "bitterbane1",
        KADM5_PASS_Q_DICT,
        "Password found in list of common passwords",
        0,
    },
    {

        "in dictionary (drop first two)",
        "test@EXAMPLE.ORG",
        "abbitterbane",
        KADM5_PASS_Q_DICT,
        "Password found in list of common passwords",
        0,
    },
    {

        "in dictionary (drop last two)",
        "test@EXAMPLE.ORG",
        "bitterbane12",
        KADM5_PASS_Q_DICT,
        "Password found in list of common passwords",
        0,
    },
    {

        "in dictionary (drop first and last)",
        "test@EXAMPLE.ORG",
        "'bitterbane'",
        KADM5_PASS_Q_DICT,
        "Password found in list of common passwords",
        0,
    },
    {

        "dictionary with three characters",
        "test@EXAMPLE.ORG",
        "bitterbane123",
        0,
        NULL,
        0,
    },
};
