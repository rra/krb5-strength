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

const struct password_test sqlite_tests[] = {
    {

        "good password",
        "test@EXAMPLE.ORG",
        "known good password",
        0,
        NULL,
    },
    {

        "in dictionary",
        "test@EXAMPLE.ORG",
        "password",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (longer)",
        "test@EXAMPLE.ORG",
        "bitterbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (drop first)",
        "test@EXAMPLE.ORG",
        "1bitterbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (drop last)",
        "test@EXAMPLE.ORG",
        "bitterbane1",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "dictionary with three characters",
        "test@EXAMPLE.ORG",
        "bitterbane123",
        0,
        NULL,
    },
    {

        "two-character dictionary word",
        "test@EXAMPLE.ORG",
        "ab",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "three-character dictionary word",
        "test@EXAMPLE.ORG",
        "one",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "single-character password",
        "test@EXAMPLE.ORG",
        "a",
        0,
        NULL,
    },
    {

        "in dictionary (edit: delete 1)",
        "test@EXAMPLE.ORG",
        "itterbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: delete 2)",
        "test@EXAMPLE.ORG",
        "btterbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: delete 3/4)",
        "test@EXAMPLE.ORG",
        "biterbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: delete 5)",
        "test@EXAMPLE.ORG",
        "bittrbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: delete 6)",
        "test@EXAMPLE.ORG",
        "bittebane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: delete 7)",
        "test@EXAMPLE.ORG",
        "bitterane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: delete 8)",
        "test@EXAMPLE.ORG",
        "bitterbne",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: delete 9)",
        "test@EXAMPLE.ORG",
        "bitterbae",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: delete 10)",
        "test@EXAMPLE.ORG",
        "bitterban",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: modify 1)",
        "test@EXAMPLE.ORG",
        "Citterbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: modify 2)",
        "test@EXAMPLE.ORG",
        "b7tterbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: modify 3)",
        "test@EXAMPLE.ORG",
        "bi#terbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: modify 4)",
        "test@EXAMPLE.ORG",
        "bit*erbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: modify 5)",
        "test@EXAMPLE.ORG",
        "bittgrbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: modify 6)",
        "test@EXAMPLE.ORG",
        "bitte.bane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: modify 7)",
        "test@EXAMPLE.ORG",
        "bitter ane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: modify 8)",
        "test@EXAMPLE.ORG",
        "bitterb-ne",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: modify 9)",
        "test@EXAMPLE.ORG",
        "bitterbame",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: modify 10)",
        "test@EXAMPLE.ORG",
        "bitterbanq",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: add 2)",
        "test@EXAMPLE.ORG",
        "b7itterbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: add 3)",
        "test@EXAMPLE.ORG",
        "bi#tterbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: add 4)",
        "test@EXAMPLE.ORG",
        "bit*terbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: add 4)",
        "test@EXAMPLE.ORG",
        "bit*terbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: add 5)",
        "test@EXAMPLE.ORG",
        "bittgerbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: add 6)",
        "test@EXAMPLE.ORG",
        "bitte.rbane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: add 7)",
        "test@EXAMPLE.ORG",
        "bitter bane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: add 8)",
        "test@EXAMPLE.ORG",
        "bitterb-ane",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: add 9)",
        "test@EXAMPLE.ORG",
        "bitterbamne",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
    {

        "in dictionary (edit: add 10)",
        "test@EXAMPLE.ORG",
        "bitterbanqe",
        KADM5_PASS_Q_DICT,
        "password found in list of common passwords",
    },
};
