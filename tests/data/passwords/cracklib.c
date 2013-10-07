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

const struct password_test cracklib_tests[] = {
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
        KADM5_PASS_Q_GENERIC,
        "it is based on a dictionary word",
    },
    {

        "in dictionary (longer)",
        "test@EXAMPLE.ORG",
        "bitterbane",
        KADM5_PASS_Q_GENERIC,
        "it is based on a dictionary word",
    },
    {

        "in dictionary (repeated)",
        "test@EXAMPLE.ORG",
        "stanfordstanford",
        KADM5_PASS_Q_GENERIC,
        "it is based on a (duplicated) dictionary word",
    },
    {

        "in dictionary (reversed)",
        "test@EXAMPLE.ORG",
        "enabrettib",
        KADM5_PASS_Q_GENERIC,
        "it is based on a (reversed) dictionary word",
    },
    {

        "seven characters",
        "test@EXAMPLE.ORG",
        "dfareas",
        KADM5_PASS_Q_GENERIC,
        "it is too short",
    },
    {

        "four characters",
        "test@EXAMPLE.ORG",
        "food",
        KADM5_PASS_Q_GENERIC,
        "it is too short",
    },
    {

        "three characters",
        "test@EXAMPLE.ORG",
        "foo",
        KADM5_PASS_Q_GENERIC,
        "it is WAY too short",
    },
    {

        "empty",
        "test@EXAMPLE.ORG",
        "",
        KADM5_PASS_Q_GENERIC,
        "it is WAY too short",
    },
    {

        "all whitespace",
        "test@EXAMPLE.ORG",
        "  	  		  ",
        KADM5_PASS_Q_GENERIC,
        "it does not contain enough DIFFERENT characters",
    },
    {

        "too simplistic",
        "test@EXAMPLE.ORG",
        "abcdefghi",
        KADM5_PASS_Q_GENERIC,
        "it is too simplistic/systematic",
    },
    {

        "not enough characters",
        "test@EXAMPLE.ORG",
        "22413411",
        KADM5_PASS_Q_GENERIC,
        "it does not contain enough DIFFERENT characters",
    },
    {

        "long password complexity",
        "test@EXAMPLE.ORG",
        "OwenDericksegregationistshumiliatemeningitis'smainmast",
        0,
        NULL,
    },
};
