#!/bin/sh
#
# Test suite for the cdbmake-wordlist utility.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

. "$SOURCE/tap/libtap.sh"
cd "$BUILD"

# We can't run this test without the cdb utility.
if ! command -v cdb >/dev/null 2>&1 ; then
    skip_all 'cdb utility required for test'
fi

# Output the test plan.
plan 11

# Create a temporary directory and wordlist.
tmpdir=`test_tmpdir`
wordlist=`test_file_path data/wordlist`
if [ -z "$wordlist" ] ; then
    bail 'cannot find data/wordlist in test suite'
fi
cp "$wordlist" "$tmpdir/wordlist"

# Add a non-ASCII word to the wordlist.
echo 'عربى' >> "$tmpdir/wordlist"

# Test generation of the basic cdb file.
cdbmake="$SOURCE/../tools/cdbmake-wordlist"
ok_program 'Database generation' 0 '' "$cdbmake" "$tmpdir/wordlist"

# Check the contents.
ok_program 'Database contains password' 0 '1' \
    cdb -q "$tmpdir/wordlist.cdb" password
ok_program 'Database contains one' 0 '1' \
    cdb -q "$tmpdir/wordlist.cdb" one
ok_program 'Database does not contain three' 100 '' \
    cdb -q "$tmpdir/wordlist.cdb" three
ok_program 'Database contains non-ASCII password' 0 '1' \
    cdb -q "$tmpdir/wordlist.cdb" 'عربى'

# Regenerate the database, filtering out short passwords.
ok_program 'Database generation with no short passwords' 0 '' \
    "$cdbmake" -l 8 "$tmpdir/wordlist"
ok_program 'Database still contains password' 0 '1' \
    cdb -q "$tmpdir/wordlist.cdb" password
ok_program 'Database does not contain one' 100 '' \
    cdb -q "$tmpdir/wordlist.cdb" one

# Regenerate the database, filtering out non-ASCII words.
ok_program 'Database generation with no non-ASCII' 0 '' \
    "$cdbmake" -a "$tmpdir/wordlist"
ok_program 'Database still contains password' 0 '1' \
    cdb -q "$tmpdir/wordlist.cdb" password
ok_program 'Database does not contain non-ASCII password' 100 '' \
    cdb -q "$tmpdir/wordlist.cdb" 'عربى'

# Clean up.
rm "$tmpdir/wordlist.cdb"
rm "$tmpdir/wordlist"
rmdir "$tmpdir" 2>/dev/null
