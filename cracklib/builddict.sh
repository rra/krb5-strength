#!/bin/sh
if [ $# -ne 2 ]; then
         echo 1>&2 Usage: $0 infile outfile
	 exit 127
fi
./mkdict "$1" | ./packer "$2"
exit 0
