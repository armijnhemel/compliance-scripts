#!/usr/bin/env python3

# Copyright Armijn Hemel for Tjaldur Software Governance Solutions
# SPDX-Identifier: GPL-3.0-only

# This scripts processes a list of strings from the Linux kernel and
# compares it to the output of a Git diffstat to see if there are matches.
#
# It expects a file with lines that have been extracted from a Linux kernel
# binary for example:
#
# $ strings /path/to/kernel/binary | egrep -e '\.[ch]$' | grep / > /path/to/output/file
#
# This script takes two parameters:
#
# 1. Git diffstat listing
# 2. output file as generated above
#
# A diffstat for a single author can be generated from a Git repository using 'git' and 'diffstat'
# for example:
#
# $ git log -p --author=torvalds | diffstat -p1


import sys
import os
import os.path
import argparse


def main(argv):
    parser = argparse.ArgumentParser()

    # the following options are provided on the commandline
    parser.add_argument("-d", "--diffstat", action="store", dest="diffstatfile",
                        help="path to diffstat file", metavar="FILE")
    parser.add_argument("-k", "--kernelstrings", action="store", dest="kernelstrings",
                        help="file with strings extracted from Linux kernel image",
                        metavar="FILE")
    args = parser.parse_args()

    if args.diffstatfile is None:
        parser.error("diffstat file missing")

    if not os.path.exists(args.diffstatfile):
        parser.error("diffstat file does not exist")

    if not os.path.isfile(args.diffstatfile):
        parser.error("diffstat file is not a file")

    if args.kernelstrings is None:
        parser.error("kernel strings file missing")

    if not os.path.exists(args.kernelstrings):
        parser.error("kernel strings file does not exist")

    if not os.path.isfile(args.kernelstrings):
        parser.error("diffstat file is not a file")

    try:
        diffstatfile = open(args.diffstatfile)
    except:
        print("Cannot parse diffstat file, exiting", file=sys.stderr)
        sys.exit(1)

    try:
        kernelfile = open(args.kernelstrings)
    except:
        print("Cannot parse kernel strings file, exiting", file=sys.stderr)
        sys.exit(1)

    # store the diffstats
    diffstats = set()

    for line in diffstatfile:
        if '|' not in line:
            continue
        kernelstring = line.strip().split('|', 1)[0].rstrip()
        # skip everything that does not end in .c or .h
        if kernelstring.endswith('.c') or kernelstring.endswith('.h'):
            diffstats.add(os.path.normpath(kernelstring))

    diffstatfile.close()

    # process the kernel lines
    kernelstrings = set()
    for line in kernelfile:
        kernelstring = line.strip()
        # skip everything that does not end in .c or .h
        if kernelstring.endswith('.c') or kernelstring.endswith('.h'):
            kernelstrings.add(os.path.normpath(kernelstring))

    kernelfile.close()

    print("in diffstat and in kernel:")
    print("--------------------------\n")
    for k in sorted(diffstats & kernelstrings):
        print(k)

    print()
    print("in diffstat, not in kernel:")
    print("---------------------------\n")
    for k in sorted(diffstats.difference(kernelstrings)):
        print(k)

    print()
    print("in kernel, not in diffstat:")
    print("---------------------------\n")
    for k in sorted(kernelstrings.difference(diffstats)):
        print(k)

if __name__ == "__main__":
    main(sys.argv)
