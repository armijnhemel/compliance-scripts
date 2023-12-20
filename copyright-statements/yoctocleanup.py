#!/usr/bin/env python3

# Copyright Armijn Hemel for Tjaldur Software Governance Solutions
# SPDX-License-Identifier: GPL-3.0-only

'''
This script is used as a pre-filter for createnotices.py.

It takes two input arguments:

1. a file with checksums/file names (for example made with 'md5sum')
2. a scancode JSON file

The output is a cleaned up JSON file that can be fed to createnotices.py
'''

import os
import os.path
import sys
import json
import argparse
import pathlib
import copy

def main(argv):
    parser = argparse.ArgumentParser()

    # the following options are provided on the commandline
    parser.add_argument("-j", "--json", action="store", dest="jsonfile",
                        help="path to ScanCode JSON file", metavar="FILE")
    parser.add_argument("-m", "--md5file", action="store", dest="checksumfile",
                        help="file with file hashes", metavar="FILE")
    parser.add_argument("-o", "--output-file", action="store", dest="output_file",
                        help="output file", metavar="FILE")
    parser.add_argument("-d", "--directory", action="store", dest="toplevel",
                        help="top level directory", metavar="DIR")

    args = parser.parse_args()

    # sanity checks for the various options
    if args.jsonfile is None:
        parser.error("ScanCode JSON file missing")

    if not os.path.exists(args.jsonfile):
        parser.error("ScanCode JSON file does not exist")

    if not os.path.isfile(args.jsonfile):
        parser.error("ScanCode JSON file is not a file")

    if args.checksumfile is None:
        parser.error("MD5 file missing")

    if args.toplevel is None:
        parser.error("Top level directory not provided")

    pathlen = len(args.toplevel)

    checksum_to_files = {}
    files_to_checksum = {}

    # open the MD5 checksum file
    with open(args.checksumfile, 'r') as checksumfile:
        for f in checksumfile:
            checksum, filename = f.strip().split('  ', maxsplit=1)
            filename = os.path.normpath(filename)
            if not checksum in checksum_to_files:
                checksum_to_files[checksum] = []
            checksum_to_files[checksum].append(filename)
            files_to_checksum[filename] = checksum

    # read the JSON
    try:
        scjsonfile = open(args.jsonfile).read()
        scjson = json.loads(scjsonfile)
    except Exception as e:
        print(e)
        print("Cannot parse ScanCode JSON, exiting", file=sys.stderr)
        sys.exit(1)

    # filter patterns for Yocto directories that aren't interesting
    filter_patterns = ['/recipe-sysroot-native/',
                       '/recipe-sysroot/',
                       '/sysroot-destdir/',
                       '/license-destdir/',
                       '/temp/log.',
                       '/temp/run.',
                       '/deploy-ipks/',
                       '/packages-split/',
                       '/pkgdata/runtime/',
                       '/pkgdata/shlibs2/',
                       '/pseudo/files.db',
                       '/pseudo/logs.db',
                       '/pseudo/pseudo.log',
                       '/pseudo/pseudo.pid',
                       '.dirstamp',
                       '.timestamp',
                       '/usr/src/debug',
                       '/.pc/.quilt_',
                       '/.pc/.version',
                       '/.pc/applied-patches',
                       '/autom4te.cache/',
                      ]

    newjson = {}
    newjson['headers'] = scjson['headers']
    newjson['files'] = []

    for f in scjson['files']:
        # skip anything but files
        if f['type'] != 'file':
            continue
        filename = f['path'][pathlen:]
        if not filename in files_to_checksum:
            continue
        skip = False
        checksum = files_to_checksum[filename]
        if len(checksum_to_files[checksum]) == 1:
            for fil in filter_patterns:
                if fil in filename:
                    skip = True
                    break
            if skip:
                continue
            newjson['files'].append(f)
        else:
            for fil in filter_patterns:
                if fil in filename:
                    for c in checksum_to_files[checksum]:
                        skipskip = False
                        for filfil in filter_patterns:
                            if filfil in c:
                                skipskip = True
                                break
                        if not skipskip:
                            break
                    if skipskip:
                        skip = True
                    break
            if skip:
                continue

            # filter
            candidates = set(checksum_to_files[checksum])
            for c in checksum_to_files[checksum]:
                for filfil in filter_patterns:
                    if filfil in c:
                        candidates.remove(c)
                        break
            if len(candidates) == 1:
                candidate = candidates.pop()
                ff = copy.deepcopy(f)
                ff['path'] = os.path.join(args.toplevel, candidate)
                newjson['files'].append(ff)
            else:
                remove_candidates = set()
                for c in candidates:
                    cparts = pathlib.Path(c).parts
                    if cparts[2] in ['build', 'image', 'package']:
                        remove_candidates.add(c)
                for c in remove_candidates:
                    candidates.remove(c)
                if len(candidates) == 1:
                    candidate = candidates.pop()
                    ff = copy.deepcopy(f)
                    ff['path'] = os.path.join(args.toplevel, candidate)
                    newjson['files'].append(ff)
                elif candidates == set():
                    continue
                else:
                    for candidate in candidates:
                        ff = copy.deepcopy(f)
                        ff['path'] = os.path.join(args.toplevel, candidate)
                        newjson['files'].append(ff)

    outfile = open(args.output_file, 'w')
    json.dump(newjson, outfile, indent=4)
    outfile.close()


if __name__ == "__main__":
    main(sys.argv)
