#!/usr/bin/env python3

# Copyright Armijn Hemel for Tjaldur Software Governance Solutions
# SPDX-Identifier: GPL-3.0-only

# This scripts processes output of ScanCode 3.0.x and outputs a file
# with license information and copyright statements per file.
# It requires that ScanCode is invoked with the --full-root option, for
# example:
#
# $ ./scancode --full-root -l -c -e -u --json-pp=/tmp/output.json /path/to/source/directory/
#
# When scanning the Linux kernel it is highly recommended to take advantage of
# the parallel processing options that ScanCode offers. For example, to run with
# eight processes at once:
#
# $ ./scancode --full-root -l -c -e -u -n 8 --json-pp=/tmp/output.json /path/to/source/directory/


import sys
import os
import json
import argparse
import csv
import itertools


def main(argv):
    parser = argparse.ArgumentParser()

    # the following options are provided on the commandline
    parser.add_argument("-j", "--json", action="store", dest="jsonfile",
                        help="path to ScanCode JSON file", metavar="FILE")
    parser.add_argument("-d", "--directory", action="store", dest="toplevel",
                        help="top level directory", metavar="DIR")
    parser.add_argument("-f", "--output-format", action="store", dest="output_format",
                        help="output format, supported values: 'csv', 'text' (default)")
    parser.add_argument("-o", "--output-file", action="store", dest="output_file",
                        help="output file (mandatory for 'csv', otherwise stdout)",
                        metavar="FILE")
    parser.add_argument("-z", "--ignore-empty", action="store_true", dest="ignore_empty",
                        help="Ignore empty results")
    parser.add_argument("-a", "--aggregate", action="store_true", dest="aggregate",
                        help="Aggregate results")
    args = parser.parse_args()

    if args.jsonfile is None:
        parser.error("ScanCode JSON file missing")

    if not os.path.exists(args.jsonfile):
        parser.error("ScanCode JSON file does not exist")

    if not os.path.isfile(args.jsonfile):
        parser.error("ScanCode JSON file is not a file")

    if args.toplevel is None:
        parser.error("Top level directory not provided")

    output_format = 'text'
    if args.output_format == 'csv':
        output_format = 'csv'

    if args.output_file is None:
        if output_format == 'csv':
            parser.error("Output file mandatory for CSV")

    try:
        scjsonfile = open(args.jsonfile).read()
        scjson = json.loads(scjsonfile)
    except:
        print("Cannot parse ScanCode JSON, exiting", file=sys.stderr)
        sys.exit(1)

    outfile_opened = False

    if output_format == 'csv':
        try:
            outfile = open(args.output_file, 'w')
        except:
            print("Could not open %s for writing CSV data" % args.output_file, file=sys.stderr)
            sys.exit(1)
        csvwriter = csv.writer(outfile)
        if not args.aggregate:
            csvwriter.writerow(['Nr', 'File', 'License(s)', 'Statement(s)'])
        outfile_opened = True
    elif output_format == 'text':
        if args.output_file is not None:
            try:
                outfile = open(args.output_file, 'w')
            except:
                print("Could not open %s for writing text data" % args.output_file, file=sys.stderr)
                sys.exit(1)
            outfile_opened = True
        else:
            outfile = sys.stdout

    # a set of file names to ignore, should be made configurable (TODO)
    ignore = set(['Makefile', 'Kconfig', 'Kbuild'])

    pathlen = len(args.toplevel)

    aggregate_licenses = set()
    aggregate_statements = set()

    filecounter = 1

    for f in scjson['files']:
        # skip directories, this needs the source code directory
        # to work correctly
        if os.path.isdir(f['path']):
            continue
        if os.path.basename(f['path']) in ignore:
            continue

        # store results
        sccopyrights = []
        sclicenses = []
        scstatements = set()
        if f['scan_errors'] != []:
            continue
        if f['authors'] != []:
            sccopyrights += f['authors']
        if f['copyrights'] != []:
            for u in f['copyrights']:
                scstatements.add(u['value'])
        if f['licenses'] != []:
            for u in f['licenses']:
                if u['spdx_license_key'] is not None:
                    sclicenses.append(u['spdx_license_key'])
                else:
                    sclicenses.append(u['short_name'])

        if args.ignore_empty:
            if scstatements == set() and sclicenses == []:
                continue

        if args.aggregate:
            aggregate_licenses.update(sclicenses)
            aggregate_statements.update(scstatements)
            continue

        # now pretty print
        licensestring = ''
        if sclicenses != []:
            licensestring = ", ".join(set(sclicenses))

        scstatements = sorted(list(scstatements))

        if output_format == 'text':
            print("%d - %s\n" % (filecounter, f['path'][pathlen:]), file=outfile)
            if sclicenses != []:
                print("License(s): %s\n" % licensestring, file=outfile)
            if scstatements != []:
                print("Statement(s): %s" % scstatements[0], file=outfile)
                if len(scstatements) > 1:
                    for i in scstatements[1:]:
                        print(i, file=outfile)
                print(file=outfile)
        elif output_format == 'csv':
            if scstatements == []:
                csvwriter.writerow([filecounter, f['path'][pathlen:], licensestring, ''])
            else:
                csvwriter.writerow([filecounter, f['path'][pathlen:],
                                    licensestring, scstatements[0]])
                for i in scstatements[1:]:
                    csvwriter.writerow(['', '', '', i])
        filecounter += 1

    if args.aggregate:
        if output_format == 'text':
            if aggregate_licenses != set():
                print("License(s):\n", file=outfile)
                for lic in sorted(list(aggregate_licenses)):
                    print(lic, file=outfile)
                print(file=outfile)
            if aggregate_statements != set():
                print("Statement(s):\n", file=outfile)
                for statement in sorted(list(aggregate_statements)):
                    print(statement, file=outfile)
                print(file=outfile)
        elif output_format == 'csv':
            # first write the header
            csvwriter.writerow(['Licenses', 'Statements'])
            licenses = sorted(list(aggregate_licenses))
            statements = sorted(list(aggregate_statements))
            for i in itertools.zip_longest(licenses, statements):
                csvwriter.writerow(i)

    if outfile_opened:
        outfile.close()

if __name__ == "__main__":
    main(sys.argv)
