#!/usr/bin/env python3

# Copyright Armijn Hemel for Tjaldur Software Governance Solutions
# SPDX-Identifier: GPL-3.0-only

# This scripts processes output of ScanCode 3.0.x and outputs a file
# with license information and copyright statements per file.
# It requires that ScanCode is invoked with the --full-root option, for
# example:
#
# $ ./scancode --full-root -l --license-text -c -e -u --json-pp=/tmp/output.json /path/to/source/directory/
#
# When scanning the Linux kernel it is highly recommended to take advantage of
# the parallel processing options that ScanCode offers. For example, to run with
# eight processes at once:
#
# $ ./scancode --full-root -l --license-text -c -e -u -n 8 --json-pp=/tmp/output.json /path/to/source/directory/

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
            csvwriter.writerow(['Nr', 'File', 'License(s)', 'Statement(s)', 'Author(s)'])
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
    aggregate_authors = set()

    filecounter = 1

    # store any full license texts that might have been found
    license_texts = set()

    for f in scjson['files']:
        # skip directories, this needs the source code directory
        # to work correctly
        if os.path.isdir(f['path']):
            continue
        if os.path.basename(f['path']) in ignore:
            continue

        # store results
        scauthors = set()
        sclicenses = []
        scstatements = set()
        if f['scan_errors'] != []:
            continue
        if f['authors'] != []:
            for u in f['authors']:
                scauthors.add(u['value'])
        if f['copyrights'] != []:
            for u in f['copyrights']:
                scstatements.add(u['value'])
        if f['licenses'] != []:
            for u in f['licenses']:
                if u['spdx_license_key'] is not None:
                    sclicenses.append(u['spdx_license_key'])
                else:
                    sclicenses.append(u['short_name'])
                if u['matched_rule'] is not None:
                    if u['matched_rule']['is_license_text']:
                        if 'matched_text' in u:
                            license_texts.add(u['matched_text'])

        if args.ignore_empty:
            if scstatements == set() and sclicenses == []:
                continue

        if args.aggregate:
            aggregate_licenses.update(sclicenses)
            aggregate_statements.update(scstatements)
            aggregate_authors.update(scauthors)
            continue

        # now pretty print
        licensestring = ''
        if sclicenses != []:
            licensestring = ", ".join(set(sclicenses))

        scstatements = sorted(list(scstatements))
        scauthors = sorted(list(scauthors))

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
            if scauthors != []:
                print("Authors(s): %s" % scauthors[0], file=outfile)
                if len(scauthors) > 1:
                    for i in scauthors[1:]:
                        print(i, file=outfile)
                print(file=outfile)
        elif output_format == 'csv':
            firststatement = ''
            firstauthor = ''
            if scstatements != []:
                firststatement = scstatements[0]
            if scauthors != []:
                firstauthor = scauthors[0]
            csvwriter.writerow([filecounter, f['path'][pathlen:], licensestring, firststatement, firstauthor])
            if scstatements != [] or scauthors != []:
                isfirst = True
                for i in itertools.zip_longest(scstatements, scauthors):
                    if isfirst:
                        isfirst = False
                        continue
                    csvwriter.writerow(['', '', '', i[0], i[1]])
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
            if aggregate_authors != set():
                print("Author(s):\n", file=outfile)
                for statement in sorted(list(aggregate_authors)):
                    print(statement, file=outfile)
                print(file=outfile)
            if license_texts != set():
                print("License text(s):\n", file=outfile)
                for license_text in sorted(list(license_texts)):
                    print(f"{80*'-'}\n", file=outfile)
                    print(license_text, file=outfile)
                    print(file=outfile)
                print(file=outfile)
        elif output_format == 'csv':
            # first write the header
            csvwriter.writerow(['License(s)', 'Statement(s)', 'Author(s)'])
            licenses = sorted(list(aggregate_licenses))
            statements = sorted(list(aggregate_statements))
            authors = sorted(list(aggregate_authors))
            for i in itertools.zip_longest(licenses, statements, authors):
                csvwriter.writerow(i)

    if outfile_opened:
        outfile.close()

if __name__ == "__main__":
    main(sys.argv)
