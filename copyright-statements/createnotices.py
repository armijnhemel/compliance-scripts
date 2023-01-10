#!/usr/bin/env python3

# Copyright Armijn Hemel for Tjaldur Software Governance Solutions
# SPDX-Identifier: GPL-3.0-only

# This scripts processes output of ScanCode 3.0.x and outputs a file
# with license information, author information and copyright statements,
# either per file, or aggregated.
#
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
    parser.add_argument("-e", "--extended", action="store_true", dest="extended",
                        help="Extended aggregated results")
    parser.add_argument("-i", "--filter-patterns", action="store", dest="filterpatterns",
                        help="file with filter patterns (extensions)", metavar="FILE")
    parser.add_argument("-s", "--skip-patterns", action="store", dest="skip_patterns",
                        help="file with filter patterns (extensions)", metavar="FILE")
    parser.add_argument("-l", "--license-filter", action="store", dest="filter_licenses",
                        help="file with licenses to report", metavar="FILE")
    parser.add_argument("-p", "--path-filter", action="store", dest="pathfilter",
                        help="only process paths under this parameter", metavar="FILE")
    parser.add_argument("-r", "--reverse", action="store", dest="reverse_output",
                        help="print license to files", metavar="FILE")
    args = parser.parse_args()

    # sanity checks for the various options
    if args.jsonfile is None:
        parser.error("ScanCode JSON file missing")

    if not os.path.exists(args.jsonfile):
        parser.error("ScanCode JSON file does not exist")

    if not os.path.isfile(args.jsonfile):
        parser.error("ScanCode JSON file is not a file")

    filter_licenses = set()

    if args.filter_licenses is not None:
        if not os.path.exists(args.filter_licenses):
            parser.error("Filter patterns file does not exist")

        if not os.path.isfile(args.filter_licenses):
            parser.error("Filter patterns file is not a file")
        try:
            filterpatternsfile = open(args.filter_licenses, 'r')
            for line in filterpatternsfile:
                filterpattern = line.rstrip()

                # skip empty lines
                if filterpattern == '':
                    continue

                # skip comment lines with #
                if filterpattern.startswith('#'):
                    continue

                filter_licenses.add(filterpattern)
            filterpatternsfile.close()
        except Exception:
            parser.error("Could not open filter patterns file %s" % args.filter_licenses, e)

    filterpatterns = []

    if args.filterpatterns is not None:
        if not os.path.exists(args.filterpatterns):
            parser.error("Filter patterns file does not exist")

        if not os.path.isfile(args.filterpatterns):
            parser.error("Filter patterns file is not a file")
        try:
            filterpatternsfile = open(args.filterpatterns, 'r')
            for line in filterpatternsfile:
                filterpattern = line.rstrip()

                # skip empty lines
                if filterpattern == '':
                    continue

                # skip comment lines with #
                if filterpattern.startswith('#'):
                    continue

                filterpatterns.append(filterpattern)
            filterpatternsfile.close()
        except Exception:
            parser.error("Could not open filter patterns file %s" % args.filterpatterns, e)

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
    except Exception as e:
        print(e)
        print("Cannot parse ScanCode JSON, exiting", file=sys.stderr)
        sys.exit(1)

    # store if a real file was opened, or stdout is used
    outfile_opened = False

    # store whether or not the spdx master data repo
    # has been added as a submodule
    have_spdx_data = False
    if os.path.exists('license-list-data/text'):
        have_spdx_data = True
        spdxdir = 'license-list-data/text'

    license_to_files = {}

    # open an output file for writing (could be stdout)
    if output_format == 'csv':
        try:
            outfile = open(args.output_file, 'w')
        except:
            print("Could not open %s for writing CSV data" % args.output_file, file=sys.stderr)
            sys.exit(1)
        csvwriter = csv.writer(outfile)
        if not args.aggregate:
            csvwriter.writerow(['Nr', 'File', 'License(s)', 'License text(s)', 'Statement(s)', 'Author(s)'])
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

    pathlen = len(args.toplevel)

    # data structures for aggregated data
    # used in case the 'aggregate' flag is set
    aggregate_license_statements = set()
    aggregate_statements = set()
    aggregate_authors = set()
    aggregate_license_texts = set()
    aggregate_license_spdx_texts = set()

    filecounter = 1

    skip_patterns = ['spdx-license-ids/index.json',
                     'spdx-license-ids/deprecated.json',
                     'spdx-license-ids/index.json',
                     'spdx-license-ids/README.md',
                     'spdx-license-ids/README.md']
    # process each result from the JSON file generated by ScanCode.
    # If aggregation is enabled data will only be stored and pretty printed
    # later. If no aggregation is used then the results will be printed
    # for each result immediately.
    for f in scjson['files']:
        # skip anything but files
        if f['type'] != 'file':
            continue
        filename = f['path'][pathlen:]
        skip = False
        for filterpattern in filterpatterns:
            if f['path'].endswith(filterpattern):
                skip = True
                break
        for s in skip_patterns:
            if s in f['path']:
                skip = True
                break
        if skip:
            continue
        if args.pathfilter is not None:
            #if not f['path'].startswith(args.pathfilter):
            if not filename.startswith(args.pathfilter):
                continue

        # store results
        scauthors = set()
        sclicense_statements = set()
        scstatements = set()
        sclicense_texts = set()
        sclicense_spdx_texts = set()

        if filter_licenses == set():
            report_license = True
        else:
            report_license = False

        if f['scan_errors'] != []:
            continue
        if f['authors'] != []:
            for author in f['authors']:
                scauthors.add(author['author'])
        if f['copyrights'] != []:
            for u in f['copyrights']:
                scstatements.add(u['copyright'])
        if f['license_detections'] != []:
            for u in f['license_detections']:
                if 'matches' not in u:
                    continue

                for match in u['matches']:
                    if 'licenses' not in match:
                        continue

                    for l in match['licenses']:
                        if l['spdx_license_key'] is not None:
                            sclicense_statements.add(l['spdx_license_key'])
                            license_key = l['spdx_license_key']
                            if license_key in filter_licenses:
                                report_license = True
                            if not l['spdx_license_key'] in license_to_files:
                                license_to_files[l['spdx_license_key']] = []
                            license_to_files[l['spdx_license_key']].append(filename)
                        else:
                            sclicense_statements.add(l['short_name'])
                            license_key = l['short_name']
                            if license_key in filterlicenses:
                                report_license = True
                            if not l['short_name'] in license_to_files:
                                license_to_files[l['short_name']] = []
                            license_to_files[l['short_name']].append(filename)

        if not report_license:
            continue

        if args.ignore_empty:
            if scstatements == set() and sclicense_statements == set() and scauthors == set():
                continue

        if args.aggregate:
            # aggregation is enabled, so just store the results
            # found and continue to the next entry.
            aggregate_license_statements.update(sclicense_statements)
            aggregate_license_texts.update(sclicense_texts)
            aggregate_license_spdx_texts.update(sclicense_spdx_texts)
            aggregate_statements.update(scstatements)
            aggregate_authors.update(scauthors)
            continue

        if args.extended:
            aggregate_license_texts.update(sclicense_texts)
            aggregate_license_spdx_texts.update(sclicense_spdx_texts)

        # first convert the copyright statements and author statements to
        # a list so they can be sorted, which is nicer for pretty printing
        scstatements = sorted(list(scstatements))
        scauthors = sorted(list(scauthors))
        sclicense_statements = sorted(list(sclicense_statements))
        sclicense_texts = sorted(list(sclicense_texts))
        #sclicense_spdx_texts = sorted(list(sclicense_spdx_texts))

        if output_format == 'text':
            print("%d - %s\n" % (filecounter, filename), file=outfile)
            if sclicense_statements != []:
                print("License(s):\n%s" % sclicense_statements[0], file=outfile)
                if len(sclicense_statements) > 1:
                    for i in sclicense_statements[1:]:
                        print(i, file=outfile)
                print(file=outfile)
            if scstatements != []:
                print("Statement(s):\n%s" % scstatements[0], file=outfile)
                if len(scstatements) > 1:
                    for i in scstatements[1:]:
                        print(i, file=outfile)
                print(file=outfile)
            if scauthors != []:
                print("Authors(s):\n%s" % scauthors[0], file=outfile)
                if len(scauthors) > 1:
                    for i in scauthors[1:]:
                        print(i, file=outfile)
                print(file=outfile)
            if sclicense_texts != [] and not args.extended:
                print("License text(s):\n%s" % sclicense_texts[0], file=outfile)
                if len(sclicense_texts) > 1:
                    for i in sclicense_texts[1:]:
                        print(i, file=outfile)
                print(file=outfile)
        elif output_format == 'csv':
            # create at least one line per file with license statement,
            # license text, copyright statement and author statement
            first_copyright_statement = ''
            first_author_statement = ''
            first_license_statement = ''
            first_license_text = ''
            if scstatements != []:
                first_copyright_statement = scstatements[0]
            if scauthors != []:
                first_author_statement = scauthors[0]
            if sclicense_statements != []:
                first_license_statement = sclicense_statements[0]
            if sclicense_texts != []:
                first_license_text = sclicense_texts[0]
            csvwriter.writerow([filecounter, filename, first_license_statement, first_license_text, first_copyright_statement, first_author_statement])
            if scstatements != [] or scauthors != []:
                isfirst = True
                for i in itertools.zip_longest(sclicense_statements, sclicense_texts, scstatements, scauthors):
                    if isfirst:
                        isfirst = False
                        continue
                    csvwriter.writerow(['', '', i[0], i[1], i[2], i[3]])
        filecounter += 1

    # pretty printing in case results need to be aggregated
    if args.aggregate:
        if output_format == 'text':
            if aggregate_license_statements != set():
                print("License(s):\n", file=outfile)
                for lic in sorted(list(aggregate_license_statements)):
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
            if aggregate_license_texts != set():
                print("License text(s):\n", file=outfile)
                for license_text in sorted(list(aggregate_license_texts)):
                    print(80*'-', file=outfile)
                    print(file=outfile)
                    print(license_text, file=outfile)
                    print(file=outfile)
                print(file=outfile)
        elif output_format == 'csv':
            # first write the header
            csvwriter.writerow(['License(s)', 'License text(s)', 'Statement(s)', 'Author(s)'])
            license_statements = sorted(list(aggregate_license_statements))
            license_texts = sorted(list(aggregate_license_texts))
            copyright_statements = sorted(list(aggregate_statements))
            authors = sorted(list(aggregate_authors))
            for i in itertools.zip_longest(license_statements, license_texts, copyright_statements, authors):
                csvwriter.writerow(i)

    if args.extended:
        if output_format == 'text':
            if aggregate_license_texts != set():
                print("License text(s):\n", file=outfile)
                for license_text in sorted(list(aggregate_license_texts)):
                    print(80*'-', file=outfile)
                    print(file=outfile)
                    print(license_text, file=outfile)
                    print(file=outfile)
                print(file=outfile)
    if outfile_opened:
        outfile.close()
    license_nr = 1
    print("Total licenses:", len(license_to_files))
    print()
    for i in license_to_files:
       print(license_nr, i)
       print('---------')
       filecounter = 1
       for j in sorted(list(set(license_to_files[i]))):
           print(filecounter, j)
           filecounter+=1
       print()
       license_nr += 1

if __name__ == "__main__":
    main(sys.argv)
