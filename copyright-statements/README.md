Script that takes a JSON output file from ScanCode, plus a directory path, and generates a simple notices file in text or CSV format. Included will be:

* license statements (in SPDX notation, or what ScanCode reports in case there is no SPDX equivalent)
* license texts (as extracted from the source code by ScanCode, or standard text from the SPDX license list data files in case no license text was extracted and there is a reference license text)
* copyright statements (as extracted by ScanCode)
* author statements (as extracted by ScanCode)

This is a very rough proof of concept script and results should not be used in a production environment, but could serve as a starting point for a proper notices file for inclusion in a product.

The following should be noted: this script only processes what ScanCode reports. If there is a bug in ScanCode, or if the output from ScanCode is not complete because it does not recognize for example a copyright statement or author statement, then it will not magically appear in the report. It should be noted that ScanCode will not catch every copyright/author statement.

ScanCode can be found here:

https://github.com/nexB/scancode-toolkit

The 'develop' branch is the most up to date and is the branch that should be used. This software will not work with older versions of ScanCode (2.x and earlier) and needs at least ScanCode 3.x.

This script is licensed under the GNU GPL 3 license.

SPDX-Identifier: GPL-3.0-only.

# Adding the SPDX license list data

If you have downloaded the code from a snapshot:

1. remove the directory 'license-list-data'
2. clone or download https://github.com/spdx/license-list-data and make sure that the data is unpacked to 'license-list-data'

If you have used Git you should do the following:

    $ git submodule init
    $ git submodule update

# Running the script

You can find the help for the program by running the following command:

    $ python3 createnotices.py --help

which will print:

    usage: createnotices.py [-h] [-j FILE] [-d DIR] [-f OUTPUT_FORMAT]
                            [-o FILE] [-z IGNORE_EMPTY] [-a AGGREGATE]

    optional arguments:
      -h, --help            show this help message and exit
      -j FILE, --json FILE  path to ScanCode JSON file
      -d DIR, --directory DIR
                            top level directory
      -f OUTPUT_FORMAT, --output-format OUTPUT_FORMAT
                            output format, supported values: 'csv', 'text'
                            (default)
      -o FILE, --output-file FILE
                            output file (mandatory for 'csv', otherwise stdout)
      -z IGNORE_EMPTY, --ignore-empty IGNORE_EMPTY
                            Ignore empty results (default: no)
      -a AGGREGATE, --aggregate AGGREGATE
                            Aggregate results (default: no)

To analyze results:

    $ python3 createnotices.py -j /path/to/scancode/json -d /path/to/source/code/directory

For example, if the directory /tmp/busybox-1.28.0/ contains source code that needs to be scanned, then ScanCode can be launched as follows (assuming that the "scancode" binary is in a directory in $PATH):

    $ scancode -l --license-text -c -e -u -n 8 --full-root --json-pp /tmp/scancode.json /tmp/busybox-1.28.0/

If "scancode" is not in a directory in $PATH, you will want to use:

    $ sh /path/to/scancode -l --license-text -c -e -u -n 8 --full-root --json-pp /tmp/scancode.json /tmp/busybox-1.28.0/

This will extract licenses and copyright statements, use 8 threads and write the results to a separate file and it prints the full path (this is necessary, as ScanCode sometimes removes directory names). Then:

    $ python3 createnotices.py -j /tmp/scancode.json -d /tmp/busybox-1.28.0/

This will print a lot of data on standard out. If you want to write it to a file you can supply a parameter:

    $ python3 createnotices.py -j /tmp/scancode.json -d /tmp/busybox-1.28.0/ -o /tmp/copyrights.txt

The command above will write the results to the file /tmp/copyrights.txt.

## Output

For each file the following will be printed:

* a sequence number
* the path relative to the root (the parameter given to "-d")
* any licenses found
* any copyright statements found
* any author statements found

For example:

    31 - archival/bbunzip.c
    
    License(s): GPL-2.0-only, GPL-2.0-or-later, Public Domain
    
    Statement(s): Copyright (c) 1992-1993 Jean-loup Gailly
    (c) 2002 Glenn McGrath
    Copyright (c) 2006 Aurelien Jacobs <aurel@gnuage.org>
    Copyright (c) 1992-1993 Jean-loup Gailly.

## Writing data as CSV

Data can also be written to CSV:

    $ python3 createnotices.py -j /tmp/scancode.json -d /tmp/busybox-1.28.0/ -f csv -o /tmp/copyrights.csv

Licenses will be concatenated, but copyright/author statements will not be and
if there is more than one author/copyright statement a new row will be used
for each statement > 1.

## Ignoring files without results

If only results with results should be processed you can specify a flag to ignore all empty results:

    $ python3 createnotices.py -j /tmp/scancode.json -d /tmp/busybox-1.28.0/ -o /tmp/copyrights.txt -z

## Aggregating results

If results should be aggregated instead of printed per file:

    $ python3 createnotices.py -j /tmp/scancode.json -d /tmp/busybox-1.28.0/ -o /tmp/copyrights.txt -a

It should be noted that when using aggregation in CSV mode the columns of the CSV file should be treated as independent columns. That means that in a row the results in the different columns will not be related to eachother.
