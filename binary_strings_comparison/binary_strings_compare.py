#!/usr/bin/env python3

# Licensed under the terms of the Apache license
# SPDX-License-Identifier: Apache-2.0

import difflib
import hashlib
import pathlib
import subprocess
import sys

from typing import Any

import click

@click.command(short_help='Compare two directories of ELF files and write diffs')
@click.option('--first-directory', '-f', required=True, help='first directory',
               type=click.Path(path_type=pathlib.Path, exists=True))
@click.option('--second-directory', '-s', required=True, help='second directory',
               type=click.Path(path_type=pathlib.Path, exists=True))
@click.option('--diff-directory', '-d', required=True, help='second directory',
               type=click.Path(path_type=pathlib.Path, exists=True))
@click.option('--verbose', '-v', is_flag=True, help='be verbose')
def main(first_directory, second_directory, diff_directory, verbose):
    if not first_directory.is_dir():
        print(f"Directory {first_directory} is not a valid directory, exiting.",
              file=sys.stderr)
        sys.exit(1)
    if not second_directory.is_dir():
        print(f"Directory {second_directory} is not a valid directory, exiting.",
              file=sys.stderr)
        sys.exit(1)

    if not diff_directory.is_dir():
        print(f"Directory {diff_directory} is not a valid directory, exiting.",
              file=sys.stderr)
        sys.exit(1)

    first_directory_found = set()
    second_directory_found = set()

    first_directory_paths = set()
    second_directory_paths = set()

    # process all the JSON files in the directory
    for result_file in first_directory.glob('**/*'):
        if not result_file.is_file():
            continue
        if result_file.is_symlink():
            continue
        # open the file and read the first 4 bytes to
        # see if it is an ELF file
        with open(result_file, 'rb') as open_file:
            magic = open_file.read(4)
        if magic != b'\x7fELF':
            continue

        with open(result_file, 'rb') as open_file:
            file_hash = hashlib.sha256(open_file.read()).hexdigest()
        first_directory_found.add((result_file.relative_to(first_directory), file_hash))
        first_directory_paths.add(result_file.relative_to(first_directory))

    for result_file in second_directory.glob('**/*'):
        if not result_file.is_file():
            continue
        if result_file.is_symlink():
            continue
        # open the file and read the first 4 bytes to
        # see if it is an ELF file
        with open(result_file, 'rb') as open_file:
            magic = open_file.read(4)
        if magic != b'\x7fELF':
            continue

        with open(result_file, 'rb') as open_file:
            file_hash = hashlib.sha256(open_file.read()).hexdigest()
        second_directory_found.add((result_file.relative_to(second_directory), file_hash))
        second_directory_paths.add(result_file.relative_to(second_directory))

    identical_files = set([x[0] for x in first_directory_found.intersection(second_directory_found)])

    if verbose:
        for f in sorted(identical_files):
            print("Identical in both:", f)
        # files in first_directory but not in second directory
        for f in sorted(first_directory_paths.difference(second_directory_paths)):
            print("In first directory, but not in second:", f)
        for f in sorted(second_directory_paths.difference(first_directory_paths)):
            print("In second directory, but not in first:", f)

    for f in sorted(first_directory_paths):
        if f not in identical_files:
            if f in second_directory_paths:
                # grab the strings of the first instance
                p = subprocess.Popen(['strings', first_directory / f], stdout=subprocess.PIPE)
                first_stdout, _ = p.communicate()

                # grab the strings of the second instance
                p = subprocess.Popen(['strings', second_directory / f], stdout=subprocess.PIPE)
                second_stdout, _ = p.communicate()

                parent_dir = f.parent
                if str(parent_dir) not in ['', '/']:
                    parent_dir_full = diff_directory / parent_dir
                    parent_dir_full.mkdir(parents=True, exist_ok=True)
                with open(diff_directory / f, 'w') as out:
                    diff_result = difflib.unified_diff(first_stdout.decode().splitlines(), second_stdout.decode().splitlines(),
                                  fromfile=f'a/{f}', tofile=f'b/{f}', lineterm='')
                    for l in diff_result:
                        out.write(l)
                        out.write('\n')

if __name__ == "__main__":
    main()
