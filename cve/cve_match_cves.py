#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Armijn Hemel

import json
import os
import pathlib
import sys

import click

# https://www.cve.org/Downloads


@click.command(short_help='process CVE data and extract useful data')
#@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--cve-directory', '-d', required=True, help='directory with CVE JSON files',
              type=click.Path(exists=True, path_type=pathlib.Path))
def main(cve_directory):
    if not cve_directory.is_dir():
        raise click.BadParameter('parameter should be a directory')

    cve_to_url = {}
    url_to_cve = {}

    for cve_report in cve_directory.glob('**/*.json'):
        with open(cve_report, 'r') as cve_json_file:
            try:
                cve_json = json.load(cve_json_file)
            except (json.decoder.JSONDecodeError, NameError):
                print(f'Invalid JSON in {cve_report}, exiting', file=sys.stderr)
                sys.exit(1)
            if not 'cveMetadata' in cve_json:
                # this is probably the metadata file
                continue
            cve_number = cve_json['cveMetadata']['cveId']
            if cve_number not in cve_to_url:
                cve_to_url[cve_number] = []

            if 'references' in cve_json['containers']['cna']:
                for c_url in cve_json['containers']['cna']['references']:
                    cve_url = c_url['url']
                    if cve_url not in url_to_cve:
                        url_to_cve[cve_url] = []

                    cve_to_url[cve_number].append(cve_url)
                    url_to_cve[cve_url].append(cve_number)

    cve_to_cve = {}

    for cve in cve_to_url:
        for cve_url in cve_to_url[cve]:
            if len(url_to_cve[cve_url]) != 1:
                if not cve in cve_to_cve:
                    cve_to_cve[cve] = set()
                for c in url_to_cve[cve_url]:
                    if c == cve:
                        continue
                    cve_to_cve[cve].add(c)

    for cve in sorted(cve_to_cve):
        related_cves = len(cve_to_cve[cve])
        print(f'{cve} has {related_cves} related CVEs')


if __name__ == "__main__":
    main()
