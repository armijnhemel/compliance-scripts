#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2023 Armijn Hemel

import json
import os
import pathlib
import re
import sys

import click

# TODO: this will also partially match URLs
RE_PATH = re.compile(r'([/\-_a-z0-9\.]+\.[a-z0-9\+]+)', re.IGNORECASE)

FUNCTION_CALLS = re.compile(r'([a-z0-9_\.]+\(\))', re.IGNORECASE)

# TODO: verify if this is robust enough before using
FUNCTION_CALLS2 = re.compile(r'the ([a-z0-9_\.]+) function', re.IGNORECASE)

ANDROID_ID = re.compile(r' (A-[0-9]{8})')
ANDROID_ID2 = re.compile(r'ID:(A-[0-9]{8})')
QUALCOMM_REFERENCE = re.compile(r'(QC-CR#[0-9]{7})')
BROADCOM_REFERENCE = re.compile(r'(B-RB#[0-9]{5,6})')
BROADCOM_REFERENCE2 = re.compile(r'(BC?-V[0-9]{10})')
MEDIATEK_REFERENCE = re.compile(r'(MT?-ALPS[0-9]{8})')
MEDIATEK_REFERENCE2 = re.compile(r'Issue ID: (ALPS[0-9]{8})')
MEDIATEK_REFERENCE3 = re.compile(r'MediaTek internal bug (ALPS[0-9]{8})')
MEDIATEK_PATCH_ID = re.compile(r'Patch ID: (ALPS[0-9]{8})')
MEDIATEK_PATCH_ID2 = re.compile(r'Patch ID: (MOLY[0-9]{8})')
NVIDIA_REFERENCE = re.compile(r'(N-CVE-[0-9]{4}-[0-9]+)')
CVE_REFERENCE = re.compile(r'(CVE-[0-9]{4}-[0-9]+)')

VALID_EXTENSIONS_SRC = ['.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh',
                    '.hpp', '.hxx', '.h++', '.l', '.y', '.qml', '.s', '.txx',
                    '.dts', '.dtsi', '.java', '.jsp', '.groovy', '.scala',
                    '.kt', '.js', '.dart', '.py', '.pl', '.pm', '.php',
                    '.php3']

VALID_EXTENSIONS_BINARIES = ['.a', '.dll', '.exe']

@click.command(short_help='process CVE data and extract useful data')
#@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--cve-directory', '-d', required=True, help='CVE XML file', type=click.Path(exists=True, path_type=pathlib.Path))
def main(cve_directory):
    if not cve_directory.is_dir():
        raise click.BadParameter('parameter should be a directory')

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
            cve_result = {'cve': cve_number}

            # skip a bunch of CVEs. TODO: reserved CVEs
            if cve_json['cveMetadata']['state'] == 'REJECTED':
                continue
            tags = cve_json['containers']['cna'].get('tags', [])
            if 'disputed' in tags:
                continue

            skip_cve = False
            for description in cve_json['containers']['cna'].get('descriptions', []):
                if description['value'].startswith('** SPLIT **'):
                    skip_cve = True
                    break
                if description['value'].startswith('** UNVERIFIABLE **'):
                    skip_cve = True
                    break
                if description['value'].startswith('** UNVERIFIABLE, PRERELEASE **'):
                    skip_cve = True
                    break

                # CVEs for (older) unsupported software versions, unsure what to do here
                if description['value'].startswith('** PRODUCT NOT SUPPORTED WHEN ASSIGNED **'):
                    pass
                if description['value'].startswith('** UNSUPPORTED WHEN ASSIGNED **'):
                    pass
                if description['value'].startswith('**VERSION NOT SUPPORTED WHEN ASSIGNED**'):
                    pass

                # search for file paths
                verified_source_paths = set()
                verified_binary_paths = set()

                match_results = RE_PATH.findall(description['value'])

                if match_results != []:
                    for match in match_results:
                        match_path = pathlib.Path(match)
                        if match_path.suffix.lower() in VALID_EXTENSIONS_SRC:
                            verified_source_paths.add(match)
                        if match_path.suffix.lower() in VALID_EXTENSIONS_BINARIES:
                            verified_binary_paths.add(match)
                cve_result['source_paths'] = verified_source_paths
                cve_result['binary_paths'] = verified_binary_paths

                # search for function calls
                functions = set()

                match_results = FUNCTION_CALLS.findall(description['value'])

                if match_results != []:
                    for match in match_results:
                        functions.add(match)

                cve_result['functions'] = functions

                # search for Android IDs
                android_ids = set()

                match_results = ANDROID_ID.findall(description['value'])
                if match_results == []:
                    match_results = ANDROID_ID2.findall(description['value'])

                if match_results != []:
                    for match in match_results:
                        android_ids.add(match)

                cve_result['android_ids'] = android_ids

                # Various vendor references
                references = {}

                # search for Qualcomm reference
                match_results = QUALCOMM_REFERENCE.findall(description['value'])
                if match_results != []:
                    references['qualcomm'] = []
                    for match in match_results:
                        references['qualcomm'].append(match)

                # search for Broadcom reference
                match_results = BROADCOM_REFERENCE.findall(description['value'])
                if match_results == []:
                    match_results = BROADCOM_REFERENCE2.findall(description['value'])

                if match_results != []:
                    references['broadcom'] = []
                    # TODO: rewrite reference to standard format or keep variants?
                    for match in match_results:
                        references['broadcom'].append(match)

                # search for Mediatek reference
                match_results = MEDIATEK_REFERENCE.findall(description['value'])
                if match_results == []:
                    match_results = MEDIATEK_REFERENCE2.findall(description['value'])
                if match_results == []:
                    match_results = MEDIATEK_REFERENCE3.findall(description['value'])
                if match_results != []:
                    references['mediatek'] = []
                    # TODO: rewrite reference to standard format or keep variants?
                    for match in match_results:
                        references['mediatek'].append(match)

                # mediatek patches (TODO: should these be separate?)
                match_results = MEDIATEK_PATCH_ID.findall(description['value'])
                if match_results == []:
                    match_results = MEDIATEK_PATCH_ID2.findall(description['value'])
                if match_results != []:
                    references['mediatek-patch'] = []
                    for match in match_results:
                        references['mediatek-patch'].append(match)

                # NVIDIA reference
                match_results = NVIDIA_REFERENCE.findall(description['value'])
                if match_results != []:
                    references['nvidia'] = []
                    for match in match_results:
                        references['nvidia'].append(match)

                cve_result['vendor_references'] = references

                # other CVEs
                cve_references = set()
                match_results = CVE_REFERENCE.findall(description['value'])
                if match_results != []:
                    for match in match_results:
                        if match != cve_number:
                            cve_references.add(match)

                cve_result['cve_references'] = cve_references
                print(cve_result)
                print()

            if skip_cve:
                continue


if __name__ == "__main__":
    main()
