#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Armijn Hemel

import os
import pathlib
import re
import sys
import xml.dom

import click
import defusedxml.minidom

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

VALID_EXTENSIONS = ['.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp',
                    '.hxx', '.h++', '.l', '.y', '.qml', '.s', '.txx', '.dts',
                    '.dtsi', '.java', '.jsp', '.groovy', '.scala', '.kt',
                    '.js', '.dart', '.py', '.pl', '.pm']

@click.command(short_help='process CVE data and extract useful data')
#@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--cve', '-f', required=True, help='CVE XML file', type=click.File('r'))
def main(cve):
    # first some sanity checks, try to parse the contents of the file
    # TODO: for speed this might be more useful to do as a SAX parser
    # than a DOM parser.
    cve_dom = defusedxml.minidom.parse(cve)

    for cve_report in cve_dom.getElementsByTagName('item'):
        cve_number = cve_report.attributes['name'].value
        description = cve_report.getElementsByTagName('desc')[0].childNodes[0].data
        if description.startswith('** RESERVED **'):
            # CVE not yet assigned
            continue

        # skip a bunch of CVEs
        if description.startswith('** DISPUTED **'):
            continue
        if description.startswith('** REJECT **'):
            continue
        if description.startswith('**REJECT**'):
            continue
        if description.startswith('** SPLIT **'):
            continue
        if description.startswith('** UNVERIFIABLE **'):
            continue
        if description.startswith('** UNVERIFIABLE, PRERELEASE **'):
            continue

        # CVEs for (older) unsupported software versions
        if description.startswith('** PRODUCT NOT SUPPORTED WHEN ASSIGNED **'):
            pass
        if description.startswith('** UNSUPPORTED WHEN ASSIGNED **'):
            pass
        if description.startswith('**VERSION NOT SUPPORTED WHEN ASSIGNED**'):
            pass

        cve_result = {'cve': cve_number}

        # search for file paths
        verified_paths = set()

        match_results = RE_PATH.findall(description)

        if match_results != []:
            for match in match_results:
                match_path = pathlib.Path(match)
                if match_path.suffix in VALID_EXTENSIONS:
                    verified_paths.add(match)

        cve_result['paths'] = verified_paths

        # search for function calls
        functions = set()

        match_results = FUNCTION_CALLS.findall(description)

        if match_results != []:
            for match in match_results:
                functions.add(match)

        cve_result['functions'] = functions

        # search for Android IDs
        android_ids = set()

        match_results = ANDROID_ID.findall(description)
        if match_results == []:
            match_results = ANDROID_ID2.findall(description)

        if match_results != []:
            for match in match_results:
                android_ids.add(match)

        cve_result['android_ids'] = android_ids

        # Various vendor references
        references = {}

        # search for Qualcomm reference
        match_results = QUALCOMM_REFERENCE.findall(description)
        if match_results != []:
            references['qualcomm'] = []
            for match in match_results:
                references['qualcomm'].append(match)

        # search for Broadcom reference
        match_results = BROADCOM_REFERENCE.findall(description)
        if match_results == []:
            match_results = BROADCOM_REFERENCE2.findall(description)

        if match_results != []:
            references['broadcom'] = []
            # TODO: rewrite reference to standard format or keep variants?
            for match in match_results:
                references['broadcom'].append(match)

        # search for Mediatek reference
        match_results = MEDIATEK_REFERENCE.findall(description)
        if match_results == []:
            match_results = MEDIATEK_REFERENCE2.findall(description)
        if match_results == []:
            match_results = MEDIATEK_REFERENCE3.findall(description)
        if match_results != []:
            references['mediatek'] = []
            # TODO: rewrite reference to standard format or keep variants?
            for match in match_results:
                references['mediatek'].append(match)

        # mediatek patches (TODO: should these be separate?)
        match_results = MEDIATEK_PATCH_ID.findall(description)
        if match_results == []:
            match_results = MEDIATEK_PATCH_ID2.findall(description)
        if match_results != []:
            references['mediatek-patch'] = []
            for match in match_results:
                references['mediatek-patch'].append(match)

        # NVIDIA reference
        match_results = NVIDIA_REFERENCE.findall(description)
        if match_results != []:
            references['nvidia'] = []
            for match in match_results:
                references['nvidia'].append(match)

        cve_result['vendor_references'] = references

        # other CVEs
        cve_references = []
        match_results = CVE_REFERENCE.findall(description)
        if match_results != []:
            for match in match_results:
                if match != cve_number:
                    cve_references.append(match)

        cve_result['cve_references'] = cve_references
        print(cve_result)
        print()



if __name__ == "__main__":
    main()
