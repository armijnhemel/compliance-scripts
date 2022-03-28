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

# https://cve.mitre.org/data/downloads/allitems.xml.gz


@click.command(short_help='process CVE data and extract useful data')
#@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--cve', '-f', required=True, help='CVE XML file', type=click.File('r'))
def main(cve):
    # first some sanity checks, try to parse the contents of the file
    # TODO: for speed this might be more useful to do as a SAX parser
    # than a DOM parser.
    cve_dom = defusedxml.minidom.parse(cve)

    cve_to_url = {}
    url_to_cve = {}

    for cve_report in cve_dom.getElementsByTagName('item'):
        cve_number = cve_report.attributes['name'].value
        references = cve_report.getElementsByTagName('refs')[0].childNodes
        for r in references:
            if r.nodeName == 'ref':
                src = r.getAttribute('source')
                if r.hasAttribute('url'):
                    cve_url = r.getAttribute('url')
                    if cve_number not in cve_to_url:
                        cve_to_url[cve_number] = []
                    cve_to_url[cve_number].append(cve_url)

                    if cve_url not in url_to_cve:
                        url_to_cve[cve_url] = []

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

    for cve in cve_to_cve:
        print(cve, sorted(cve_to_cve[cve]))


if __name__ == "__main__":
    main()
