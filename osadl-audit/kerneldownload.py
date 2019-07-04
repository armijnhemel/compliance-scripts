#!/usr/bin/env python3

# simple downloader for Linux kernel source code files
# from the official Linux kernel download site
# Copyright Armijn Hemel 2018-2019
# Licensed under the terms of the GPLv3 license
# SPDX-License-Identifier: GPL-3.0-only

import os
import sys
import tempfile
import subprocess
import json
import hashlib
import argparse
import re
import requests

# TODO: verify contents of sha256sums.asc
#import gnupg

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--directory", action="store",
                    dest="storedirectory",
                    help="path to directory to store files",
                    metavar="DIR")
args = parser.parse_args()

# checks for the scandirectory
if args.storedirectory is None:
    parser.error("Directory for storing files")

if not os.path.exists(args.storedirectory):
    print("Store directory does not exist: %s" % args.storedirectory,
          file=sys.stderr)
    sys.exit(1)

# then rewrite the path to an absolute path
if not os.path.isabs(args.storedirectory):
    storedirectory = os.path.normpath(os.path.join(os.getcwd(), args.storedirectory))
else:
    storedirectory = args.storedirectory

baseurl = 'https://cdn.kernel.org/pub/linux/kernel'

kernelsubdirs = ['v1.0', 'v1.1', 'v1.2', 'v1.3', 'v2.0', 'v2.1', 'v2.2',
                 'v2.3', 'v2.4', 'v2.5', 'v2.6', 'v2.6/longterm/v2.6.27',
                 'v2.6/longterm/v2.6.32', 'v2.6/longterm/v2.6.33',
                 'v2.6/longterm/v2.6.34', 'v2.6/longterm/v2.6.35',
                 'v3.x', 'v4.x', 'v5.x']

filenametochecksum = {}
faileddownloads = set()
downloadurls = {}

for k in kernelsubdirs:
    filestofetch = []
    kernelurl = "%s/%s/%s" % (baseurl, k, 'sha256sums.asc')
    r = requests.get(kernelurl)
    if r.status_code != 200:
        continue

    # grab the response as text (so it already decompressed it in case it was gzip compressed
    # which seems to be the case)
    pgpchecksums = r.text
    if 'PGP' in pgpchecksums:
        p = subprocess.Popen(["gpg"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, encoding='utf8')
        checksums = p.communicate(pgpchecksums)[0].strip()
    else:
        checksums = pgpchecksums
    for i in checksums.split('\n'):
        print(i)
        if i is not None:
            (checksum, filename) = i.split()
            if 'linux' in filename and 'tar.xz' in filename:
                if 'badsig' in filename:
                    continue
                filenametochecksum[filename] = checksum
                kernelurl = "%s/%s/%s" % (baseurl, k, filename)
                downloadurls[filename] = kernelurl
                if not os.path.exists(os.path.join(storedirectory, filename)):
                    filestofetch.append(filename)

    # now fetch each individual source code archive file
    for i in filestofetch:
        print("downloading %s" % i)
        kernelurl = "%s/%s/%s" % (baseurl, k, i)
        try:
            r = requests.get(kernelurl)
            if r.status_code != 200:
                continue
        except:
            print("downloading failed %s\n" % i)
            faileddownloads.add(kernelurl)
            continue
        print("computing SHA256 for %s" % i)
        h = hashlib.new('sha256')
        h.update(r.content)
        if h.hexdigest() != filenametochecksum[i]:
            print("corrupt download %s\n" % i)
            faileddownloads.add(kernelurl)
            continue
        print("writing %s\n" % i)
        outfile = open(os.path.join(storedirectory, i), 'wb')
        outfile.write(r.content)
        outfile.flush()
        outfile.close()

# read information for already downloaded files from an existing archives.json
if os.path.exists(os.path.join(storedirectory, 'archives.json')):
    archivejsonfile = open(os.path.join(storedirectory, 'archives.json'))
    archivejson = json.load(archivejsonfile)
    archivejsonfile.close()
    for a in archivejson:
        if 'filename' in a and 'checksum' in a:
            if a['filename'] in filenametochecksum:
                if a['checksum'] == filenametochecksum[a['filename']]:
                    continue
            else:
                filenametochecksum[a['filename']] = a['checksum']

# now create the JSON
kernelfiles = os.listdir(storedirectory)
kernelfiles.sort()

outjson = []

versionre = re.compile('linux-([\w\d\.\-]+).tar.xz$')

for filename in kernelfiles:
    if 'linux' in filename and 'tar.xz' in filename:
        versionres = versionre.match(filename)
        version = None
        if versionres is not None:
            version = versionres.groups()[0]
        if filename not in filenametochecksum:
            kernelfile = open(os.path.join(storedirectory, filename), 'rb')
            kerneldata = kernelfile.read()
            kernelfile.close()
            h = hashlib.new('sha256')
            h.update(kerneldata)
            checksum = h.hexdigest()
            filenametochecksum[filename] = checksum
        outjson.append({'filename': filename,
                        'sha256': filenametochecksum[filename],
                        'website': 'https://www.kernel.org/',
                        'project': 'Linux kernel',
                        'downloadurl': downloadurls[filename],
                        'package': 'linux',
                        'version': version})

# write JSON to output file
archivejsonfile = open(os.path.join(storedirectory, 'archives.json'), 'w')
archivejsonfile.write(json.dumps(outjson))
archivejsonfile.close()

# report on any failed downloads
for i in faileddownloads:
    print("Failed to download:", i)
