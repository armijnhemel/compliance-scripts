#!/usr/bin/python3

## simple downloader for Linux kernel source code files from the official Linux kernel download site
## Copyright Armijn Hemel 2018
## Licensed under the terms of the GPLv3 license
## SPDX-License-Identifier: GPL-3.0-only

import os, sys, tempfile, subprocess, json, hashlib, argparse
import requests

## TODO: verify contents of sha256sums.asc
#import gnupg

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--directory", action="store", dest="storedirectory", help="path to directory to store files", metavar="DIR")
args = parser.parse_args()

## checks for the scandirectory
if args.storedirectory == None:
	parser.error("Directory for storing files")

if not os.path.exists(args.storedirectory):
	print("Store directory does not exist: %s" % args.storedirectory, file=sys.stderr)
	sys.exit(1)

## then rewrite the path to an absolute path
if not os.path.isabs(args.storedirectory):
	storedirectory = os.path.normpath(os.path.join(os.getcwd(), args.storedirectory))
else:
	storedirectory = args.storedirectory

baseurl = 'https://cdn.kernel.org/pub/linux/kernel'

kernelsubdirs = ['v1.0', 'v1.1', 'v1.2', 'v1.3', 'v2.0', 'v2.1', 'v2.2', 'v2.3', 'v2.4', 'v2.5', 'v2.6', 'v2.6/longterm/v2.6.27', 'v2.6/longterm/v2.6.32', 'v2.6/longterm/v2.6.33', 'v2.6/longterm/v2.6.34', 'v2.6/longterm/v2.6.35', 'v3.0', 'v3.x', 'v4.x']

filenametochecksum = {}
faileddownloads = set()
downloadurls = {}

for k in kernelsubdirs:
	filestofetch = set()
	kernelurl = "%s/%s/%s" % (baseurl, k, 'sha256sums.asc')
	r = requests.get(kernelurl)
	if r.status_code != 200:
		continue

	## grab the response as text (so it already decompressed it in case it was gzip compressed
	## which seems to be the case)
	pgpchecksums = r.text
	if 'PGP' in pgpchecksums:
		p = subprocess.Popen(["gpg"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8')
		checksums = p.communicate(pgpchecksums)[0].strip()
	else:
		checksums = pgpchecksums
	for i in checksums.split('\n'):
		if i != None:
			(checksum, filename) = i.split()
			if 'linux' in filename and 'tar.xz' in filename:
				if 'badsig' in filename:
					continue
				filenametochecksum[filename] = checksum
				kernelurl = "%s/%s/%s" % (baseurl, k, filename)
				downloadurls[filename] = kernelurl
				if not os.path.exists(os.path.join(storedirectory, filename)):
					filestofetch.add(filename)

	## now fetch each individual source code archive file
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
			print("corrupt download %s\n" %i)
			faileddownloads.add(kernelurl)
			continue
		print("writing %s\n" % i)
		outfile = open(os.path.join(storedirectory, i), 'wb')
		outfile.write(r.content)
		outfile.flush()
		outfile.close()

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

print(downloadurls)

## now write the JSON
kernelfiles = os.listdir(storedirectory)

outjson = []

for filename in kernelfiles:
	if 'linux' in filename and 'tar.xz' in filename:
		if filename in filenametochecksum:
			outjson.append({'filename': filename, 'checksum': checksum, 'website': 'https://www.kernel.org/', 'project': 'linux', 'downloadurl': downloadurls[filename]})
		else:
			kernelfile = open(os.path.join(storedirectory, filename), 'rb')
			kerneldata = kernelfile.read()
			kernelfile.close()
			h = hashlib.new('sha256')
			h.update(kerneldata)
			checksum = h.hexdigest()
			filenametochecksum[filename] = checksum
			outjson.append({'filename': filename, 'checksum': checksum, 'website': 'https://www.kernel.org/', 'project': 'linux', 'downloadurl': downloadurls[filename]})

archivejsonfile = open(os.path.join(storedirectory, 'archives.json'), 'w')
archivejsonfile.write(json.dumps(outjson))
archivejsonfile.close()

for i in faileddownloads:
	print("Failed to download:", i)
