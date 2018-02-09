#!/usr/bin/python3

## Simple script that walks a directory tree to search for possible
## non-existent links in source code archives.
##
## Licensed under the terms of the General Public License version 3
##
## SPDX-License-Identifier: GPL-3.0-only
##
## Copyright 2018 - Armijn Hemel

import sys, os, argparse

def main(argv):
	parser = argparse.ArgumentParser()

	## the following options are provided on the commandline
	parser.add_argument("-d", "--directory", action="store", dest="dirtoscan", help="path to directory to scan", metavar="DIR")
	args = parser.parse_args()

	## first some sanity checks for the directory that needs to be scanned
	if args.dirtoscan == None:
		parser.error("Directory argument missing")

	if not os.path.exists(args.dirtoscan):
		parser.error("Directory %s does not exist" % args.dirtoscan)

	if not os.path.isdir(args.dirtoscan):
		parser.error("%s is not a directory" % args.dirtoscan)

	## first get rid of unnecessary path components
	dirtoscan = os.path.normpath(args.dirtoscan)

	dirwalker = os.walk(dirtoscan)

	for direntry in dirwalker:
		## now check 
		for directoryname in direntry[1]:
			if os.path.islink(os.path.join(direntry[0], directoryname)):
				linkname = os.path.join(direntry[0], directoryname)
				target = os.readlink(linkname)
				## then check if it exists.
				if not os.path.exists(os.path.join(os.path.dirname(linkname), target)):
					print("WARNING: Non-existing link for %s: %s\n" % (linkname, target))
		for filename in direntry[2]:
			if os.path.islink(os.path.join(direntry[0], filename)):
				linkname = os.path.join(direntry[0], filename)
				target = os.readlink(linkname)
				## then check if it exists.
				if not os.path.exists(os.path.join(os.path.dirname(linkname), target)):
					print("WARNING: Non-existing link for %s: %s\n" % (linkname, target))

if __name__ == "__main__":
	main(sys.argv)
