#!/usr/bin/python3

# This script walks a directory of files extracts symbols from ELF files,
# records dependencies (taking symbolic links and RPATH into account) and
# constructs Cypher statements to load it into Neo4J to enable queries.
#
# The method works as follows:
#
# 1. walk a directory of files and store:
#    a) names of dynamically ELF files
#    b) symbols defined by the ELF files (including visibility,
#       type and binding)
#    c) symbols exported by the ELF files (including binding, type, and so on)
#    d) dependencies declared in dynamically linked files,
#       possibly indirect (symbolic links)
#
# 2. for each group of binaries (architecture, endianness, etc.) it
#    will then generate a Cypher file with all the information from 1.
#
# The typical use case would be a firmware of an embedded system that
# has been unpacked first into a separate directory.
#
# Background material about the method can be found here:
#
# https://lwn.net/Articles/548216/
# https://github.com/armijnhemel/conference-talks/tree/master/fsfe2013
#
# ELF background information can be found in public sources here:
#
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
# https://en.wikipedia.org/wiki/Weak_symbol
# https://refspecs.linuxbase.org/elf/elf.pdf
# https://android.googlesource.com/platform/art/+/master/runtime/elf.h
# https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-43405/index.html
#
# Licensed under the terms of the General Public License version 3
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright 2018-2019 - Armijn Hemel, Tjaldur Software Governance Solutions

import sys
import os
import re
import subprocess
import json
import tempfile
import copy
import string
import secrets
import configparser
import argparse

# import pyelftools
import elftools.elf.elffile
import elftools.elf.dynamic
import elftools.elf.sections


def main(argv):
    parser = argparse.ArgumentParser()

    # the following options are provided on the commandline
    parser.add_argument("-c", "--config", action="store", dest="cfg",
                        help="path to configuration file", metavar="FILE")
    parser.add_argument("-d", "--directory", action="store",
                        dest="dirtoscan",
                        help="path to directory to scan", metavar="DIR")
    parser.add_argument("-o", "--outputformat", action="store",
                        dest="outputformat",
                        help="output format", metavar="FORMAT")
    args = parser.parse_args()

    # first some sanity checks for the directory that needs to be scanned
    if args.dirtoscan is None:
        parser.error("Directory argument missing")

    if not os.path.exists(args.dirtoscan):
        parser.error("Directory %s does not exist" % args.dirtoscan)

    if not os.path.isdir(args.dirtoscan):
        parser.error("%s is not a directory" % args.dirtoscan)

    # first get rid of unnecessary path components, like '..',
    # multiple slashes, etc.
    dirtoscan = os.path.normpath(args.dirtoscan)

    #supported_formats = ['text', 'cypher', 'graphviz']
    supported_formats = ['cypher']

    # check the output format. By default it is cypher.
    outputformat = 'cypher'
    if args.outpuformat is not None:
        if args.outputformat not in supported_formats:
            parser.error("Unsupported output format %s" % args.outputformat)

    # then some checks for the configuration file
    if args.cfg is None:
        parser.error("Configuration file missing")

    if not os.path.exists(args.cfg):
        parser.error("Configuration file does not exist")

    config = configparser.ConfigParser()

    configfile = open(args.cfg, 'r')

    try:
        config.readfp(configfile)
    except Exception:
        print("Cannot read configuration file", file=sys.stderr)
        sys.exit(1)

    # process the configuration file and store settings
    config_settings = {}

    cypherdir = None
    for section in config.sections():
        if section == 'cypher':
            try:
                cypherdir = config.get(section, 'cypherdir')
            except:
                print("Directory to write Cypher files not configured",
                      file=sys.stderr)
                configfile.close()
                sys.exit(1)
            if not os.path.exists(cypherdir):
                print("Directory to write Cypher files does not exist",
                      file=sys.stderr)
                configfile.close()
                sys.exit(1)
            if not os.path.isdir(cypherdir):
                print("Directory to write Cypher files is not a directory",
                      file=sys.stderr)
                configfile.close()
                sys.exit(1)
    configfile.close()

    if cypherdir is None:
        print("Directory to write Cypher files not configured",
              file=sys.stderr)
        sys.exit(1)

    # keep a list per machine architecture, in case of leftover binaries
    # from other architectures, operating systems, endianness,
    # class (32/64 bit). etc.
    # example:
    # ['mips']['linux']['big']['ELF64']
    machinetobinary = {}

    # store the symbols per binary, with their types
    elftoimportedsymbols = {}
    elftoexportedsymbols = {}

    # store names to full paths
    filenametofullpath = {}

    # store symbolic links to their final target
    symlinktotarget = {}

    # store needed libraries
    linkedlibraries = {}

    # store the length of the top level directory, as everything
    # will be relative to it and the graph should be free of
    # hardcoded paths.
    topdirlength = len(dirtoscan)

    dirwalker = os.walk(dirtoscan)

    for direntry in dirwalker:
        for filename in direntry[2]:
            fullfilename = os.path.join(direntry[0], filename)
            relfullfilename = fullfilename[topdirlength:]
            if os.path.islink(fullfilename):
                # keep checking whether or not a symlink can be resolved

                # keep a list of file paths to detect loops
                seensymlinks = set()

                # set the first instance to the current filename
                symlinkname = fullfilename

                while True:
                    # symbolic links might have been recorded instead
                    # of the actual name of the dependency, so try to
                    # resolve it.
                    # First find out the target of the symbolic link
                    try:
                        targetfile = os.readlink(symlinkname)
                    except:
                        continue

                    # Then start resolving the symbolic link to actua files.
                    # In case the target is absolute it should be made
                    # relative to the root of the scanning directory,
                    # otherwise it is relative to the current directory.
                    if os.path.isabs(targetfile):
                        targetfile = os.path.relpath(targetfile, '/')
                        targetfile = os.path.join(dirtoscan, targetfile)
                    else:
                        targetfile = os.path.normpath(os.path.join(direntry[0], targetfile))
                    # then recursively check whether or not symbolic links
                    # point to other symbolic links or to paths that exist
                    if os.path.islink(targetfile):
                        symlinkname = targetfile
                        if targetfile in seensymlinks:
                            # target file has already been seen,
                            # there is a cycle
                            break
                        seensymlinks.add(targetfile)
                        continue
                    if not os.path.isfile(targetfile):
                        # anything else but a file (directories, pipes,
                        # sockets, etc.) can be ignored
                        break
                    else:
                        # the target is an actual file
                        symlinktotarget[relfullfilename] = targetfile[topdirlength:]
                        break
                continue

            if not os.path.isfile(fullfilename):
                # anything else but a file (directories, pipes, sockets, etc.)
                # can be ignored
                continue

            # then do a first check to see if a file can be a valid ELF
            # file by reading the first four bytes of the file to
            # verify (see ELF specification)
            try:
                scanfile = open(fullfilename, 'rb')
                databytes = scanfile.read(4)
                scanfile.close()
                if databytes != b'\x7f\x45\x4c\x46':
                    continue
            except:
                continue

            dynamicelf = False

            # first check whether or not this is a dynamically linked
            # ELF file plus already load a few data structures into memory
            # that will be used later on as well.
            openedelffile = open(fullfilename, 'rb')
            elffilerepresentation = elftools.elf.elffile.ELFFile(openedelffile)
            elfheader = elffilerepresentation.header
            for sec in elffilerepresentation.iter_sections():
                if isinstance(sec, elftools.elf.dynamic.DynamicSection):
                    dynamicelf = True
                    break

            # statically linked binary, not interesting for now
            if not dynamicelf:
                openedelffile.close()
                continue

            # now split the files according to their architecture, class
            # operating system, and so on. The exact values used are
            # irrelevant as they are not used anywhere else.
            architecture = elfheader['e_machine']
            elf_endian = elffilerepresentation.little_endian
            operating_system = elfheader['e_ident']['EI_OSABI']
            elfclass = elffilerepresentation.elfclass

            if architecture not in machinetobinary:
                machinetobinary[architecture] = {}

            # extract and store the operating system
            if operating_system not in machinetobinary[architecture]:
                machinetobinary[architecture][operating_system] = {}

            # extract and store the endianness
            if elf_endian not in machinetobinary[architecture][operating_system]:
                machinetobinary[architecture][operating_system][elf_endian] = {}

            # extract and store the class (ELF32/ELF64]
            if elfclass not in machinetobinary[architecture][operating_system][elf_endian]:
                machinetobinary[architecture][operating_system][elf_endian][elfclass] = set()

            # then store the binary in the right set
            machinetobinary[architecture][operating_system][elf_endian][elfclass].add(relfullfilename)

            # plus record the name to the full path files
            if not os.path.basename(fullfilename) in filenametofullpath:
                filenametofullpath[os.path.basename(fullfilename)] = set()
            filenametofullpath[os.path.basename(fullfilename)].add(relfullfilename)

            # Record the symbols and linked libraries
            # The imported ones (UND in readelf) will be in 'imports'
            # and the exported ones will be in 'exports'
            # Linked libraries will be in 'libs'
            # first initialize
            elftoimportedsymbols[relfullfilename] = []
            elftoexportedsymbols[relfullfilename] = []
            linkedlibraries[relfullfilename] = []

            for sec in elffilerepresentation.iter_sections():
                if isinstance(sec, elftools.elf.sections.SymbolTableSection):
                    for symbol in sec.iter_symbols():
                        store_symbol = {}
                        if symbol['st_size'] == 0:
                            continue
                        if symbol['st_info']['type'] == 'STT_NOTYPE':
                            continue
                        if symbol['st_info']['bind'] == 'STB_LOCAL':
                            continue
                        if symbol['st_shndx'] == 'SHN_ABS':
                            continue

                        # store name
                        store_symbol['name'] = symbol.name
                        # store size
                        store_symbol['size'] = symbol['st_size']

                        # store type
                        if symbol['st_info']['type'] == 'STT_FUNC':
                            store_symbol['type'] = 'FUNC'
                        elif symbol['st_info']['type'] == 'STT_OBJECT':
                            store_symbol['type'] = 'OBJECT'

                        # store binding
                        if symbol['st_info']['bind'] == 'STB_WEAK':
                            store_symbol['bind'] = 'WEAK'
                        elif symbol['st_info']['bind'] == 'STB_GLOBAL':
                            store_symbol['bind'] = 'GLOBAL'

                        if symbol['st_shndx'] == 'SHN_UNDEF':
                            elftoimportedsymbols[relfullfilename].append(store_symbol)
                        else:
                            elftoexportedsymbols[relfullfilename].append(store_symbol)
                elif isinstance(sec, elftools.elf.dynamic.DynamicSection):
                    for tag in sec.iter_tags():
                        if tag.entry.d_tag == 'DT_NEEDED':
                            linkedname = tag.needed
                            linkedlibraries[relfullfilename].append(linkedname)
            openedelffile.close()

    # now create a cypherfile for each set of ELF files that belong together
    for a in machinetobinary:
        for o in machinetobinary[a]:
            for endian in machinetobinary[a][o]:
                for elfclass in machinetobinary[a][o][endian]:
                    elftoplaceholder = {}
                    placeholdertoelf = {}
                    symboltoplaceholder = {}
                    placeholdertosymbol = {}
                    allplaceholdernames = set()
                    if len(machinetobinary[a][o][endian][elfclass]) == 0:
                        continue

                    # first generate place holder names for every binary
                    for filename in machinetobinary[a][o][endian][elfclass]:
                        # first generate a placeholder name
                        # from Python3 docs
                        # https://docs.python.org/3/library/secrets.html#recipes-and-best-practices
                        while True:
                            placeholdername = ''.join(secrets.choice(string.ascii_letters) for i in range(8))
                            if placeholdername not in placeholdertoelf and placeholdername not in allplaceholdernames:
                                placeholdertoelf[placeholdername] = filename
                                break
                        elftoplaceholder[filename] = placeholdername
                        allplaceholdernames.add(placeholdername)

                    # write the data to a Cypher file
                    cypherfile = tempfile.mkstemp(dir=cypherdir,
                                                  suffix='.cypher')
                    os.fdopen(cypherfile[0]).close()
                    cypherfileopen = open(cypherfile[1], 'w')
                    cypherfileopen.write("CREATE ")

                    seenfirst = False

                    # first add all the ELF files as nodes to the graph
                    for filename in machinetobinary[a][o][endian][elfclass]:
                        if seenfirst:
                            cypherfileopen.write(", \n")
                        else:
                            seenfirst = True
                        # first create the nodes
                        cypherfileopen.write("(%s:ELF {name: '%s'})" % (elftoplaceholder[filename], filename))

                    # then add all the links
                    for filename in machinetobinary[a][o][endian][elfclass]:
                        if len(linkedlibraries[filename]) != 0:
                            # record the dependencies that are linked with
                            for l in linkedlibraries[filename]:
                                libfound = False
                                if l in filenametofullpath:
                                    for fl in filenametofullpath[l]:
                                        # only record dependencies that
                                        # are in the same "class"
                                        if fl in machinetobinary[a][o][endian][elfclass]:
                                            libfound = True
                                            break
                                if not libfound:
                                    # problem here, ignore for now
                                    continue
                                    #pass
                                cypherfileopen.write(", \n")
                                cypherfileopen.write("(%s)-[:LINKSWITH]->(%s)" % (elftoplaceholder[filename], elftoplaceholder[fl]))

                    # then add all the exported symbols just once
                    tmpexportsymbols = set()

                    for filename in machinetobinary[a][o][endian][elfclass]:
                        for exp in elftoexportedsymbols[filename]:
                            # remove a few symbols that are not needed
                            if exp['size'] == 0:
                                continue
                            if exp['type'] == 'NOTYPE':
                                continue
                            tmpexportsymbols.add((exp['name'], exp['type'], exp['bind']))
                    for exp in tmpexportsymbols:
                        (symbolname, symboltype, symbolbinding) = exp
                        while True:
                            placeholdername = ''.join(secrets.choice(string.ascii_letters) for i in range(8))
                            if placeholdername not in placeholdertosymbol and placeholdername not in allplaceholdernames:
                                placeholdertosymbol[placeholdername] = symbolname
                                break
                        symboltoplaceholder[(symbolname, symboltype)] = placeholdername
                        allplaceholdernames.add(placeholdername)
                        cypherfileopen.write(", \n")
                        cypherfileopen.write("(%s:SYMBOL {name: '%s', type: '%s'})" % (symboltoplaceholder[(symbolname, symboltype)], symbolname, symboltype))

                    # then declare for all the symbols which are exported
                    for filename in machinetobinary[a][o][endian][elfclass]:
                        for exp in elftoexportedsymbols[filename]:
                            # remove a few symbols that are not needed
                            if exp['size'] == 0:
                                continue
                            if exp['type'] == 'NOTYPE':
                                continue
                            cypherfileopen.write(", \n")
                            cypherfileopen.write("(%s)-[:EXPORTS]->(%s)" % (elftoplaceholder[filename], symboltoplaceholder[(exp['name'], exp['type'])]))
                    for filename in machinetobinary[a][o][endian][elfclass]:
                        for imp in elftoimportedsymbols[filename]:
                            if imp['bind'] == 'LOCAL':
                                # skip LOCAL symbols
                                continue
                            if imp['bind'] == 'WEAK':
                                # skip WEAK symbols for now
                                continue
                            if (imp['name'], imp['type']) in symboltoplaceholder:
                                cypherfileopen.write(", \n")
                                cypherfileopen.write("(%s)-[:USES]->(%s)" % (elftoplaceholder[filename], symboltoplaceholder[(imp['name'], imp['type'])]))
                            else:
                                # something is horribly wrong here
                                pass
if __name__ == "__main__":
    main(sys.argv)
