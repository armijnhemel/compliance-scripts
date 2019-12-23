#!/usr/bin/env python3

# This script walks a directory of files extracts symbols from ELF files,
# records dependencies (taking symbolic links and RPATH into account) and
# generates different types of output.
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
#    will then generate output files with all the information from 1.
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

import argparse
import configparser
import os
import secrets
import string
import sys
import tempfile

# import pyelftools
import elftools.elf.elffile
import elftools.elf.dynamic
import elftools.elf.sections

def createcypher(outputdir, machine_to_binary, linked_libraries,
                 filename_to_full_path, elf_to_exported_symbols,
                 elf_to_imported_symbols):
    '''Create a Cypher file for each set of ELF files that belongs together'''

    # create a cypher file for each architecture/operating system
    # combination that was found. This means:
    #
    # * generating names for the nodes in the graph
    # * defining vertices between the nodes
    # * writing the output file
    for architecture in machine_to_binary:
        for o in machine_to_binary[architecture]:
            for endian in machine_to_binary[architecture][o]:
                for elfclass in machine_to_binary[architecture][o][endian]:
                    elf_to_placeholder = {}
                    placeholder_to_elf = {}
                    symbol_to_placeholder = {}
                    placeholder_to_symbol = {}
                    all_placeholder_names = set()
                    if machine_to_binary[architecture][o][endian][elfclass] == set():
                        continue

                    # first generate place holder names for every binary
                    for filename in machine_to_binary[architecture][o][endian][elfclass]:
                        # Create a placeholder name and check if it already exists. If so
                        # generate and check a new name until one is found that doesn't exist.
                        #
                        # Taken from the Python3 documentation:
                        # https://docs.python.org/3/library/secrets.html#recipes-and-best-practices
                        while True:
                            placeholdername = ''.join(secrets.choice(string.ascii_letters) for i in range(8))
                            if placeholdername not in placeholder_to_elf and placeholdername not in all_placeholder_names:
                                placeholder_to_elf[placeholdername] = filename
                                break
                        elf_to_placeholder[filename] = placeholdername
                        all_placeholder_names.add(placeholdername)

                    # write the data to a Cypher file
                    cypherfile = tempfile.mkstemp(dir=outputdir,
                                                  suffix='.cypher')
                    os.fdopen(cypherfile[0]).close()
                    cypherfileopen = open(cypherfile[1], 'w')
                    cypherfileopen.write("CREATE ")

                    seenfirst = False

                    # first add all the ELF files as nodes to the graph
                    for filename in machine_to_binary[architecture][o][endian][elfclass]:
                        if seenfirst:
                            cypherfileopen.write(", \n")
                        else:
                            seenfirst = True
                        # first create the nodes
                        cypherfileopen.write("(%s:ELF {name: '%s'})" % (elf_to_placeholder[filename], filename))

                    # then add all the links
                    for filename in machine_to_binary[architecture][o][endian][elfclass]:
                        if linked_libraries[filename] != []:
                            # record the dependencies that are linked with
                            for l in linked_libraries[filename]:
                                libfound = False
                                if l in filename_to_full_path:
                                    for fl in filename_to_full_path[l]:
                                        # only record dependencies that
                                        # are in the same "class"
                                        if fl in machine_to_binary[architecture][o][endian][elfclass]:
                                            libfound = True
                                            break
                                if not libfound:
                                    # problem here, ignore for now
                                    continue
                                    #pass
                                cypherfileopen.write(", \n")
                                cypherfileopen.write("(%s)-[:LINKSWITH]->(%s)" % (elf_to_placeholder[filename], elf_to_placeholder[fl]))

                    # then add all the exported symbols just once
                    tmpexportsymbols = set()

                    for filename in machine_to_binary[architecture][o][endian][elfclass]:
                        for exp in elf_to_exported_symbols[filename]:
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
                            if placeholdername not in placeholder_to_symbol and placeholdername not in all_placeholder_names:
                                placeholder_to_symbol[placeholdername] = symbolname
                                break
                        symbol_to_placeholder[(symbolname, symboltype)] = placeholdername
                        all_placeholder_names.add(placeholdername)
                        cypherfileopen.write(", \n")
                        cypherfileopen.write("(%s:SYMBOL {name: '%s', type: '%s'})" % (symbol_to_placeholder[(symbolname, symboltype)], symbolname, symboltype))

                    # then declare for all the symbols which are exported
                    for filename in machine_to_binary[architecture][o][endian][elfclass]:
                        for exp in elf_to_exported_symbols[filename]:
                            # remove a few symbols that are not needed
                            if exp['size'] == 0:
                                continue
                            if exp['type'] == 'NOTYPE':
                                continue
                            cypherfileopen.write(", \n")
                            cypherfileopen.write("(%s)-[:EXPORTS]->(%s)" % (elf_to_placeholder[filename], symbol_to_placeholder[(exp['name'], exp['type'])]))

                    # store which files use which symbols
                    for filename in machine_to_binary[architecture][o][endian][elfclass]:
                        for imp in elf_to_imported_symbols[filename]:
                            if imp['bind'] == 'LOCAL':
                                # skip LOCAL symbols
                                continue
                            if imp['bind'] == 'WEAK':
                                # skip WEAK symbols for now
                                continue
                            if (imp['name'], imp['type']) in symbol_to_placeholder:
                                cypherfileopen.write(", \n")
                                cypherfileopen.write("(%s)-[:USES]->(%s)" % (elf_to_placeholder[filename], symbol_to_placeholder[(imp['name'], imp['type'])]))
                            else:
                                # something is horribly wrong here
                                pass

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
    if args.outputformat is not None:
        if args.outputformat not in supported_formats:
            parser.error("Unsupported output format %s" % args.outputformat)
        outputformat = args.outputformat

    # then some checks for the configuration file
    if args.cfg is None:
        parser.error("Configuration file missing")

    if not os.path.exists(args.cfg):
        parser.error("Configuration file does not exist")

    config = configparser.ConfigParser()

    configfile = open(args.cfg, 'r')

    try:
        config.read_file(configfile)
    except Exception:
        print("Cannot read configuration file", file=sys.stderr)
        sys.exit(1)

    # process the configuration file and store settings
    config_settings = {}

    outputdir = None
    for section in config.sections():
        if outputformat == 'cypher':
            if section == 'cypher':
                try:
                    outputdir = config.get(section, 'cypherdir')
                except:
                    print("Directory to write Cypher files not configured",
                          file=sys.stderr)
                    configfile.close()
                    sys.exit(1)
                if not os.path.exists(outputdir):
                    print("Directory to write Cypher files does not exist",
                          file=sys.stderr)
                    configfile.close()
                    sys.exit(1)
                if not os.path.isdir(outputdir):
                    print("Directory to write Cypher files is not a directory",
                          file=sys.stderr)
                    configfile.close()
                    sys.exit(1)
    configfile.close()

    if outputdir is None:
        print("Directory to write output files to not configured",
              file=sys.stderr)
        sys.exit(1)

    # keep a list per machine architecture, in case of leftover binaries
    # from other architectures, operating systems, endianness,
    # class (32/64 bit). etc.
    # example:
    # ['mips']['linux']['big']['ELF64']
    machine_to_binary = {}

    # store the symbols per binary, with their types
    elf_to_imported_symbols = {}
    elf_to_exported_symbols = {}

    # store names to full paths
    filename_to_full_path = {}

    # store symbolic links to their final target
    symlink_to_target = {}

    # store needed libraries
    linked_libraries = {}

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

                    # Then start resolving the symbolic link to actual files.
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
                        # symbolic links have already been processed, and
                        # anything else but a file (directories, pipes,
                        # sockets, etc.) can be safely ignored
                        break
                    else:
                        # the target is an actual file
                        symlink_to_target[relfullfilename] = targetfile[topdirlength:]
                        break
                continue

            if not os.path.isfile(fullfilename):
                # symbolic links have already been processed, and
                # anything else but a file (directories, pipes,
                # sockets, etc.) can be safely ignored
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
                # for some reason the file cannot be read
                continue

            dynamicelf = False

            # first check whether or not this is a dynamically linked
            # ELF file. Already load a few data structures into memory
            # that will be used later on as well.
            openedelffile = open(fullfilename, 'rb')
            elffilerepresentation = elftools.elf.elffile.ELFFile(openedelffile)
            elfheader = elffilerepresentation.header
            for sec in elffilerepresentation.iter_sections():
                if isinstance(sec, elftools.elf.dynamic.DynamicSection):
                    dynamicelf = True
                    break

            # statically linked binary, or not a regular ELF file,
            # not interesting for now
            if not dynamicelf:
                openedelffile.close()
                continue

            # now split the files according to their architecture,
            # operating system, and so on. The exact values are
            # irrelevant as they are not used anywhere else in the program
            # (they might be interesting for reporting).
            # Although in most cases there will only be one architecture,
            # operating system, and so on, sometimes files for other
            # architectures are found.
            architecture = elfheader['e_machine']
            elf_endian = elffilerepresentation.little_endian
            operating_system = elfheader['e_ident']['EI_OSABI']
            elfclass = elffilerepresentation.elfclass

            # the current architecture is not yet found, so create
            # the necessary data structures
            if architecture not in machine_to_binary:
                machine_to_binary[architecture] = {}

            # extract and store the operating system. If it isn't
            # yet known create the necessary data structures
            if operating_system not in machine_to_binary[architecture]:
                machine_to_binary[architecture][operating_system] = {}

            # extract and store the endianness
            if elf_endian not in machine_to_binary[architecture][operating_system]:
                machine_to_binary[architecture][operating_system][elf_endian] = {}

            # extract and store the class (ELF32/ELF64]
            if elfclass not in machine_to_binary[architecture][operating_system][elf_endian]:
                machine_to_binary[architecture][operating_system][elf_endian][elfclass] = set()

            # then store the binary in the right set
            machine_to_binary[architecture][operating_system][elf_endian][elfclass].add(relfullfilename)

            # plus record the name to the full path files
            if not os.path.basename(fullfilename) in filename_to_full_path:
                filename_to_full_path[os.path.basename(fullfilename)] = set()
            filename_to_full_path[os.path.basename(fullfilename)].add(relfullfilename)

            # Record the symbols and linked libraries found in each ELF binary:
            # * imported ones (UND in readelf) will be in 'imports'
            # * the exported ones will be in 'exports'
            # * linked libraries will be in 'libs'
            elf_to_imported_symbols[relfullfilename] = []
            elf_to_exported_symbols[relfullfilename] = []
            linked_libraries[relfullfilename] = []

            for section in elffilerepresentation.iter_sections():
                if isinstance(section, elftools.elf.sections.SymbolTableSection):
                    for symbol in section.iter_symbols():
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
                            elf_to_imported_symbols[relfullfilename].append(store_symbol)
                        else:
                            elf_to_exported_symbols[relfullfilename].append(store_symbol)
                elif isinstance(section, elftools.elf.dynamic.DynamicSection):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == 'DT_NEEDED':
                            linkedname = tag.needed
                            linked_libraries[relfullfilename].append(linkedname)
            openedelffile.close()

    # for all symlinks copy the data of targets to the symlinks
    for i in symlink_to_target:
        if symlink_to_target[i] in elf_to_exported_symbols:
            elf_to_exported_symbols[i] = elf_to_exported_symbols[symlink_to_target[i]]
        if symlink_to_target[i] in elf_to_imported_symbols:
            elf_to_imported_symbols[i] = elf_to_imported_symbols[symlink_to_target[i]]
        if symlink_to_target[i] in linked_libraries:
            linked_libraries[i] = linked_libraries[symlink_to_target[i]]

    # now generate output
    if outputformat == 'cypher':
        createcypher(outputdir, machine_to_binary, linked_libraries,
                     filename_to_full_path, elf_to_exported_symbols,
                     elf_to_imported_symbols)

if __name__ == "__main__":
    main(sys.argv)
