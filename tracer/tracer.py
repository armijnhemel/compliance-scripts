#!/usr/bin/env python3

# Trace file processor
#
# Background information:
#
# * http://www.st.ewi.tudelft.nl/~sander/pdf/publications/TUD-SERG-2012-010.pdf
# * http://rebels.ece.mcgill.ca/confpaper/2014/09/14/tracing-software-build-processes-to-uncover-license-compliance-inconsistencies.html
#
# SPDX-License-Identifier: GPL-3.0
#
# Copyright 2017-2023 - Armijn Hemel
#
# ---- USAGE ----
#
# Example: Linux kernel
#
# First trace a Linux kernel build with (for example) the following command:
#
# strace -e trace=%file,process,dup,dup2,close,pipe,fchdir -y -qq -f -s 256 make 2> ../linux-strace
#
# and then run this script on the output.
#
# Alternatively, to save diskspace for the trace file (easily 50%), use:
#
# strace -e trace=%process,dup,dup2,open,openat,close,rename,getcwd,chdir,fchdir,pipe -y -qq -f -s 256 make 2> ../linux-strace
#
# Make sure there is enough disk space available, as trace files for the
# Linux kernel tend to be quite big.

import argparse
import copy
import datetime
import hashlib
import multiprocessing
import os
import queue
import random
import re
import shutil
import string
import subprocess
import sys

import click

# there are only a few syscalls that are interesting
INTERESTING_SYSCALLS = ['open', 'openat', 'chdir', 'fchdir',
                        'rename', 'clone', 'symlink', 'symlinkat']

# regular expression for process IDs (PIDs)
pidre = re.compile(r'\[pid\s+(\d+)\]')

# some precompiled regular expressions for interesting system calls
# valid filename characters:
# <>\w/\-+,.*$:;
chdirre = re.compile(r"chdir\(\"([\w/\-_+,.]+)\"\s*\)\s+=\s+(\d+)")
fchdirre = re.compile(r"fchdir\((\d+)<(.*)>\s*\)\s+=\s+(\d+)")
getcwdre = re.compile(r"getcwd\(\"([\w/\-_+,.]+)\", \d+\)\s+=\s+")
openre = re.compile(r"open\(\"([<>\w/\-+,.*$:;]+)\", ([\w|]+)(?:,\s+\d+)?\)\s+= (\-?\d+)<(.*)>$")
openatre = re.compile(r"openat\((\w+), \"([<>\w/\-+,.*$:;]+)\", ([\w|]+)(?:,\s+\d+)?\)\s+= (\-?\d+)<(.*)>$")
openatre2 = re.compile(r"openat\((\w+)<(.*)>, \"([<>\w/\-+,.*$:;]+)\", ([\w|]+)(?:,\s+\d+)?\)\s+= (\-?\d+)<(.*)>$")
renamere = re.compile(r"rename\(\"([\w/\-+,.]+)\",\s+\"([\w/\-+,.]+)\"\)\s+=\s+(\-?\d+)")
clonere = re.compile(r"clone\([\w/\-+,.=]+,\s+[\w|=]+,\s+[\w=]+?\)\s+=\s+(\-?\d+)")
cloneresumedre = re.compile(r"clone\s*resumed>\s*.*=\s+(\-?\d+)$")
vforkresumedre = re.compile(r"vfork\s*resumed>\s*\)\s*=\s*(\d+)")
vforkre = re.compile(r"vfork\(\s*\)\s*=\s*(\d+)")
#execvere = re.compile(r"execve\(\"(?P<command>.*)\",\s*\[(?P<args>.*)\],\s+0x\w+\s+/\*\s+\d+\s+vars\s+\*/\)\s*=\s*(?P<returncode>\-?\d+)")
execvere = re.compile(r"execve\(\"(?P<command>.*)\",\s*\[(?P<args>.*)\],\s+0x\w+\s+/\*\s+\d+\s+vars\s+\*/")
# symlinkre =
# symlinkatre =

def rewritepid(pid):
    pass

def process_trace_line(traceline, defaultpid, pidtocwd, pidtocmd, directories, ignore_files, openfiles, basepath, defaultcwd, pidtopidlabel):
    # then look at the 'regular' lines
    if '+++ exited with' in traceline:
        # this message can be in the trace file unless -qq is passed
        # as a parameter
        return
    if '--- SIGCHLD' in traceline:
        # The child process has exited, so remove information from the
        # data structures in case of PID wrapping (which can easily happen)
        sigchldres = re.search(r"si_pid=(\w+),", traceline)
        if sigchldres is not None:
            # remove this pid from the list of pid labels
            sigchldpid = sigchldres.groups()[0]
            del pidtopidlabel[sigchldpid]

    syscallres = re.search(r"(\w+)\(", traceline)
    if syscallres is not None:
        syscall = syscallres.groups()[0]
    else:
        # something really weird happening here, so exiting
        return

    if syscall not in INTERESTING_SYSCALLS:
        return

    # first determine the pid of the line
    if traceline.startswith('[pid '):
        pid = pidre.match(traceline).groups()[0]
    else:
        # This is the top level pid. It actually is possible to
        # later reconstruct the pid if the top level process
        # forks a process and the process returns, or if a vfork
        # call is resumed.
        if defaultpid is not None:
            pid = defaultpid
        else:
            pid = 'default'

    if not pid in pidtocwd and pid != 'default':
        pidtocwd[pid] = defaultcwd

    if syscall == 'chdir' or syscall == 'fchdir':
        if syscall == 'fchdir':
            fchdirres = fchdirre.search(traceline)
            if fchdirres is not None:
                fchdirfd = int(fchdirres.groups()[0])
                fullchdirpath = fchdirres.groups()[1]
                fchdirresult = fchdirres.groups()[2]
                pidtocwd[pid] = fullchdirpath
                directories.add(fullchdirpath)
        else:
            chdirres = chdirre.search(traceline)
            if chdirres is not None:
                chdirpath = chdirres.groups()[0]
                chdirresult = int(chdirres.groups()[1])
                if chdirresult != 0:
                    return
                if chdirpath == '.':
                    return
                if chdirpath.startswith('/'):
                    pidtocwd[pid] = chdirpath
                    directories.add(chdirpath)
                else:
                    if pid in pidtocwd:
                        pidtocwd[pid] = os.path.normpath(os.path.join(basepath, pidtocwd[pid], chdirpath))
    if syscall == 'open':
        openres = openre.search(traceline)
        if openres is not None:
            openreturn = openres.groups()[2]
            if openreturn == '-1':
                # -1 means "No such file or directory" so ignore
                return
            openpath = os.path.normpath(openres.groups()[0])
            openflags = set(openres.groups()[1].split('|'))
            full_open_path = openres.groups()[3]

            if full_open_path in directories:
                # directories can be safely ignored
                return

            # ignore files that should be ignored
            if full_open_path in ignore_files:
                return

            # if files have already been recorded they are not interesting
            if full_open_path in openfiles:
                return

            # directories are not interesting, except to store the
            # file descriptor
            if 'O_DIRECTORY' in openflags:
                directories.add(full_open_path)
                return
            # absolute paths are only relevant if
            # coming from the same source code directory
            if openpath.startswith('/'):
                if not openpath.startswith(basepath):
                    return
            # now check the flags to see if a file is new. If so, it can
            # be added to ignore_files
            if "O_RDWR" in openflags or "O_WRONLY" in openflags:
                if "O_CREAT" in openflags:
                    if "O_EXCL" in openflags or "O_TRUNC" in openflags:
                        ignore_files.add(full_open_path)
                        return
            # add the full reconstructed path, relative to root
            openfiles.add(full_open_path)

    if syscall == 'openat':
        openres = openatre.search(traceline)
        if openres is not None:
            openfd = os.path.normpath(openres.groups()[0])
            openpath = os.path.normpath(openres.groups()[1])
            openflags = set(openres.groups()[2].split('|'))
            openreturn = openres.groups()[3]
            full_open_path = openres.groups()[4]
        else:
            openres = openatre2.search(traceline)
            if openres is not None:
                openfd = os.path.normpath(openres.groups()[0])
                openpath = os.path.normpath(openres.groups()[2])
                openflags = set(openres.groups()[3].split('|'))
                openreturn = openres.groups()[4]
                full_open_path = openres.groups()[5]
        if openres is not None:
            if full_open_path in directories:
                # directories can be safely ignored
                return

            # ignore files that should be ignored
            if full_open_path in ignore_files:
                return

            # if files have already been recorded they are not interesting
            if full_open_path in openfiles:
                return
            # directories are not interesting, so record them to ignore them
            if 'O_DIRECTORY' in openflags:
                directories.add(full_open_path)
                return
            if openpath.startswith('/'):
                if not openpath.startswith(basepath):
                    return
            # now check the flags to see if a file is new
            if "O_RDWR" in openflags or "O_WRONLY" in openflags:
                if "O_CREAT" in openflags:
                    if "O_EXCL" in openflags or "O_TRUNC" in openflags:
                        ignore_files.add(full_open_path)
                        return

            # add the full reconstructed path, relative to root
            openfiles.add(full_open_path)

    if syscall == 'rename':
        renameres = renamere.search(traceline)
        if renameres is not None:
            sourcefile = os.path.normpath(os.path.join(pidtocwd[pid], renameres.groups()[0]))
            targetfile = os.path.normpath(os.path.join(pidtocwd[pid],renameres.groups()[1]))
            # check if sourcefile is in ignore_files. If so,
            # then targetfile should be as well.
            if sourcefile in ignore_files:
                ignore_files.add(targetfile)

def main(argv):
    parser = argparse.ArgumentParser()

    # the following options are provided on the commandline
    # the configuration file
    parser.add_argument("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")

    # the path to the trace file
    parser.add_argument("-f", "--tracefile", action="store", dest="tracefile", help="path to trace file", metavar="FILE")

    # the base path of the source code directory used during the build.
    # This might actually be different than --sourcedir
    # in case the trace file is processed on a different machine
    parser.add_argument("-b", "--basepath", action="store", dest="basepath", help="base path of source directory during build", metavar="BASEPATH")

    # a directory where the source code files can be found. These might
    # be the same as base path, but doesn't have to be.
    parser.add_argument("-s", "--sourcedir", action="store", dest="sourcedir", help="path of source directory", metavar="SOURCEDIR")

    # a directory to copy the opened files to
    parser.add_argument("-t", "--targetdir", action="store", dest="targetdir", help="directory to copy/write files that were opened during the build", metavar="DIR")

    # an identifier with which the build can be identified
    parser.add_argument("-u", "--buildid", action="store", dest="buildid", help="string to identify the build with", metavar="BUILD ID")

    args = parser.parse_args()

    if args.tracefile == None:
        parser.error("Trace file missing")

    if not os.path.exists(args.tracefile):
        parser.error("Trace file does not exist")

    if not os.path.isfile(args.tracefile):
        parser.error("Trace file is not a file")

    if args.basepath == None:
        parser.error("basepath for source directory missing")

    if not os.path.isabs(args.basepath):
        parser.error("basepath not an absolute path")

    if args.buildid == None:
        parser.error("build identifier missing")

    if args.buildid.strip() == "":
        parser.error("build identifier empty")

    # TODO: symbolic links are actually resolved by strace when using
    # the -y option, so make sure that the basepath is first resolved as
    # well.
    basepath = os.path.normpath(args.basepath)

    targetdir = None
    if args.targetdir is not None:
        if not os.path.exists(args.targetdir):
            parser.error("directory to write temporary files does not exist")
        targetdir = args.targetdir

    sourcedir = None
    if args.sourcedir is not None:
        if not os.path.exists(args.sourcedir):
            parser.error("directory with source code files does not exist")
        sourcedir = args.sourcedir

    tracefile = open(args.tracefile, 'r')

    defaultcwd = ''
    firstgetcwd = False

    pidtocwd = {}
    pidtocmd = {}

    pidtopidlabel = {}

    directories = set()

    # store which processes create other processes and vice versa
    parenttopid = {}
    knownchildpids = set()

    # store the inputs and outputs per file
    inputsperpid = {}
    outputsperpid= {}

    # the pid of the first process is not shown in the trace file until after
    # returning from the first clone/execve/etc.
    # It is easy to find out what the top level PID is by keeping track of
    # which PIDs are known. When a system call is resumed for an unknown PID
    # that will be the top level PID.
    knownpids = set()

    # set a dummy value for the first PID
    defaultpid = None

    openfiles = set()

    # a list of files created or overwritten, so can be ignored later on
    ignore_files = set()

    backlog = []
    backlogged = False

    for i in tracefile:
        # either there is an exit code, or the system call is unfinished. The rest
        # is irrelevant garbage.
        # Assume that strace is running in English. Right now (March 8, 2018) strace
        # has not been translated, so this is a safe assumption.
        if not ('=' in i or 'unfinished' in i):
            continue

        # first determine the pid of the line
        if i.startswith('[pid '):
            pid = pidre.match(i).groups()[0]
        else:
            # This is the top level pid. It actually is possible to
            # later reconstruct the pid if the top level process
            # forks a process and the process returns, or if a vfork
            # call is resumed.
            if defaultpid is not None:
                pid = defaultpid
            else:
                pid = 'default'

        #if 'execve(' in i:
        #    execveres = execvere.search(i)
        #    if execveres is not None:
        #        pidtocmd[pid] = execveres.group('command')

        if 'getcwd(' in i:
            if not firstgetcwd:
                cwd = getcwdre.match(i).groups()[0]
                defaultcwd = cwd
                firstgetcwd = True
                if not 'default' in pidtocwd:
                    pidtocwd['default'] = cwd
                    directories.add(cwd)
                continue

        # cloned processes inherit the cwd of the parent process
        elif 'clone(' in i:
            if '<unfinished ...>' in i:
                backlog.append(i.strip())
                backlogged = True
                continue
            cloneres = clonere.search(i)
            if cloneres is not None:
                if not pid in parenttopid:
                    parenttopid[pid] = []
                clonepid = cloneres.groups()[0]
                while True:
                    newpidlabel = clonepid
                    for n in range(4):
                        # add a random string at the end of the pid, just consisting of ascii letters
                        # the PIDs themselves are not really interesting anyway, so can be rewritten.
                        newpidlabel = newpidlabel + random.choice(string.ascii_letters)
                    if not newpidlabel in knownpids:
                        knownpids.add(newpidlabel)
                        pidtopidlabel[clonepid] = newpidlabel
                        break
                if clonepid in knownchildpids:
                    # now rewrite the ID to something sensible first
                    translatepids = {}
                    while True:
                        newclonepid = clonepid
                        for n in range(4):
                            # add a random string at the end of the pid, just consisting of ascii letters
                            # the PIDs themselves are not really interesting anyway, so can be rewritten.
                            newclonepid = newclonepid + random.choice(string.ascii_letters)
                        if not newclonepid in knownchildpids:
                            knownchildpids.add(newclonepid)
                            translatepids[clonepid] = newclonepid
                            break

                    while len(translatepids) != 0:
                        pidstoremove = set()
                        for t in translatepids:
                            # first check if the translated value
                            # is in parenttopid to prevent that values
                            # are overwritten
                            if translatepids[t] in parenttopid:
                                continue
                            if translatepids[t] in pidtocmd:
                                continue
                            # now translate everything
                            # first the parent
                            if t in parenttopid:
                                # first rewrite all the children
                                for pp in parenttopid[t]:
                                    pidtoparent[pp] = translatepids[t]
                                parenttopid[translatepids[t]] = copy.deepcopy(parenttopid[t])
                                del parenttopid[t]
                            if t in pidtocmd:
                                print("translating", t, translatepids[t], pidtocmd[t])
                                pidtocmd[translatepids[t]] = copy.deepcopy(pidtocmd[t])
                                del pidtocmd[t]
                            if t in pidtoparent:
                                parenttopid[pidtoparent[t]].remove(t)
                                parenttopid[pidtoparent[t]].append(translatepids[t])
                                pidtoparent[translatepids[t]] = copy.deepcopy(pidtoparent[t])
                                del pidtoparent[t]
                            pidstoremove.add(t)
                        for to in pidstoremove:
                            del translatepids[t]

                parenttopid[pid].append(clonepid)
                pidtoparent[clonepid] = pid
                pidtocwd[clonepid] = copy.deepcopy(pidtocwd[pid])
                knownchildpids.add(clonepid)

        # look through the lines with 'resumed' to find the PIDs of child processes
        # and store them.
        if " resumed>" in i:
            # This is an alternative way to get to the first PID in some circumstances
            if pid not in knownpids:
                defaultpid = pid
                pidtocwd[pid] = copy.deepcopy(pidtocwd['default'])
                if 'default' in pidtocmd:
                    pidtocmd[pid] = copy.deepcopy(pidtocmd['default'])
            if 'vfork' in i:
                vforkres = vforkresumedre.search(i)
                if vforkres is not None:
                    if not pid in parenttopid:
                        parenttopid[pid] = []
                    vforkpid = vforkres.groups()[0]
                    while True:
                        newpidlabel = vforkpid
                        for n in range(4):
                            # add a random string at the end of the pid, just consisting of ascii letters
                            # the PIDs themselves are not really interesting anyway, so can be rewritten.
                            newpidlabel = newpidlabel + random.choice(string.ascii_letters)
                        if not newpidlabel in knownpids:
                            knownpids.add(newpidlabel)
                            pidtopidlabel[vforkpid] = newpidlabel
                            break
                    if vforkpid in knownchildpids:
                        # now rewrite the ID to something sensible first
                        translatepids = {}
                        while True:
                            newclonepid = vforkpid
                            for n in range(4):
                                # add a random string at the end of the pid, just consisting of ascii letters
                                # the PIDs themselves are not really interesting anyway, so can be rewritten.
                                newclonepid = newclonepid + random.choice(string.ascii_letters)
                            if not newclonepid in knownchildpids:
                                knownchildpids.add(newclonepid)
                                translatepids[vforkpid] = newclonepid
                                break

                        while len(translatepids) != 0:
                            pidstoremove = set()
                            for t in translatepids:
                                # first check if the translated value
                                # is in parenttopid to prevent that values
                                # are overwritten
                                if translatepids[t] in parenttopid:
                                    continue
                                if translatepids[t] in pidtocmd:
                                    continue
                                # now translate everything
                                # first the parent
                                if t in parenttopid:
                                    # first rewrite all the children
                                    for pp in parenttopid[t]:
                                        pidtoparent[pp] = translatepids[t]
                                    parenttopid[translatepids[t]] = copy.deepcopy(parenttopid[t])
                                    del parenttopid[t]
                                if t in pidtocmd:
                                    print("translating", t, translatepids[t], pidtocmd[t])
                                    pidtocmd[translatepids[t]] = copy.deepcopy(pidtocmd[t])
                                    del pidtocmd[t]
                                if t in pidtoparent:
                                    parenttopid[pidtoparent[t]].remove(t)
                                    parenttopid[pidtoparent[t]].append(translatepids[t])
                                    pidtoparent[translatepids[t]] = copy.deepcopy(pidtoparent[t])
                                    del pidtoparent[t]
                                pidstoremove.add(t)
                            for to in pidstoremove:
                                del translatepids[t]

                    parenttopid[pid].append(vforkpid)
                    pidtoparent[vforkpid] = pid
                    pidtocwd[vforkpid] = copy.deepcopy(pidtocwd[pid])
                    knownchildpids.add(vforkpid)
            elif 'clone' in i:
                cloneres = cloneresumedre.search(i.strip())
                if cloneres is not None:
                    if not pidtopidlabel[pid] in parenttopid:
                        parenttopid[pidtopidlabel[pid]] = []
                    clonepid = cloneres.groups()[0]
                    while True:
                        newpidlabel = clonepid
                        for n in range(4):
                            # add a random string at the end of the pid, just consisting of ascii letters
                            # the PIDs themselves are not really interesting anyway, so can be rewritten.
                            newpidlabel = newpidlabel + random.choice(string.ascii_letters)
                        if not newpidlabel in knownpids:
                            knownpids.add(newpidlabel)
                            pidtopidlabel[clonepid] = newpidlabel
                            break

                    parenttopid[pidtopidlabel[pid]].append(pidtopidlabel[clonepid])
                    pidtoparent[pidtopidlabel[clonepid]] = pidtopidlabel[pid]
                    pidtocwd[pidtopidlabel[clonepid]] = copy.deepcopy(pidtocwd[pidtopidlabel[pid]])
                    if backlog != []:
                        for traceline in backlog:
                            process_trace_line(traceline, defaultpid, pidtocwd, pidtocmd, directories, ignore_files, openfiles, basepath, defaultcwd, pidtopidlabel)
                        backlog = []
                        backlogged = False
                    knownchildpids.add(pidtopidlabel[clonepid])

        if backlogged:
            backlog.append(i.strip())
            continue

        # add the pid to the list of known PIDs
        knownpids.add(pidtopidlabel[pid])

        # then look at the lines that have either 'unfinished' or 'resumed'
        # Because the -y flag to strace is doing the heavy lifting just a bit of processing
        # needs to be done for open() and openat() to make sure that false positives are
        # not included.
        if "<unfinished ...>" in i or " resumed>" in i:
            if not ' resumed>' in i:
                if 'open(' in i or 'openat(' in i:
                    processopen = False
                    if 'openat(' in i:
                        openatres = re.search(r"openat\((\w+), \"([<>\w/\-+,.]+)\", ([\w|]+)", i.strip())
                        if openatres is not None:
                            openfd = os.path.normpath(openatres.groups()[0])
                            openpath = os.path.normpath(openatres.groups()[1])
                            openflags = set(openatres.groups()[2].split('|'))
                            processopen = True
                    elif 'open(' in i:
                        openres = re.search(r"open\(\"([<>\w/\-+,.*$:;]+)\", ([\w|]+)", i.strip())
                        if openres is not None:
                            openpath = os.path.normpath(openres.groups()[0])
                            openflags = set(openres.groups()[1].split('|'))
                            processopen = True

                    if processopen:
                        # now check the flags to see if a file is new. If so, it can
                        # be added to ignore_files
                        # Don't look at directories here, as sometimes regular files are
                        # opened with O_DIRECTORY and will fail with -1, which can only
                        # be found out later. This is too risky and could lead to files
                        # being ignored that should not be ignored.
                        if "O_RDWR" in openflags or "O_WRONLY" in openflags:
                            if "O_CREAT" in openflags:
                                if "O_EXCL" in openflags or "O_TRUNC" in openflags:
                                    openpath = os.path.normpath(os.path.join(pidtocwd[pid], openpath))
                                    ignore_files.add(openpath)
            else:
                # look at 'resumed'
                if '<... open' in i:
                    openres = re.search(r'<... open(?:at)? resumed> \)\s+=\s+(?P<return>\-?\d+)', i)
                    if openres is not None:
                        openreturn = openres.group('return')
                        if openreturn != '-1':
                            # only look at files that can be succesfully opened
                            openres = re.search(r'<... open(:?at)? resumed> \)\s+=\s+\d+<(?P<path>.*)>$', i)
                            if openres is not None:
                                openpath = openres.group('path')

                                # absolute paths are only relevant if
                                # coming from the same source code directory
                                if openpath.startswith('/'):
                                    if not openpath.startswith(basepath):
                                        continue

                                if openpath in ignore_files:
                                    # not interested in files that have been created by
                                    # the process, as they will not have been in the
                                    # original source code tree
                                    continue

                                if openpath in openfiles:
                                    # files that are already recorded as open
                                    # can be ignored
                                    continue

                                if openpath in directories:
                                    # directories can be safely ignored
                                    continue

                                # add the full reconstructed path, relative to root
                                openfiles.add(openpath)
        else:
            process_trace_line(i.strip(), defaultpid, pidtocwd, pidtocmd, directories, ignore_files, openfiles, basepath, defaultcwd, pidtopidlabel)

    print("END RECONSTRUCTION", datetime.datetime.utcnow().isoformat(), file=sys.stderr)

    # now compute the hashes for the files, if the correct source code is actually available

    if targetdir is not None and sourcedir is not None:
        print(f"COPYING FILES TO {targetdir}")
        for i in openfiles:
            filename = i[len(basepath)+1:]
            basedir = os.path.dirname(i[len(basepath)+1:])
            if not os.path.exists(os.path.join(sourcedir, filename)):
                continue
            if os.path.isdir(os.path.join(sourcedir, filename)):
                continue
            if basedir != '':
                try:
                    os.makedirs(os.path.join(targetdir, basedir))
                except:
                    pass
                shutil.copy(os.path.join(sourcedir, filename), os.path.join(targetdir, basedir))
            else:
                shutil.copy(os.path.join(sourcedir, filename), targetdir)
    for p in pidtocmd:
        print(p, pidtocmd[p])

    for p in parenttopid:
        if p in pidtocmd:
            print("%s (%s) created: " % (p, pidtocmd[p]), parenttopid[p])
        else:
            print("%s created: " % p, parenttopid[p])

if __name__ == "__main__":
    main(sys.argv)
