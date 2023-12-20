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

import copy
import datetime
import os
import pathlib
import random
import re
import shutil
import string
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

def process_trace_line(traceline, default_pid, pid_to_cwd, pid_to_cmd, directories, ignore_files, openfiles, basepath, default_cwd, pidtopidlabel):
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
        if default_pid is not None:
            pid = default_pid
        else:
            pid = 'default'

    if not pid in pid_to_cwd and pid != 'default':
        pid_to_cwd[pid] = default_cwd

    if syscall in ['chdir', 'fchdir']:
        if syscall == 'fchdir':
            fchdirres = fchdirre.search(traceline)
            if fchdirres is not None:
                fchdirfd = int(fchdirres.groups()[0])
                fullchdirpath = fchdirres.groups()[1]
                fchdirresult = fchdirres.groups()[2]
                pid_to_cwd[pid] = fullchdirpath
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
                    pid_to_cwd[pid] = chdirpath
                    directories.add(chdirpath)
                else:
                    if pid in pid_to_cwd:
                        pid_to_cwd[pid] = os.path.normpath(os.path.join(basepath, pid_to_cwd[pid], chdirpath))
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
            sourcefile = os.path.normpath(os.path.join(pid_to_cwd[pid], renameres.groups()[0]))
            targetfile = os.path.normpath(os.path.join(pid_to_cwd[pid],renameres.groups()[1]))
            # check if sourcefile is in ignore_files. If so,
            # then targetfile should be as well.
            if sourcefile in ignore_files:
                ignore_files.add(targetfile)


@click.command(short_help='Process TechInfoDepot XML dump')
@click.option('--basepath', '-b', 'basepath', required=True,
              help='base path of source director during build', type=str)
@click.option('--buildid', '-u', 'buildid', required=True,
              help='string to identify the build with', type=str)
@click.option('--sourcedir', '-s', 'sourcedir',
              help='path of source directory', type=click.Path(path_type=pathlib.Path))
@click.option('--targetdir', '-t', 'targetdir',
              help='directory to copy/write files that were opened during the build',
              type=click.Path(path_type=pathlib.Path))
@click.option('--tracefile', '-f', 'tracefile', required=True, help='path to trace file',
               type=click.Path('r', path_type=pathlib.Path))
def main(basepath, buildid, sourcedir, targetdir, tracefile):
    # the base path of the source code directory used during the build.
    # This might actually be different than --sourcedir
    # in case the trace file is processed on a different machine
    if not os.path.isabs(basepath):
        raise click.ClickException("--basepath should point to an absolute path")

    copy_files = False

    # a directory where the source code files can be found for copying.
    # These might be the same as base path, but doesn't have to be.
    if sourcedir is not None:
        if not os.path.exists(sourcedir):
            raise click.ClickException("directory with source code files does not exist")
        copy_files = True

    # directory to copy the used files to from sourcedir
    if targetdir is not None:
        if not os.path.exists(targetdir):
            raise click.ClickException("target directory does not exist")
        if not copy_files:
            raise click.ClickException("target directory defined but '--sourcedir' is not set")
    else:
        copy_files = False

    if buildid.strip() == "":
        raise click.ClickException("build identifier empty")

    # TODO: symbolic links are actually resolved by strace when using
    # the -y option, so make sure that the basepath is first resolved as
    # well.
    basepath = os.path.normpath(basepath)

    tracefile = open(tracefile, 'r')

    default_cwd = ''
    firstgetcwd = False

    pid_to_cwd = {}
    pid_to_cmd = {}

    pidtopidlabel = {}

    directories = set()

    # store which processes create other processes and vice versa
    parent_to_pid = {}
    known_child_pids = set()

    # store the inputs and outputs per file
    inputs_per_pid = {}
    outputs_per_pid= {}

    # the pid of the first process is not shown in the trace file until after
    # returning from the first clone/execve/etc.
    # It is easy to find out what the top level PID is by keeping track of
    # which PIDs are known. When a system call is resumed for an unknown PID
    # that will be the top level PID.
    knownpids = set()

    # set a dummy value for the first PID
    default_pid = None

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
            if default_pid is not None:
                pid = default_pid
            else:
                pid = 'default'

        #if 'execve(' in i:
        #    execveres = execvere.search(i)
        #    if execveres is not None:
        #        pid_to_cmd[pid] = execveres.group('command')

        if 'getcwd(' in i:
            if not firstgetcwd:
                cwd = getcwdre.match(i).groups()[0]
                default_cwd = cwd
                firstgetcwd = True
                if 'default' not in pid_to_cwd:
                    pid_to_cwd['default'] = cwd
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
                if pid not in parent_to_pid:
                    parent_to_pid[pid] = []
                clonepid = cloneres.groups()[0]
                while True:
                    # add a random string at the end of the pid, just consisting
                    # of ascii letters the PIDs themselves are not really
                    # interesting anyway, so can be rewritten.
                    new_pid_label = clonepid + "".join(random.sample(string.ascii_letters, 4))
                    if not new_pid_label in knownpids:
                        knownpids.add(new_pid_label)
                        pidtopidlabel[clonepid] = new_pid_label
                        break
                if clonepid in known_child_pids:
                    # now rewrite the ID to something sensible first
                    translatepids = {}
                    while True:
                        # add a random string at the end of the pid, just consisting
                        # of ascii letters the PIDs themselves are not really
                        # interesting anyway, so can be rewritten.
                        newclonepid = clonepid + "".join(random.sample(string.ascii_letters, 4))
                        if not newclonepid in known_child_pids:
                            known_child_pids.add(newclonepid)
                            translatepids[clonepid] = newclonepid
                            break

                    while len(translatepids) != 0:
                        pidstoremove = set()
                        for t in translatepids:
                            # first check if the translated value
                            # is in parent_to_pid to prevent that values
                            # are overwritten
                            if translatepids[t] in parent_to_pid:
                                continue
                            if translatepids[t] in pid_to_cmd:
                                continue
                            # now translate everything
                            # first the parent
                            if t in parent_to_pid:
                                # first rewrite all the children
                                for pp in parent_to_pid[t]:
                                    pid_to_parent[pp] = translatepids[t]
                                parent_to_pid[translatepids[t]] = copy.deepcopy(parent_to_pid[t])
                                del parent_to_pid[t]
                            if t in pid_to_cmd:
                                print("translating", t, translatepids[t], pid_to_cmd[t])
                                pid_to_cmd[translatepids[t]] = copy.deepcopy(pid_to_cmd[t])
                                del pid_to_cmd[t]
                            if t in pid_to_parent:
                                parent_to_pid[pid_to_parent[t]].remove(t)
                                parent_to_pid[pid_to_parent[t]].append(translatepids[t])
                                pid_to_parent[translatepids[t]] = copy.deepcopy(pid_to_parent[t])
                                del pid_to_parent[t]
                            pidstoremove.add(t)
                        for t in pidstoremove:
                            del translatepids[t]

                parent_to_pid[pid].append(clonepid)
                pid_to_parent[clonepid] = pid
                pid_to_cwd[clonepid] = copy.deepcopy(pid_to_cwd[pid])
                known_child_pids.add(clonepid)

        # look through the lines with 'resumed' to find the PIDs of child processes
        # and store them.
        if " resumed>" in i:
            # This is an alternative way to get to the first PID in some circumstances
            if pid not in knownpids:
                default_pid = pid
                pid_to_cwd[pid] = copy.deepcopy(pid_to_cwd['default'])
                if 'default' in pid_to_cmd:
                    pid_to_cmd[pid] = copy.deepcopy(pid_to_cmd['default'])
            if 'vfork' in i:
                vforkres = vforkresumedre.search(i)
                if vforkres is not None:
                    if pid not in parent_to_pid:
                        parent_to_pid[pid] = []
                    vforkpid = vforkres.groups()[0]
                    while True:
                        # add a random string at the end of the pid, just consisting
                        # of ascii letters # the PIDs themselves are not really
                        # interesting anyway, so can be rewritten.
                        new_pid_label = vforkpid + "".join(random.sample(string.ascii_letters, 4))
                        if not new_pid_label in knownpids:
                            knownpids.add(new_pid_label)
                            pidtopidlabel[vforkpid] = new_pid_label
                            break
                    if vforkpid in known_child_pids:
                        # now rewrite the ID to something sensible first
                        translatepids = {}
                        while True:
                            # add a random string at the end of the pid, just consisting
                            # of ascii letters the PIDs themselves are not really
                            # interesting anyway, so can be rewritten.
                            newclonepid = vforkpid + "".join(random.sample(string.ascii_letters, 4))
                            if not newclonepid in known_child_pids:
                                known_child_pids.add(newclonepid)
                                translatepids[vforkpid] = newclonepid
                                break

                        while len(translatepids) != 0:
                            pidstoremove = set()
                            for t in translatepids:
                                # first check if the translated value
                                # is in parent_to_pid to prevent that values
                                # are overwritten
                                if translatepids[t] in parent_to_pid:
                                    continue
                                if translatepids[t] in pid_to_cmd:
                                    continue
                                # now translate everything
                                # first the parent
                                if t in parent_to_pid:
                                    # first rewrite all the children
                                    for pp in parent_to_pid[t]:
                                        pid_to_parent[pp] = translatepids[t]
                                    parent_to_pid[translatepids[t]] = copy.deepcopy(parent_to_pid[t])
                                    del parent_to_pid[t]
                                if t in pid_to_cmd:
                                    print("translating", t, translatepids[t], pid_to_cmd[t])
                                    pid_to_cmd[translatepids[t]] = copy.deepcopy(pid_to_cmd[t])
                                    del pid_to_cmd[t]
                                if t in pid_to_parent:
                                    parent_to_pid[pid_to_parent[t]].remove(t)
                                    parent_to_pid[pid_to_parent[t]].append(translatepids[t])
                                    pid_to_parent[translatepids[t]] = copy.deepcopy(pid_to_parent[t])
                                    del pid_to_parent[t]
                                pidstoremove.add(t)
                            for to in pidstoremove:
                                del translatepids[t]

                    parent_to_pid[pid].append(vforkpid)
                    pid_to_parent[vforkpid] = pid
                    pid_to_cwd[vforkpid] = copy.deepcopy(pid_to_cwd[pid])
                    known_child_pids.add(vforkpid)
            elif 'clone' in i:
                cloneres = cloneresumedre.search(i.strip())
                if cloneres is not None:
                    if not pidtopidlabel[pid] in parent_to_pid:
                        parent_to_pid[pidtopidlabel[pid]] = []
                    clonepid = cloneres.groups()[0]
                    while True:
                        # add a random string at the end of the pid, just consisting
                        # of ascii letters the PIDs themselves are not really
                        # interesting anyway, so can be rewritten.
                        new_pid_label = clonepid + "".join(random.sample(string.ascii_letters, 4))
                        if not new_pid_label in knownpids:
                            knownpids.add(new_pid_label)
                            pidtopidlabel[clonepid] = new_pid_label
                            break

                    parent_to_pid[pidtopidlabel[pid]].append(pidtopidlabel[clonepid])
                    pid_to_parent[pidtopidlabel[clonepid]] = pidtopidlabel[pid]
                    pid_to_cwd[pidtopidlabel[clonepid]] = copy.deepcopy(pid_to_cwd[pidtopidlabel[pid]])
                    if backlog != []:
                        for traceline in backlog:
                            process_trace_line(traceline, default_pid, pid_to_cwd, pid_to_cmd,
                                               directories, ignore_files, openfiles, basepath,
                                               default_cwd, pidtopidlabel)
                        backlog = []
                        backlogged = False
                    known_child_pids.add(pidtopidlabel[clonepid])

        if backlogged:
            backlog.append(i.strip())
            continue

        # add the pid to the list of known PIDs
        knownpids.add(pidtopidlabel[pid])

        # then look at the lines that have either 'unfinished' or 'resumed'
        # Because the -y flag to strace is doing the heavy lifting just a bit of
        # processing needs to be done for open() and openat() to make sure that
        # false positives are not included.
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
                                    openpath = os.path.normpath(os.path.join(pid_to_cwd[pid], openpath))
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
            process_trace_line(i.strip(), default_pid, pid_to_cwd, pid_to_cmd, directories,
                               ignore_files, openfiles, basepath, default_cwd, pidtopidlabel)

    print("END RECONSTRUCTION", datetime.datetime.utcnow().isoformat(), file=sys.stderr)

    if copy_files:
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

    for pid in pid_to_cmd:
        print(pid, pid_to_cmd[pid])

    for pid in parent_to_pid:
        if pid in pid_to_cmd:
            print("%s (%s) created: " % (pid, pid_to_cmd[pid]), parent_to_pid[pid])
        else:
            print("%s created: " % pid, parent_to_pid[pid])

if __name__ == "__main__":
    main()
