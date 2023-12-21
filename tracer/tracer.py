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

IGNORE_DIRECTORIES = ['/dev/', '/proc/', '/sys/']

# there are only a few syscalls that are interesting
INTERESTING_SYSCALLS = ['open', 'openat', 'chdir', 'fchdir',
                        'rename', 'renameat2', 'clone', 'clone3', 'symlink', 'symlinkat']

# regular expression for process IDs (PIDs)
pidre = re.compile(r'\[pid\s+(\d+)\]')
pid_with_syscall_re = re.compile(r'\[pid\s+(\d+)\]\s+(\w+)\(')

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
clone_resumed_re = re.compile(r"clone\s*resumed>\s*.*=\s+(\-?\d+)$")
vforkresumedre = re.compile(r"vfork\s*resumed>\s*\)\s*=\s*(\d+)")
vforkre = re.compile(r"vfork\(\s*\)\s*=\s*(\d+)")
#execvere = re.compile(r"execve\(\"(?P<command>.*)\",\s*\[(?P<args>.*)\],\s+0x\w+\s+/\*\s+\d+\s+vars\s+\*/\)\s*=\s*(?P<returncode>\-?\d+)")
execvere = re.compile(r"execve\(\"(?P<command>.*)\",\s*\[(?P<args>.*)\],\s+0x\w+\s+/\*\s+\d+\s+vars\s+\*/")
# symlinkre =
# symlinkatre =

def rewrite_pid(pid):
    # add a random string at the end of the pid, just consisting
    # of ascii letters the PIDs themselves are not really
    # interesting anyway, so can be rewritten.
    new_pid = pid + "".join(random.sample(string.ascii_letters, 4))
    return new_pid

def process_trace_line(traceline, default_pid, pid_to_cwd, pid_to_cmd, directories, ignore_files,
                       open_files, basepath, default_cwd, pid_to_pid_label):
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
            del pid_to_pid_label[sigchldpid]

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
                full_chdir_path = fchdirres.groups()[1]
                fchdirresult = fchdirres.groups()[2]
                pid_to_cwd[pid] = full_chdir_path
                directories.add(full_chdir_path)
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
    elif syscall == 'open':
        openres = openre.search(traceline)
        if openres is not None:
            openreturn = openres.groups()[2]
            if openreturn == '-1':
                # -1 means "No such file or directory" so ignore
                return
            openpath = os.path.normpath(openres.groups()[0])
            open_flags = set(openres.groups()[1].split('|'))
            full_open_path = openres.groups()[3]

            if full_open_path in directories:
                # directories can be safely ignored
                return

            # ignore files that should be ignored
            if full_open_path in ignore_files:
                return

            # if files have already been recorded they are not interesting
            if full_open_path in open_files:
                return

            # directories are not interesting, except to store the
            # file descriptor
            if 'O_DIRECTORY' in open_flags:
                directories.add(full_open_path)
                return
            # absolute paths are only relevant if
            # coming from the same source code directory
            if openpath.startswith('/'):
                if not openpath.startswith(str(basepath)):
                    return
            # now check the flags to see if a file is new. If so, it can
            # be added to ignore_files
            if "O_RDWR" in open_flags or "O_WRONLY" in open_flags:
                if "O_CREAT" in open_flags:
                    if "O_EXCL" in open_flags or "O_TRUNC" in open_flags:
                        ignore_files.add(full_open_path)
                        return
            # add the full reconstructed path, relative to root
            open_files.add(full_open_path)

    if syscall == 'openat':
        openres = openatre.search(traceline)
        if openres is not None:
            openfd = os.path.normpath(openres.groups()[0])
            openpath = os.path.normpath(openres.groups()[1])
            open_flags = set(openres.groups()[2].split('|'))
            openreturn = openres.groups()[3]
            full_open_path = openres.groups()[4]
        else:
            openres = openatre2.search(traceline)
            if openres is not None:
                openfd = os.path.normpath(openres.groups()[0])
                openpath = os.path.normpath(openres.groups()[2])
                open_flags = set(openres.groups()[3].split('|'))
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
            if full_open_path in open_files:
                return
            # directories are not interesting, so record them to ignore them
            if 'O_DIRECTORY' in open_flags:
                directories.add(full_open_path)
                return
            if openpath.startswith('/'):
                if not openpath.startswith(str(basepath)):
                    return
            # now check the flags to see if a file is new
            if "O_RDWR" in open_flags or "O_WRONLY" in open_flags:
                if "O_CREAT" in open_flags:
                    if "O_EXCL" in open_flags or "O_TRUNC" in open_flags:
                        ignore_files.add(full_open_path)
                        return

            # add the full reconstructed path, relative to root
            open_files.add(full_open_path)

    if syscall == 'rename':
        renameres = renamere.search(traceline)
        if renameres is not None:
            sourcefile = os.path.normpath(os.path.join(pid_to_cwd[pid], renameres.groups()[0]))
            targetfile = os.path.normpath(os.path.join(pid_to_cwd[pid],renameres.groups()[1]))
            # check if sourcefile is in ignore_files. If so,
            # then targetfile should be as well.
            if sourcefile in ignore_files:
                ignore_files.add(targetfile)

@click.command(short_help='Process strace output')
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
               type=click.File('r'))
def main(basepath, buildid, sourcedir, targetdir, tracefile):
    # the base path of the source code directory used during the build.
    # This might actually be different than --sourcedir
    # in case the trace file is processed on a different machine
    basepath = pathlib.Path(os.path.normpath(basepath))

    if not basepath.is_absolute():
        raise click.ClickException("--basepath should point to an absolute path")

    copy_files = False

    # a directory where the source code files can be found for copying.
    # These might be the same as base path, but doesn't have to be.
    if sourcedir is not None:
        if not sourcedir.exists():
            raise click.ClickException("directory with source code files does not exist")
        copy_files = True

    # directory to copy the used files to from sourcedir
    if targetdir is not None:
        if not targetdir.exists():
            raise click.ClickException("target directory does not exist")
        if not copy_files:
            raise click.ClickException("target directory defined but '--sourcedir' is not set")
    else:
        copy_files = False

    if buildid.strip() == "":
        raise click.ClickException("build identifier empty")

    # TODO: symbolic links are actually resolved by strace when using
    # the -y option. Make sure this is properly handled.

    default_cwd = ''
    first_getcwd = False

    pid_to_cwd = {}
    pid_to_cmd = {}
    pid_to_parent = {}

    # lookup table for current PIDs to a unique PID.
    # This is because PIDs can be reused for processes.
    pid_to_pid_label = {}

    directories = set()

    # store paths of programs that are used during the build
    # process, typically in execve()
    exec_programs = set()

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
    known_pids = set()

    # set a dummy value for the first PID
    default_pid = None

    open_files = set()

    # a list of files created or overwritten, so can be ignored later on
    ignore_files = set()

    backlog = []
    backlogged = False

    # walk through the lines of the strace log. There are a few caveats:
    # * not every line has the full contents of a single systam call. Calls
    #   can be interrupted ('unfinished') and then resume, so a record has
    #   to be kept which line belongs to which PID
    # * PIDs can wrap around and be reused by different processes. There is
    #   only a limited amount of process IDs so for very large builds (like
    #   the Linux kernel these are reused for unrelated processes. This is why
    #   PIDs are stored with a unique identifier so there are no clashes. The
    #   only exception is the top level PID, which will not be reused.
    for line in tracefile:
        # either there is an exit code, or the system call is unfinished. The rest
        # is irrelevant garbage.
        # Assume that strace is running in English. Right now (December 20, 2023) strace
        # has not been translated, so this is a safe assumption.
        if not ('=' in line or 'unfinished' in line):
            continue

        # grab the PID and syscall, or just the syscall
        # if the line is for the top level PID.
        pid_syscall = pid_with_syscall_re.match(line)
        if pid_syscall is not None:
            pid, syscall = pid_syscall.groups()
        else:
            syscall_res = re.match(r"(\w+)\(", line)
            if syscall_res is None:
                # garbage line
                continue

            syscall = syscall_res.groups()[0]

            # This is a line for the top level pid. It actually is possible
            # to later find the actual pid if the top level process forks
            # a process and the process returns, or if a vfork call is resumed.
            if default_pid is not None:
                pid = default_pid
            else:
                pid = 'default'
                pid_to_pid_label[pid] = pid

        # Process a few system calls separately from the rest,
        # as these can change relevant metadata and this metadata
        # needs to be properly stored.

        if syscall == 'execve':
            execveres = execvere.search(line)
            if execveres is not None:
                #pid_to_cmd[pid] = execveres.group('command')
                exec_programs.add(execveres.group('command'))

        if syscall == 'getcwd' and not first_getcwd:
            # record the first instance of getcwd()
            cwd = getcwdre.match(line).groups()[0]
            default_cwd = cwd
            first_getcwd = True
            if 'default' not in pid_to_cwd:
                pid_to_cwd['default'] = cwd
                directories.add(cwd)

        # cloned processes inherit the cwd of the parent process.
        # First retrieve the information for the parent process and
        # store it for the cloned process.
        elif syscall == 'clone':
            if '<unfinished ...>' in line:
                backlog.append(line.strip())
                backlogged = True
                continue

            cloneres = clonere.search(line)
            if cloneres is not None:
                if pid not in parent_to_pid:
                    parent_to_pid[pid] = []
                clonepid = cloneres.groups()[0]
                while True:
                    new_pid_label = rewrite_pid(clonepid)
                    if new_pid_label not in known_pids:
                        known_pids.add(new_pid_label)
                        pid_to_pid_label[clonepid] = new_pid_label
                        break
                if clonepid in known_child_pids:
                    # now rewrite the ID to something sensible first
                    translate_pids = {}
                    while True:
                        new_clone_pid = rewrite_pid(clonepid)
                        if new_clone_pid not in known_child_pids:
                            known_child_pids.add(new_clone_pid)
                            translate_pids[clonepid] = new_clone_pid
                            break

                    while len(translate_pids) != 0:
                        pids_to_remove = set()
                        for t in translate_pids:
                            # first check if the translated value
                            # is in parent_to_pid to prevent that values
                            # are overwritten
                            if translate_pids[t] in parent_to_pid:
                                continue
                            if translate_pids[t] in pid_to_cmd:
                                continue
                            # now translate everything
                            # first the parent
                            if t in parent_to_pid:
                                # first rewrite all the children
                                for pp in parent_to_pid[t]:
                                    pid_to_parent[pp] = translate_pids[t]
                                parent_to_pid[translate_pids[t]] = copy.deepcopy(parent_to_pid[t])
                                del parent_to_pid[t]
                            if t in pid_to_cmd:
                                print("translating", t, translate_pids[t], pid_to_cmd[t])
                                pid_to_cmd[translate_pids[t]] = copy.deepcopy(pid_to_cmd[t])
                                del pid_to_cmd[t]
                            if t in pid_to_parent:
                                parent_to_pid[pid_to_parent[t]].remove(t)
                                parent_to_pid[pid_to_parent[t]].append(translate_pids[t])
                                pid_to_parent[translate_pids[t]] = copy.deepcopy(pid_to_parent[t])
                                del pid_to_parent[t]
                            pids_to_remove.add(t)
                        for t in pids_to_remove:
                            del translate_pids[t]

                parent_to_pid[pid].append(clonepid)
                pid_to_parent[clonepid] = pid
                pid_to_cwd[clonepid] = copy.deepcopy(pid_to_cwd[pid])
                known_child_pids.add(clonepid)

        # look through the lines with 'resumed' to find the PIDs of child processes
        # and store them.
        if " resumed>" in line:
            # This is an alternative way to get to the first PID in some circumstances
            if pid not in known_pids:
                default_pid = pid
                pid_to_cwd[pid] = copy.deepcopy(pid_to_cwd['default'])
                if 'default' in pid_to_cmd:
                    pid_to_cmd[pid] = copy.deepcopy(pid_to_cmd['default'])
            if 'vfork' in line:
                vforkres = vforkresumedre.search(line)
                if vforkres is not None:
                    if pid not in parent_to_pid:
                        parent_to_pid[pid] = []
                    vforkpid = vforkres.groups()[0]
                    while True:
                        new_pid_label = rewrite_pid(vforkpid)
                        if new_pid_label not in known_pids:
                            known_pids.add(new_pid_label)
                            pid_to_pid_label[vforkpid] = new_pid_label
                            break
                    if vforkpid in known_child_pids:
                        # now rewrite the ID to something sensible first
                        translate_pids = {}
                        while True:
                            new_clone_pid = rewrite_pid(vforkpid)
                            if new_clone_pid not in known_child_pids:
                                known_child_pids.add(new_clone_pid)
                                translate_pids[vforkpid] = new_clone_pid
                                break

                        while len(translate_pids) != 0:
                            pids_to_remove = set()
                            for t in translate_pids:
                                # first check if the translated value
                                # is in parent_to_pid to prevent that values
                                # are overwritten
                                if translate_pids[t] in parent_to_pid:
                                    continue
                                if translate_pids[t] in pid_to_cmd:
                                    continue
                                # now translate everything
                                # first the parent
                                if t in parent_to_pid:
                                    # first rewrite all the children
                                    for pp in parent_to_pid[t]:
                                        pid_to_parent[pp] = translate_pids[t]
                                    parent_to_pid[translate_pids[t]] = copy.deepcopy(parent_to_pid[t])
                                    del parent_to_pid[t]
                                if t in pid_to_cmd:
                                    print("translating", t, translate_pids[t], pid_to_cmd[t])
                                    pid_to_cmd[translate_pids[t]] = copy.deepcopy(pid_to_cmd[t])
                                    del pid_to_cmd[t]
                                if t in pid_to_parent:
                                    parent_to_pid[pid_to_parent[t]].remove(t)
                                    parent_to_pid[pid_to_parent[t]].append(translate_pids[t])
                                    pid_to_parent[translate_pids[t]] = copy.deepcopy(pid_to_parent[t])
                                    del pid_to_parent[t]
                                pids_to_remove.add(t)
                            for t in pids_to_remove:
                                del translate_pids[t]

                    parent_to_pid[pid].append(vforkpid)
                    pid_to_parent[vforkpid] = pid
                    pid_to_cwd[vforkpid] = copy.deepcopy(pid_to_cwd[pid])
                    known_child_pids.add(vforkpid)
            elif 'clone' in line:
                cloneres = clone_resumed_re.search(line.strip())
                if cloneres is not None:
                    if pid_to_pid_label[pid] not in parent_to_pid:
                        parent_to_pid[pid_to_pid_label[pid]] = []
                    clonepid = cloneres.groups()[0]
                    while True:
                        new_pid_label = rewrite_pid(clonepid)
                        if new_pid_label not in known_pids:
                            known_pids.add(new_pid_label)
                            pid_to_pid_label[clonepid] = new_pid_label
                            break

                    parent_to_pid[pid_to_pid_label[pid]].append(pid_to_pid_label[clonepid])
                    pid_to_parent[pid_to_pid_label[clonepid]] = pid_to_pid_label[pid]
                    pid_to_cwd[pid_to_pid_label[clonepid]] = copy.deepcopy(pid_to_cwd[pid_to_pid_label[pid]])
                    if backlog != []:
                        for traceline in backlog:
                            process_trace_line(traceline, default_pid, pid_to_cwd, pid_to_cmd,
                                               directories, ignore_files, open_files, basepath,
                                               default_cwd, pid_to_pid_label)
                        backlog = []
                        backlogged = False
                    known_child_pids.add(pid_to_pid_label[clonepid])

        # store the line for later processing
        if backlogged:
            backlog.append(line.strip())
            continue

        # add the pid to the list of known PIDs
        known_pids.add(pid_to_pid_label[pid])

        # then look at the lines that have either 'unfinished' or 'resumed'
        # Because the -y flag to strace is doing the heavy lifting just a bit of
        # processing needs to be done for open() and openat() to make sure that
        # false positives are not included.
        if "<unfinished ...>" in line or " resumed>" in line:
            if not ' resumed>' in line:
                if 'open(' in line or 'openat(' in line:
                    process_open = False
                    if 'openat(' in line:
                        openatres = re.search(r"openat\((\w+), \"([<>\w/\-+,.]+)\", ([\w|]+)", line.strip())
                        if openatres is not None:
                            openfd = os.path.normpath(openatres.groups()[0])
                            openpath = os.path.normpath(openatres.groups()[1])
                            open_flags = set(openatres.groups()[2].split('|'))
                            process_open = True
                    elif 'open(' in line:
                        openres = re.search(r"open\(\"([<>\w/\-+,.*$:;]+)\", ([\w|]+)", line.strip())
                        if openres is not None:
                            openpath = os.path.normpath(openres.groups()[0])
                            open_flags = set(openres.groups()[1].split('|'))
                            process_open = True

                    if process_open:
                        # now check the flags to see if a file is new. If so, it can
                        # be added to ignore_files
                        # Don't look at directories here, as sometimes regular files are
                        # opened with O_DIRECTORY and will fail with -1, which can only
                        # be found out later. This is too risky and could lead to files
                        # being ignored that should not be ignored.
                        if "O_RDWR" in open_flags or "O_WRONLY" in open_flags:
                            if "O_CREAT" in open_flags:
                                if "O_EXCL" in open_flags or "O_TRUNC" in open_flags:
                                    openpath = os.path.normpath(os.path.join(pid_to_cwd[pid], openpath))
                                    ignore_files.add(openpath)
            else:
                # look at 'resumed'
                if '<... open' in line:
                    openres = re.search(r'<... open(?:at)? resumed> \)\s+=\s+(?P<return>\-?\d+)', line)
                    if openres is not None:
                        openreturn = openres.group('return')
                        if openreturn != '-1':
                            # only look at files that can be succesfully opened
                            openres = re.search(r'<... open(:?at)? resumed> \)\s+=\s+\d+<(?P<path>.*)>$', line)
                            if openres is not None:
                                openpath = openres.group('path')

                                # absolute paths are only relevant if
                                # coming from the same source code directory
                                if openpath.startswith('/'):
                                    if not openpath.startswith(str(basepath)):
                                        continue

                                if openpath in ignore_files:
                                    # not interested in files that have been created by
                                    # the process, as they will not have been in the
                                    # original source code tree
                                    continue

                                if openpath in open_files:
                                    # files that are already recorded as open
                                    # can be ignored
                                    continue

                                if openpath in directories:
                                    # directories can be safely ignored
                                    continue

                                # add the full reconstructed path, relative to root
                                open_files.add(openpath)
        else:
            process_trace_line(line.strip(), default_pid, pid_to_cwd, pid_to_cmd, directories,
                               ignore_files, open_files, basepath, default_cwd, pid_to_pid_label)

    print("END RECONSTRUCTION", datetime.datetime.utcnow().isoformat(), file=sys.stderr)

    if copy_files:
        print(f"COPYING FILES TO {targetdir}")
        for i in open_files:
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
            print(f"{pid} created: ", parent_to_pid[pid])

if __name__ == "__main__":
    main()
