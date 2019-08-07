# About

This scripts processes a list of strings from the Linux kernel or a Linux
kernel module and compares it to the output of a Git diffstat to see if there
are matches.

It expects a file with lines that have been extracted from a Linux kernel
binary for example:

    $ strings /path/to/kernel/binary | egrep -e '\.[ch]$' | grep / > /path/to/kernel/strings/file

This script takes two parameters:

1. Git diffstat listing
2. output file as generated above

To create a diffstat you will first need a local clone of the repository, which
can be done with "git", for example:

    $ git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git

A diffstat for a single author can be generated from a Git repository
using 'git' and 'diffstat', for example:

    $ git log -p --author=torvalds | diffstat -p1 > /path/to/diffstat/file

The script can then be invoked as follows:

    $ python3 diffstatverifier.py -d /path/to/diffstat/file -k /path/to/kernel/strings/file

The script will print three sets of results (concatenated):

1. file names that can be found in both the diffstat and the strings extracted from the Linux kernel
2. file names that can only be found in the diffstat, but not in the strings extracted from the Linux kernel
3. file names that can only be found in the strings extracted from the kernel, but not in the diffstat

It should be noted that the Linux kernel build process does not record every
file name that has been compiled into the binary image, so the result of this
script should be regarded as a baseline.

# License

SPDX-Identifier: GPL-3.0-only
