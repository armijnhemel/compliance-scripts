# Binary comparison script for ELF files

This directory contains a script to compare ELF files two directories. It works
by first computing hashes (SHA256) for binaries having the same subpath and if
the binaries are not identical running `strings` on the binaries, and creating
a unified diff and writing to a file.

## Why?

A task in GPL compliance engineering is to check if supplied source code is
"complete and corresponding". The most effective way to verify this is by doing
a rebuild of the source code and then comparing the rebuilt binaries to the
original binaries for which the source code is for (for example, the binaries
found inside a router firmware file).

If the binaries are identical, then the source code is complete. This can be
easily verified by computing a cryptographic hash value for the binaries, for
example a SHA256. Many binaries cannot be rebuilt exactly due to time stamps,
paths of files, or other information that can change, having been included in
the binaries. A common method to verify if the binaries are equivalent is to
extract human readables strings from each of the binaries and comparing the
string outputs for obvious differences.

If the differences are small and mainly limited to information known to change
(time stamps, paths, etc.) then it is enough to say they are equivalent.

As an example let's take BusyBox, which can often be found inside devices and
which always includes a time stamp.

After running `strings` on the two binaries a unified diff can be made using the
command `diff -u`. The result should look similar to this:

```
--- a/bin/busybox
+++ b/bin/busybox
@@ -4896,7 +4896,7 @@
 either all or none of the filesystem types passed to -t must be prefixed with 'no' or '!'
 FSCK_FORCE_ALL_PARALLEL
 FSCK_MAX_INST
-fsck (busybox 1.23.2, 2023-12-11 19:45:55 CST)
+fsck (busybox 1.23.2, 2024-06-27 13:53:09 CEST)
 FSTAB_FILE
 Checking all filesystems
 /dev/md
@@ -5045,7 +5045,7 @@
 ignorecase 
 showmatch 
 tabstop=
-1.23.2 2023-12-11 19:45:55 CST
+1.23.2 2024-06-27 13:53:09 CEST
 '%s' is read only
 '%s' %dL, %dC
 yank
@@ -5270,7 +5270,7 @@
 getcwd
 bad regex '%s': %s
 invalid argument '%s' to '%s'
-BusyBox v1.23.2 (2023-12-11 19:45:55 CST)
+BusyBox v1.23.2 (2024-06-27 13:53:09 CEST)
 you must be root
 0123456789ABCDEF
 /var/log/wtmp
```

As can be seen the differences are fairly small. Big deletions or additions are
typically a sign of the build not being complete and corresponding. Some
caveats apply:

* not building in the exact environment can cause changes: if the generated
  code is different (for example: different toolchain or different settings)
  then these differences might show up as big blocks, even though the source
  code is complete and corresponding (but the environment which isn't
  necessarly part of the complete and corresponding source code isn't)
* sometimes strings will have been reordered, even when building in the same
  (almost identical) environment. To check for equivalence you can check if
  the additions and deletions match.

## Automating generating diffs

In firmware files there can easily be a few hundred binaries that need to be
matched. This is a task that can be completely automated, and that's what the
script `binary_strings_compare.py` does.

Dependencies are modest: `click` and `kaitaistruct` (Python modules) and
`binutils` (for `strings`) are all that's needed.

Parameters to the script are:

1. a first directory potentially containing ELF files
2. a second directory potentially containing ELF files
3. an empty directory for writing unified diffs to

It is important that the first and second directory have the same directory
structure, as the script relies on the (relative) paths being identical.

For each real file (symbolic links are ignored) the file is opened to verify if
the first 4 bytes contain the ELF magic. Then a SHA256 checksum is computed.
For each file that can be found in both directories the checksums are compared.
If the checksums are not identical then depending on the options provided either
one of two things is done:

* the `strings` command is run on the entire "raw" binary (`--raw`, default)
* the `strings` command is run on only the `.rodata` section (`--no-raw`)

Then a unified diff of the results is computed, and the output is written to the
same (relative) path as the original file, but then in the directory for the
unified diffs. The number of context lines is hardcoded to `0`, but can be
easily changed. If only the `.rodata` section is looked at it is recommended
to also use the `--sort` option which sorts and deduplicates the extracted
strings.

So for example if both directories contain the (relative) path `./bin/busybox`
with a copy of BusyBox, then the difference will be written to `./bin/busybox`
in the diff directory.

The program can be invoked as follows:

```console
$ python binary_strings_compare.py -f /path/to/first/directory -s /path/to/second/directory -d /path/to/diff/directory
```

Optionally the `--verbose` flag can be set to output some statistics, about
which files can only be found in the first or second directory, and so on.
