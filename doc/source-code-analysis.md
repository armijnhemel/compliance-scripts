This file documents the steps typically needed to find common issues in source code releases.

1. unpack all of the source code: source code in archives typically comes in archives, like ZIP files, or tar balls. To do a full analysis these should first be unpacked, otherwise it might be easy to miss things. This can be done manually, or with a few simple scripts that recursively unpack these archives.

2. determine the type of every file: in a source code archive there are certain things that should be treated as suspicious, for example executable files, such as ELF files or bFLT files, as these might indicate that source code is missing. A command with which to fairly efficiently find out the type of files is:

    $ find -print0 | xargs --null file

This is not fool proof, as it relies on the "file" command being correct, which it very often is, but not always. Suspicious patterns to look for:

* ELF files - binary files that were compiled. These could indicate that source code is missing, although it is also very possible that simply all build artifacts from a build were included. This is fairly easy to find out. Of course, it might be that the code was licensed under a license that does not require disclosure of source code.
* bFLT files - similar to ELF files, but for MMU-less systems. These are much more rare.
* Java .class files - similar to ELF files, but then for Java.
* CPIO archives - these can contain more binaries
* U-Boot images - these often contain a Linux kernel, sometimes also file systems or CPIO archives
* various file systems (ext2, ubi/ubifs, jffs2, etc.) - file systems that can contain binaries
* compressed files - these could contain interesting information as well

What to ignore:

* directories
* text files (for now)
* device files
* sockets
* pipes

Interesting file patterns/names

* vmlinux/vmlinuz and variants - these typically contain a Linux kernel image
* ramdisk - could be an initial file system
* rootfs - could indicate a root file system
* .img - this extension is frequently used for certain Android images

and so on.

3. for known open source code download the vanilla source code from the offical release site and do a recursive diff: comparing the source code to vanilla source code allows you to quickly zoom in on changes that were made.
