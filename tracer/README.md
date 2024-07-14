# Trace file processor

When trying to reason about C/C++ ELF binaries on Linux (for example: which
license(s) the binary should be released under, or if there are any security
issues) there are a few paths that can be taken. The first path (which is used
in for example [BANG][bang]) is to use fingerprinting to try to reconstruct
what is used in a binary. This works reasonalby well when the binary is a black
box and there is no source code that can be rebuilt available. It is not
necessarily a good method as fingerprinting relies on identifiable information
being available in a binary, such as function names or strings, which isn't
always the case (example: statically linked binaries, where no strings were
used), but if there is no source code available it gives an mostly accurate
result. If there is source code that can be rebuilt available, then the second
path, build tracing, is much better, as it exactly keeps track of which files
were used to create individual binaries. This enables a user to zoom in on only
the files that were actually used in building a binary.

Some background information can be found in the following two papers:

* http://www.st.ewi.tudelft.nl/~sander/pdf/publications/TUD-SERG-2012-010.pdf
* http://rebels.ece.mcgill.ca/confpaper/2014/09/14/tracing-software-build-processes-to-uncover-license-compliance-inconsistencies.html

## Usage

Example: Linux kernel

First trace a Linux kernel build with (for example) the following command:

```console
strace -o ../linux-strace -e trace=%file,%process,dup,dup2,dup3,close,pipe,tee,fchdir -y -Y -qq -f --seccomp-bpf -s 256 make
```

(TODO: is `close()` really needed?)

and then run this script on the output.

Alternatively, to save diskspace for the trace file (sometimes up to 50%), use:

```console
$ strace -o ../linux-strace -e trace=chdir,getcwd,link,linkat,mkdir,open,openat,rename,renameat2,sendfile,symlink,symlinkat,unlink,unlinkat,%process,dup,dup2,dup3,close,pipe,tee,fchdir -y -Y -qq -f --seccomp-bpf -s 256 make
```

The following syscalls (from `%file`) can be ignored:

* `access`
* `chmod`
* `faccessat2`
* `fchmodat`
* `newfstatat`
* `readlink`
* `statfs`
* `utimensat`

The following syscalls (from %file) can possibly be ignored:

* `mkdir`
* `unlink`
* `unlinkat`

TODO: There are probably more calls that need to be added
* `fcntl`
* `sendfile64`

TODO: what to do with writes to files? There are sometimes zero sized files
that are merely touched, but no content is written to them. Should write
calls such as `write()` also be tracked?

Make sure there is enough disk space available, as trace files for the
Linux kernel tend to be quite big.

[bang]:https://github.com/armijnhemel/binaryanalysis-ng/
