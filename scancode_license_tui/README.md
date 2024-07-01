# Scancode license TUI

This is a (work in progress) text user interface (TUI) for processing results
of [ScanCode][scancode]. It is written in Python and based on [Rich][rich]. It
can display results of recent versions of ScanCode, there is no backward
compatibility mode.

This is not meant as a full replacement for other tools processing ScanCode
results, but as a quick inspection tool.

## Using the tool

First you need to make sure you have the dependencies installed, see
`requirements.txt` (or `shell.nix` for those using Nix). The dependencies
are modest.

After running ScanCode simply supply the path of the JSON result file:

```
$ python scancode_license_tui.py -j /path/to/result/json
```

for example if the result is found in a file `/tmp/busybox.json`:

```
$ python scancode_license_tui.py -j /tmp/busybox.json
```

To display only results that ScanCode found use the `--results-only` flag:

```
$ python scancode_license_tui.py -j /path/to/result/json --results-only
```

Quiting the tool: CTRL-q

[scancode]:https://github.com/nexB/scancode-toolkit
[rich]:https://github.com/Textualize/rich
