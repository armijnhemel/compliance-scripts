This directory has scripts to create linking graphs for ELF files

# Requirements

* Python3
* Neo4J (tested with 3.3.2 community edition)
* pyelftools (tested with python3-pyelftools-0.22-0.11.git20130619.a1d9681.fc26.noarch)

# Usage

1. start and configure Neo4J (out of scope of this document)
2. unpack a root file system of a firmware into a directory (example: /tmp/rootfs)
3. adapt the configuration file to change the directory where Cypher files will be stored
4. run the script: `python3 generatecypher.py -c /path/to/config -d /path/to/directory`
5. load the resulting Cypher file into Neo4J

# License

Licensed under the terms of the General Public License version 3

SPDX-License-Identifier: GPL-3.0-only

Copyright 2018 - Armijn Hemel
