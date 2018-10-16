This directory has scripts to create linking graphs for ELF files

# Requirements

* Python3
* Neo4J (tested with 3.4.9 community edition)
* pyelftools (tested with python3-pyelftools-0.24-1.fc28.noarch)

# Getting Neo4J

Get the community edition at:

https://neo4j.com/download-center/

Since Neo4J tends to shuffle these download links around every once in a while
it might not be accurate at some point in time.

# Usage

1. start and configure Neo4J (out of scope of this document)
2. unpack a root file system of a firmware into a directory (example: /tmp/rootfs)
3. adapt the configuration file to change the directory where Cypher files will be stored
4. run the script: `python3 generatecypher.py -c /path/to/config -d /path/to/directory`
5. load the resulting Cypher file into Neo4J

# Example

(picture for this example can be found in the directory "pics")

This script can be used to generate graphs after unpacking a firmware with
BANG. For example:

    $ python3 generatecypher.py -c graph.config -d ~/tmp/bang-scan-gpiy5nb2/unpack/TEW-636APB-1002.bin-squashfs-1/

Afterwards load the graph into Neo4J (figure 1) and then run the loaded graph
by "playing" the script.

It might be that Neo4J barfs saying that there is a StackOverflowError and
suggests to increase the size of the stack. As there will likely be quite a
few nodes and edges it is advised to increase the stack a bit more than the
suggested 2M, and set it to 200M or so:

    dbms.jvm.additional=-Xss200M

By default only 25 nodes are shown, using this query:

    MATCH (n:ELF) RETURN n LIMIT 25

To change this to show for example all nodes use this query instead:

    MATCH (n:ELF) RETURN n

# License

Licensed under the terms of the General Public License version 3

SPDX-License-Identifier: GPL-3.0-only

Copyright 2018 - Armijn Hemel
