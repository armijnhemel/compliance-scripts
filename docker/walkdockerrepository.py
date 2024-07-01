#!/usr/bin/python3

# Copyright 2018 Armijn Hemel for Tjaldur Software Governance Solutions
# SPDX-License-Identifier: GPL-3.0

# This scripts processes a Docker data structure and pretty prints some
# statistics about it.

import sys
import os
import json
import argparse
import pathlib
import base64
import binascii
import gzip
import collections


def main(argv):
    parser = argparse.ArgumentParser()

    # the following options are provided on the commandline
    parser.add_argument("-d", "--directory", action="store",
                        dest="dockerdirectory",
                        help="top level Docker directory", metavar="DIR")

    # allow optional image to be passed as parameter
    parser.add_argument("-i", "--image", action="store",
                        dest="dockerimage",
                        help="Docker image to report on (optional)", metavar="LAYER")

    args = parser.parse_args()

    if args.dockerdirectory is None:
        parser.error("Path top Docker directory missing")

    # sanity checks for the Docker directory
    dockerdir = pathlib.Path(args.dockerdirectory)
    if not dockerdir.exists():
        print("Path '%s' does not exist" % dockerdir, file=sys.stderr)
        sys.exit(1)
    if not dockerdir.is_dir():
        print("Path '%s' is not a directory" % dockerdir, file=sys.stderr)
        sys.exit(1)

    # check to see if the top level directory has the right structure
    repositoriesfilename = dockerdir / "image" / "overlay2" / "repositories.json"
    try:
        if not repositoriesfilename.exists():
            print("Path '%s' does not exist" % repositoriesfilename, file=sys.stderr)
            sys.exit(1)
        if not repositoriesfilename.is_file():
            print("Path '%s' is not a regular file" % repositoriesfilename, file=sys.stderr)
            sys.exit(1)
    except PermissionError:
        print("Cannot access '%s' (permission denied)" % repositoriesfilename, file=sys.stderr)
        sys.exit(1)

    # read the JSON
    jsonfile = open(repositoriesfilename, 'r')
    try:
        repositoriesjson = json.load(jsonfile)
        jsonfile.close()
    except:
        jsonfile.close()
        print("Cannot open '%s' as JSON" % repositoriesfilename, file=sys.stderr)
        sys.exit(1)

    # verify the JSON contents
    if 'Repositories' not in repositoriesjson:
        print("JSON element 'Repositories' missing in %s" % repositoriesfilename, file=sys.stderr)
        sys.exit(1)

    # store top level identifiers
    repositoriestoimages = {}
    imagestorepositories = {}

    for i in repositoriesjson['Repositories']:
        tagvalueseen = set()
        for r in repositoriesjson['Repositories'][i]:
            if args.dockerimage != None:
                if r != args.dockerimage:
                    continue
            tagvalue = repositoriesjson['Repositories'][i][r]
            if not tagvalue.startswith('sha256:'):
                continue
            tagvalue = tagvalue.split(':', 1)[1]
            repositoriestoimages[r] = tagvalue
            if not tagvalue in imagestorepositories:
                imagestorepositories[tagvalue] = []
            imagestorepositories[tagvalue].append(r)

    # now extract meta information for the layers of each image
    imagetolayers = {}
    for r in repositoriestoimages:
        imagejsonfilename = dockerdir / "image" / "overlay2" / "imagedb" / "content" / "sha256" / repositoriestoimages[r]
        if not imagejsonfilename.exists():
            print("Path '%s' does not exist" % imagejsonfilename, file=sys.stderr)
            sys.exit(1)
        if not imagejsonfilename.is_file():
            print("Path '%s' is not a regular file" % imagejsonfilename, file=sys.stderr)
            sys.exit(1)
        # read the JSON
        jsonfile = open(imagejsonfilename, 'r')
        try:
            imagejson = json.load(jsonfile)
            jsonfile.close()
        except:
            jsonfile.close()
            print("Cannot open '%s' as JSON" % imagejsonfilename, file=sys.stderr)
            continue
        if 'rootfs' not in imagejson:
            print("JSON element 'rootfs' not in '%s'" % imagejsonfilename, file=sys.stderr)
            continue
        if 'type' not in imagejson['rootfs']:
            print("JSON element 'type' not in '%s'" % imagejsonfilename, file=sys.stderr)
            continue
        if imagejson['rootfs']['type'] != 'layers':
            continue
        if 'diff_ids' not in imagejson['rootfs']:
            print("JSON element 'diff_ids' not in '%s'" % imagejsonfilename, file=sys.stderr)
            continue
        imagetolayers[r] = list(map(lambda x: x.split(':', 1)[1], imagejson['rootfs']['diff_ids']))

    # see if any images share layers
    intersections = []
    for l in imagetolayers:
        for ll in imagetolayers:
            if l == ll:
                continue
            intersection = set(imagetolayers[l]).intersection(set(imagetolayers[ll]))
            if intersection != set():
                if intersection == set(imagetolayers[l]) and intersection == set(imagetolayers[ll]):
                    continue
                intersections.append((l, ll, intersection))

    if len(intersections) != 0:
        print("SHARED LAYERS:")
        print("--------------")
        for i in intersections:
            print("Image %s and %s share:" % (i[0], i[1]), i[2])

    # optional
    layertometainformation = {}
    for l in imagetolayers:
        for ll in imagetolayers[l]:
            metajsonfilename = dockerdir / "image" / "overlay2" / "distribution" / "v2metadata-by-diffid" / "sha256" / ll
            if not metajsonfilename.exists():
                continue
            if not metajsonfilename.is_file():
                print("Path '%s' is not a regular file" % metajsonfilename, file=sys.stderr)
                sys.exit(1)
            try:
                metafile = open(metajsonfilename, 'r')
                metacontents = metafile.read()
                metafile.close()
                metainfo = json.loads(metacontents)
                if len(metainfo) != 0:
                    if ll not in layertometainformation:
                        layertometainformation[ll] = []
                    for m in metainfo:
                        if 'SourceRepository' not in m:
                            continue
                        layertometainformation[ll].append(m['SourceRepository'])
            except:
                continue

    layeridtolayerdir = {}
    layerdirtolayerid = {}
    layertoparent = {}
    parenttolayer = {}
    layertocacheid = {}
    cacheidtolayer = {}

    layerdir = dockerdir / "image" / "overlay2" / "layerdb" / "sha256"

    # first find out the mapping of layer ids to layer directories
    for l in layerdir.iterdir():
        if not l.is_dir():
            continue
        # first read 'diff'
        diffname = dockerdir / "image" / "overlay2" / "layerdb" / "sha256" / l.name / 'diff'
        if not diffname.exists():
            continue
        try:
            difffile = open(diffname, 'r')
            diffcontents = difffile.read()
            diffid = diffcontents.split(':', 1)[1]
            difffile.close()
        except:
            continue
        layeridtolayerdir[diffid] = l.name
        layerdirtolayerid[l.name] = diffid

    # read 'parent'
    for l in layerdir.iterdir():
        if not l.is_dir():
            continue
        # first read 'diff'
        diffname = dockerdir / "image" / "overlay2" / "layerdb" / "sha256" / l.name / 'diff'
        if not diffname.exists():
            continue
        try:
            difffile = open(diffname, 'r')
            diffcontents = difffile.read()
            diffid = diffcontents.split(':', 1)[1]
            difffile.close()
        except:
            continue

        parentname = dockerdir / "image" / "overlay2" / "layerdb" / "sha256" / l.name / 'parent'
        if not parentname.exists():
            layertoparent[diffid] = None
            continue
        try:
            parentfile = open(parentname, 'r')
            parentcontents = parentfile.read()
            parentid = parentcontents.split(':', 1)[1]
            parentfile.close()
        except:
            continue
        if parentid not in layerdirtolayerid:
            # something is really wrong here
            continue
        layertoparent[diffid] = layerdirtolayerid[parentid]
        parenttolayer[layerdirtolayerid[parentid]] = diffid

    # store the tar meta data
    layertotarmeta = {}

    # read 'cache id' and tar-split.json.gz
    for l in layerdir.iterdir():
        if not l.is_dir():
            continue
        # first read 'diff'
        diffname = dockerdir / "image" / "overlay2" / "layerdb" / "sha256" / l.name / 'diff'
        if not diffname.exists():
            continue
        try:
            difffile = open(diffname, 'r')
            diffcontents = difffile.read()
            diffid = diffcontents.split(':', 1)[1]
            difffile.close()
        except:
            continue

        cacheidname = dockerdir / "image" / "overlay2" / "layerdb" / "sha256" / l.name / 'cache-id'
        if not cacheidname.exists():
            continue
        try:
            cachefile = open(cacheidname, 'r')
            cacheid = cachefile.read()
            cachefile.close()
        except:
            continue
        layertocacheid[diffid] = cacheid
        cacheidtolayer[cacheid] = diffid

        # tar-split.json.gz is a gzip compressed file and
        # each line is a separate JSON data structure
        tarsplitname = dockerdir / "image" / "overlay2" / "layerdb" / "sha256" / l.name / 'tar-split.json.gz'
        if not tarsplitname.exists():
            continue
        try:
            if diffid not in layertotarmeta:
                layertotarmeta[diffid] = []
            tarsplitfile = gzip.open(tarsplitname, 'r')
            for ll in tarsplitfile:
                tarjson = json.loads(ll)

                # first some sanity checks to see if the JSON is actually
                # valid Docker JSON
                if 'position' not in tarjson:
                    continue
                if 'type' not in tarjson:
                    continue
                if 'payload' not in tarjson:
                    continue

                # then process the JSON
                if tarjson['type'] == 1:
                    if 'name' not in tarjson:
                        continue
                elif 'type' == 2:
                    pass
                else:
                    continue
                if tarjson['payload'] is not None:
                    try:
                        layerbase64 = base64.b64decode(tarjson['payload'])
                    except binascii.Error as e:
                        continue
                    except TypeError as e:
                        continue
                    if tarjson['type'] == 1:
                        layertotarmeta[diffid].append(tarjson['name'])
                else:
                    # directory
                    if tarjson['type'] == 1:
                        pass
                        #layertotarmeta[diffid].append(tarjson['name'])
            tarsplitfile.close()
        except Exception as e:
            continue

    # determine the top layer for each image
    imagetoplayers = {}
    for l in imagetolayers:
        toplayerfound = False
        for p in imagetolayers[l]:
            if p not in parenttolayer:
                imagetoplayers[l] = p
                toplayerfound = True
                break
        if not toplayerfound:
            # TODO: figure out what to do with this
            pass

    for l in imagetoplayers:
        p = imagetoplayers[l]
        parent = layertoparent[p]
        print("LAYER STACK FOR:", l)
        print((17+len(l))*"-")
        print()
        imagestack = collections.deque()
        imagestack.appendleft(p)
        if p in layertometainformation:
            print(p, 'from:', ''.join(set(layertometainformation[p])))
            #print(dockerdir / 'overlay2' / layertocacheid[p], 'from:', ''.join(set(layertometainformation[p])))
        else:
            print(p)
            #print(dockerdir / 'overlay2' / layertocacheid[p])
        while parent is not None:
            imagestack.appendleft(parent)
            print("-->")
            if parent in layertometainformation:
                print(parent, 'from:', ''.join(set(layertometainformation[p])))
                #print(dockerdir / 'overlay2' / layertocacheid[parent], 'from:', ''.join(set(layertometainformation[parent])))
            else:
                print(parent)
                #print(dockerdir / 'overlay2' / layertocacheid[parent])
            parent = layertoparent[parent]
        print(64*"-")
        print()

        # print which new paths are introduced in each layer
        filesseen = set()
        for p in imagestack:
            newfiles = set(layertotarmeta[p]).difference(filesseen)
            if len(newfiles) == 1:
                print("Layer %s introduced 1 new path" % p)
                #for f in newfiles:
                #    print("*", f)
                #print()
            else:
                print("Layer %s introduced %d new paths" % (p, len(newfiles)))
                #for f in sorted(newfiles):
                #    print("*", f)
                #print()
            filesseen.update(layertotarmeta[p])
        print()

        # for each layer print the first layer that introduce
        # changes to files, plus to which files
        while True:
            try:
                p = imagestack.popleft()
                filesseen = set(layertotarmeta[p])
                alreadychanged = set()
                for pp in imagestack:
                    layerintersection = filesseen.intersection(set(layertotarmeta[pp]))
                    if len(layerintersection) != 0:
                        # only report the files that are first changes
                        newlychanged = filesseen.intersection(layerintersection).difference(alreadychanged)
                        if len(newlychanged) != 0:
                            print("Files from %s changed in %s:" % (p, pp))
                            for f in sorted(newlychanged):
                                print("*", f)
                            print()
                        alreadychanged.update(layerintersection)
            except Exception as e:
                break


if __name__ == "__main__":
    main(sys.argv)
