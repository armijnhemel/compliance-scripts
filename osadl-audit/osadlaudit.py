#!/usr/bin/env python3

# Copyright 2012-2019 Armijn Hemel for Tjaldur Software Governance Solutions
# Licensed under the terms of the GNU General Public License version 3
# SPDX-License-Identifier: GPL-3.0-only
# Licensed under GPL version 3, see LICENSE file for details

'''
This program was originally written for the OSADL License Compliance Audit:

https://lca.osadl.org/

This program checks source code archives to see where they differ from upstream
and optionally performs a license scan using ScanCode and FOSSology.

If configured it will also compute distances using TLSH to find the closest
file in the database (filename based).
'''

import os
import os.path
import sys
import hashlib
import subprocess
import stat
import tempfile
import psycopg2
import json
import magic
import configparser
import argparse
import multiprocessing
import queue

havetlsh = False
try:
    import tlsh
    havetlsh = True
except:
    pass


# compute TLSH and return the most promising hits in the database
def scantlsh(scanqueue, reportqueue, cursor, conn, tlshcutoff):
    while True:
        # first get the data for a file for which a close match
        # needs to be compute.
        (directory, filename, sha256) = scanqueue.get()

        # then compute the TLSH hash and search in the database
        # for the closest files.
        tlshfile = open(os.path.join(directory, filename), 'rb')
        tlshdata = tlshfile.read()
        tlshfile.close()
        tlshhash = tlsh.hash(tlshdata)

        if tlshhash == '':
            # file is either too small or a hash cannot be
            # computed (example: all characters are the same)
            scanqueue.task_done()
            continue

        # now get checksums for files with the exact same name
        cursor.execute("select distinct checksum from fileinfo where filename=%s", (filename,))
        candidates = cursor.fetchall()
        conn.commit()
        if len(candidates) == 0:
            scanqueue.task_done()
            continue

        # keep the most promising files in a list
        mostpromising = []

        # first set the value for the found hash very high
        minhash = sys.maxsize

        for candidate in candidates:
            # first grab the TLSH value from the database
            cursor.execute("select tlsh from hashes where sha256=%s", candidate)
            tlshresult = cursor.fetchone()
            if tlshresult is None:
                continue

            # compute the difference with the TLSH value computed above
            # if the distance is smaller than the distance of the current
            # best hit, then this will be the new best hit. If it is the
            # same it is added to the list of best matches.
            tlshdiff = tlsh.diff(tlshhash, tlshresult[0])
            if tlshdiff < minhash:
                minhash = tlshdiff
                mostpromising = [candidate[0]]
            elif tlshdiff == minhash:
                mostpromising.append(candidate[0])

        # if there are promising files and they aren't below a
        # specific TLSH threshold return the information associated
        # with these files.
        if mostpromising != []:
            if minhash < tlshcutoff:
                candidates = []
                for m in mostpromising:
                    cursor.execute("select packagename, version, fullfilename from fileinfo where checksum=%s", (m,))
                    candidates += cursor.fetchall()
                    conn.commit()
                reportqueue.put((directory, filename, candidates, minhash))
        scanqueue.task_done()


# run Scancode and FOSSology scans here
def runlicensescanner(scanqueue, reportqueue, scancodepath, nomossapath):
    while True:
        (filedir, filename, filehash) = scanqueue.get()
        scancoderes = set()
        fossologyres = set()

        # Run Scancode, needs fea65d35a475553368db17a1d196e61a92974a74 or later
        p = subprocess.Popen([scancodepath, '-lceu', '--quiet', '--json-pp', '-', os.path.join(filedir, filename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        (stanout, stanerr) = p.communicate()
        scancodejson = json.loads(stanout)
        for f in scancodejson['files']:
            if 'licenses' in f:
                for l in f['licenses']:
                    if 'spdx_license_key' in l:
                        scancoderes.add(l['spdx_license_key'])

        # Also run the stand alone Nomos scanner from FOSSology.
        # This requires FOSSology 2.4 or later.
        p = subprocess.Popen([nomossapath, os.path.join(filedir, filename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        (stanout, stanerr) = p.communicate()
        stanout = stanout.decode('utf-8')
        fosslines = stanout.strip().split('\n')
        for j in range(0, len(fosslines)):
            fossysplit = fosslines[j].strip().rsplit(" ", 1)
            licenses = fossysplit[-1].split(',')
            fossologyres.update(licenses)
        reportqueue.put((filedir, filename, filehash, scancoderes, fossologyres))
        scanqueue.task_done()


# scan the files to find the files that cannot be found in the database
def scanfiles(scanqueue, reportqueue, cursor, conn):
    while True:
        (directory, filename) = scanqueue.get()
        scanfile = open(os.path.join(directory, filename), 'rb')
        h = hashlib.new('sha256')
        h.update(scanfile.read())
        scanfile.close()
        filehash = h.hexdigest()
        cursor.execute('select * from fileinfo where checksum=%s LIMIT 1', (filehash,))
        res = cursor.fetchall()
        conn.commit()
        if res == []:
            reportqueue.put((directory, filename, filehash))
        scanqueue.task_done()


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
    parser.add_argument("-s", "--directory", action="store", dest="scandir", help="path to top level directory to scan", metavar="DIR")
    args = parser.parse_args()

    # first some sanity checks for the commandline arguments
    if args.scandir is None:
        parser.error("Need top level directory to scan")
    if args.cfg is None:
        parser.error("Need configuration file")

    if not os.path.exists(args.scandir):
        print("Scan directory does not exist", file=sys.stderr)
        exit(1)
    if not os.path.exists(args.cfg):
        print("Configuration file does not exist", file=sys.stderr)
        exit(1)

    # sanity checks for the configuration file
    configfile = open(args.cfg, 'r')
    config = configparser.ConfigParser()
    try:
        config.readfp(configfile)
    except Exception:
        configfile.close()
        sys.exit(1)

    # set a few default values
    scanlicense = False
    verbose = False
    postgresql_host = None
    postgresql_port = None
    extensions = []
    tlshscan = False

    # process the configuration file
    for section in config.sections():
        if section == "global":
            continue
        if section == "database":
            try:
                postgresql_user = config.get(section, 'postgresql_user')
                postgresql_password = config.get(section, 'postgresql_password')
                postgresql_db = config.get(section, 'postgresql_db')
            except:
                print("Configuration file malformed: missing database information", file=sys.stderr)
                configfile.close()
                sys.exit(1)
            try:
                postgresql_host = config.get(section, 'postgresql_host')
            except:
                pass
            try:
                postgresql_port = config.get(section, 'postgresql_port')
            except:
                pass
        if section == "audit":
            try:
                verboseconf = config.get(section, 'verbose')
                if verboseconf == 'yes':
                    verbose = True
            except:
                pass
            try:
                scanlicenseconf = config.get(section, 'scanlicense').strip()
                if scanlicenseconf == 'yes':
                    scanlicense = True
            except:
                pass
            try:
                extensions = list(map(lambda x: x.strip(), config.get(section, 'extensions').strip().split(':')))
            except:
                pass
            try:
                if havetlsh:
                    usetlsh = config.get(section, 'usetlsh').strip()
                    if usetlsh != 'yes':
                        tlshscan = False
                    else:
                        tlshscan = True
            except:
                pass
            try:
                tlshcutoff = int(config.get(section, 'tlshcutoff').strip())
            except:
                tlshcutoff = 200
            try:
                nomossapath = config.get(section, 'nomossapath')
                # check if nomossa exists
                if not os.path.exists(nomossapath):
                    nomossapath = None
            except:
                nomossapath = None
            try:
                scancodepath = config.get(section, 'scancodepath')
                # check if scancode exists
                if not os.path.exists(scancodepath):
                    scancodepath = None
            except:
                scancodepath = None
            try:
                processors = min(int(config.get(section, 'processors')), multiprocessing.cpu_count())
            except:
                processors = multiprocessing.cpu_count()
    configfile.close()

    if scanlicense:
        if nomossapath is None:
            print("WARNING: License scanning enabled but no valid path for Nomos declared!!\n", file=sys.stderr)
            scanlicense = False
        if scancodepath is None:
            print("WARNING: License scanning enabled but no valid path for ScanCode declared!!\n", file=sys.stderr)
            scanlicense = False

    # sanity checks for the database
    try:
        c = psycopg2.connect(database=postgresql_db, user=postgresql_user, password=postgresql_password, port=postgresql_port, host=postgresql_host)
        c.close()
    except:
        print("Database server not running or malconfigured, exiting.", file=sys.stderr)
        sys.exit(1)

    filestoscan = set()

    # keep track of which files cannot be found at all in the database
    notfoundfiles = []

    # keep track of any other smells in the source archive
    smells = {}

    dirwalk = os.walk(args.scandir, topdown=True)
    skiplist = set()
    for direntry in dirwalk:
        if direntry[0] in skiplist:
            print("skipping", direntry[0], skiplist)
            continue
        for dirname in direntry[1]:
            # make sure all directories can be accessed
            if not os.path.islink("%s/%s" % (direntry[0], dirname)):
                os.chmod("%s/%s" % (direntry[0], dirname), stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            # then search for smells
            if dirname == '.svn':
                if 'svn' in smells:
                    smells['svn'].add(os.path.normpath("%s/.svn" % direntry[0]))
                else:
                    smells['svn'] = set([os.path.normpath("%s/.svn" % direntry[0])])
                skiplist.add(os.path.normpath("%s/.svn" % direntry[0]))
                direntry[1].remove('.svn')
        for filename in direntry[2]:
            if filename == '.gitignore':
                continue

            # only look at files with certain extensions if configured
            if extensions != []:
                ignorefile = True
                for e in extensions:
                    if filename.endswith(e):
                        ignorefile = False
                        break
                if ignorefile:
                    continue

            # make sure all files can be accessed
            try:
                if not os.path.islink("%s/%s" % (direntry[0], filename)):
                    os.chmod("%s/%s" % (direntry[0], filename), stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            except Exception:
                #print e
                pass
            if os.path.islink("%s/%s" % (direntry[0], filename)):
                continue
            if os.stat("%s/%s" % (direntry[0], filename)).st_size == 0:
                continue
            # then do a few more sanity checks for smells, such as
            # * vim swap files
            # * binary files
            # * .gitignore files
            if filename.startswith('.') and filename.endswith('.swp'):
                datafile = open(filename, 'rb')
                databuffer = datafile.read(6)
                datafile.close()
                if databuffer == 'b0VIM\x20':
                    if 'vim' in smells:
                        smells['vim'].append("%s/%s" % (direntry[0], filename))
                    else:
                        smells['vim'] = ["%s/%s" % (direntry[0], filename)]
                continue
            filestoscan.add((direntry[0], filename))

    if verbose:
        print("SCANNING %d files" % len(filestoscan))
        sys.stdout.flush()

    # keep a list of postgresql connections and cursors,
    # for use in separate threads
    postgresql_conns = []
    postgresql_cursors = []

    # create a bunch of PostgreSQL connections and cursors
    for i in range(0, processors):
        c = psycopg2.connect(database=postgresql_db, user=postgresql_user, password=postgresql_password, port=postgresql_port, host=postgresql_host)
        cursor = c.cursor()
        postgresql_conns.append(c)
        postgresql_cursors.append(cursor)

    scanmanager = multiprocessing.Manager()
    scanqueue = scanmanager.JoinableQueue(maxsize=0)
    reportqueue = scanmanager.JoinableQueue(maxsize=0)
    processes = []

    # add the files to scan to the scan queue
    for i in filestoscan:
        scanqueue.put(i)

    # create a number of processes to scan files
    for i in range(0, processors):
        p = multiprocessing.Process(target=scanfiles, args=(scanqueue, reportqueue, postgresql_cursors[i], postgresql_conns[i]))
        processes.append(p)

    for p in processes:
        p.start()

    scanqueue.join()

    notfoundfiles = []

    while True:
        try:
            notfoundfiles.append(reportqueue.get_nowait())
            reportqueue.task_done()
        except queue.Empty:
            # Queue is empty
            break

    reportqueue.join()

    # terminate the processes
    for p in processes:
        p.terminate()

    if verbose:
        print("%d FILES NOT FOUND IN DATABASE" % len(notfoundfiles))
        sys.stdout.flush()

    # If tlsh is enabled then try to find out what
    # the closest match for the file could be
    totaltlshscore = 0
    if tlshscan:
        if verbose:
            print("COMPUTING AND COMPARING TLSH OF FILES NOT FOUND IN DATABASE\n")
            sys.stdout.flush()

        # create new queues
        scanqueue = scanmanager.JoinableQueue(maxsize=0)
        reportqueue = scanmanager.JoinableQueue(maxsize=0)
        processes = []

        for i in notfoundfiles:
            # filehash, filedir, filename
            scanqueue.put(i)

        # create a number of processes to scan files
        for i in range(0, processors):
            p = multiprocessing.Process(target=scantlsh, args=(scanqueue, reportqueue, postgresql_cursors[i], postgresql_conns[i], tlshcutoff))
            processes.append(p)

        for p in processes:
            p.start()

        scanqueue.join()

        while True:
            try:
                tlshresult = reportqueue.get_nowait()
                print("CLOSEST %d CANDIDATES FOR FILE %s WITH DISTANCE %d:" % (len(tlshresult[2]), os.path.join(tlshresult[0], tlshresult[1]), tlshresult[3]))
                for candidate in tlshresult[2]:
                    print("\tPACKAGE %s, VERSION %s, FILE %s" % candidate)
                print()
                reportqueue.task_done()
            except queue.Empty:
                # Queue is empty
                break

        reportqueue.join()

        # terminate the processes
        for p in processes:
            p.terminate()

    if scanlicense:
        if verbose:
            print("DETERMINING LICENSE OF FILES NOT FOUND")
            sys.stdout.flush()

        # create new queues....again
        scanqueue = scanmanager.JoinableQueue(maxsize=0)
        reportqueue = scanmanager.JoinableQueue(maxsize=0)
        processes = []

        for i in notfoundfiles:
            # filehash, filedir, filename
            scanqueue.put(i)

        # create a number of processes to scan files
        for i in range(0, processors):
            p = multiprocessing.Process(target=runlicensescanner, args=(scanqueue, reportqueue, scancodepath, nomossapath))
            processes.append(p)

        for p in processes:
            p.start()

        scanqueue.join()
        notfoundfiles = []
        while True:
            try:
                scanresult = reportqueue.get_nowait()
                notfoundfiles.append(scanresult)
                reportqueue.task_done()
            except queue.Empty:
                # Queue is empty
                break

        reportqueue.join()

        # terminate the processes
        for p in processes:
            p.terminate()
    else:
        notfoundfiles = map(lambda x: x + ([], []), notfoundfiles)

    if verbose:
        if smells != {}:
            print("Smells found:\n")
            for i in smells:
                if i == 'vim':
                    print("* Vim swap files found:")
                    for s in smells[i]:
                        print("  -", s)
                if i == 'svn':
                    print("* Subversion directories found:")
                    for s in smells[i]:
                        print("  -", s)
                print("")

        # each entry in notfound files:
        # (filedir, filename, filehash, scancoderes, fossologyres)
        notfoundfiles = list(notfoundfiles)
        notfoundfiles.sort()
        for i in notfoundfiles:
            (filedir, filename, filehash, scancoderes, fossologyres) = i
            #print "NOT FOUND\t%s\tScanCode:\t%s\tFOSSology:\t%s" % (os.path.normpath(os.path.join(filedir, filename)), reduce(lambda x, y: x + y, scancoderes), list(fossologyres))
            print("NOT FOUND\t%s\tScanCode:\t%s\tFOSSology:\t%s" % (os.path.normpath(os.path.join(filedir, filename)), list(scancoderes), list(fossologyres)))

    # close database connections
    for cursor in postgresql_cursors:
        cursor.close()
    for conn in postgresql_conns:
        conn.close()

if __name__ == "__main__":
    main(sys.argv)
