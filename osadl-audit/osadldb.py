#!/usr/bin/python3

## script to create a database from Linux kernel tarballs
## official Linux kernel tarballs can be grabbed from:
## https://cdn.kernel.org/pub/linux/kernel/
##
## SPDX-License-Identifier: GPL-3.0-only
##
## Copyright 2018 - Armijn Hemel
##

## This script processes a directory with Linux kernel tarballs.
## It reads a JSON datafile describing each archive file in detail
## (hashes, download location, and so on).
##
## It unpacks each archive and for each file inside the archive it stores:
## * name + path of the file (relative path inside unpacking directory)
## * name of file (basename)
## * SHA256 checksum
## * TLSH (optional)

import sys, os, subprocess, tempfile, hashlib, json, stat, shutil, copy, time
import argparse, configparser, multiprocessing, tarfile, json
import psycopg2, psycopg2.extras
import psutil

usetlsh = False
try:
	import tlsh
	usetlsh = True
except:
	pass

## a thread that takes results and writes them to the database
def writetodb(dbconn, dbcursor, resultqueue):
	seensha256 = set()
	while True:
		## get data from the result queue
		(resulttype, results) = resultqueue.get()
		## first part of the tuple is the type
		if resulttype == 'file':
			psycopg2.extras.execute_values(dbcursor, "insert into fileinfo (packagename, version, fullfilename, relativefilename, filename, checksum) values %s", results)
			dbconn.commit()
		elif resulttype == 'archive':
			dbcursor.execute("insert into archive (packagename, version, archivename, checksum, project, downloadurl, website) values (%s,%s,%s,%s,%s,%s,%s)", (results['package'], results['version'], results['filename'], results['sha256'], results['project'], results['downloadurl'], results['downloadurl']))
			dbconn.commit()
			print("Wrote: %s\n" % results['version'])
			sys.stdout.flush()
		elif resulttype == 'hashes':
			for res in results:
				if not res['sha256'] in seensha256:
					## ignore entries without TLSH hashes for now, as they wouldn't matter for matching
					## and the checksum has already been recorded in 'fileinfo'
					if res['tlshhash'] != None:
						dbcursor.execute("insert into hashes (sha256, tlsh) values (%s,%s) ON CONFLICT DO NOTHING", (res['sha256'], res['tlshhash']))
						seensha256.add(res['sha256'])
			dbconn.commit()
		resultqueue.task_done()

## a thread to unpack an archive and compute checksums for files
def processarchive(scanqueue, resultqueue, sourcesdirectory, unpackprefix, cacheresult, cachedir, processsleep):
	seensha256 = set()
	while True:
		## grab a new task
		task = scanqueue.get()

		jsonsuccess = False
		## first check if there are already results available and use those instead
		if cacheresult:
			kernelresultfilename = os.path.join(cachedir, "%s.json" % task['sha256'])
			if os.path.exists(kernelresultfilename):
				kernelresultfile = open(kernelresultfilename, 'r')
				try:
					kernelresults = json.load(kernelresultfile)
					jsonsuccess = True
				except:
					## corrupt file
					kernelresultfile.close()
					try:
						os.unlink(kernelresultfilename)
					except:
						pass
				kernelresultfile.close()

		results = []
		hashresults = []
		resultcounter = 0

		if cacheresult and jsonsuccess:
				## split the results
				for f in kernelresults:
					fullfilename = f['fullfilename']
					relativefilename = f['relativefilename']
					filehash = f['sha256']
					results.append((task['package'], task['version'], fullfilename, relativefilename, os.path.basename(fullfilename), filehash))
					if 'tlshhash' in f and not filehash in seensha256:
						hashresults.append({'sha256': filehash, 'tlshhash': f['tlshhash']})
					seensha256.add(filehash)

				## send results to the database
				resultqueue.put(('file', results))
				resultqueue.put(('hashes', hashresults))

				print("Queued\n", task['version'])
				sys.stdout.flush()

				## send the results for the archive to the database
				resultqueue.put(('archive', copy.deepcopy(task)))

				memstats = psutil.virtual_memory()
				#swapstats = psutil.swap_memory()
				if memstats.percent > 30:
					time.sleep(processsleep)

				## tell the queue the task is done
				scanqueue.task_done()
				continue

		## create a temporary directory
		unpackdirectory = tempfile.mkdtemp(dir=unpackprefix)

		## store the length of the temporary directory so it can be properly
		## cut from the data that is being stored. Add 1 for the '/' of the path
		unpackdirectorylen = len(unpackdirectory) + 1

		## For each archive:
		## 1. unpack the archive
		## 2. compute hashes for each file found in the archive
		## 3. report results
		if 'tar' in task['filename'].lower():
			try:
				sourcetar = tarfile.open(os.path.join(sourcesdirectory, task['filename']), 'r')
				sourcetar.extractall(path=unpackdirectory)
				sourcetar.close()
			except:
				## tar file could not be unpacked, so stop
				shutil.rmtree(unpackdirectory)
				scanqueue.task_done()
				continue
		else:
			## TODO: add support for ZIP files
			shutil.rmtree(unpackdirectory)
			scanqueue.task_done()
			continue

		cacheresults = []

		## check to see whether or not part the path should be removed first
		## before storing as "relativefilename"
		removetopdirlen = unpackdirectorylen
		removetopdir = False
		if len(os.listdir(unpackdirectory)) == 1:
			topdir = os.listdir(unpackdirectory)[0]
			if topdir == task['package']:
				removetopdir = True
			else:
				for i in ['-', ',', '_', ' ']:
					if topdir == "%s%s%s" % (task['package'], i, task['version']):
						removetopdir = True
						break
			if removetopdir:
				removetopdirlen += len(topdir) + 1

		## walk the directory
		dirwalk = os.walk(unpackdirectory)

		for direntries in dirwalk:
			## make sure all subdirectories and files can be accessed
			for subdir in direntries[1]:
				subdirname = os.path.join(direntries[0], subdir)
				if not os.path.islink(subdirname):
					os.chmod(subdirname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			for filename in direntries[2]:
				fullfilename = os.path.join(direntries[0], filename)
				if not os.path.islink(fullfilename):
					os.chmod(fullfilename, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)

				## now read the contents of the file
				try:
					sourcefile = open(fullfilename, 'rb')
					sourcedata = sourcefile.read()
					sourcefile.close()
				except:
					continue

				## compute hashes
				h = hashlib.new('sha256')
				h.update(sourcedata)
				filehash = h.hexdigest()
				tlshhash = None

				results.append((task['package'], task['version'], fullfilename[unpackdirectorylen:], fullfilename[removetopdirlen:], os.path.basename(fullfilename), filehash))
				if cacheresult:
					tmpresult = {'sha256': filehash, 'fullfilename': fullfilename[unpackdirectorylen:], 'relativefilename': fullfilename[removetopdirlen:]}

				if usetlsh:
					## only compute TLSH for files that are 256 bytes are more
					if len(sourcedata) >= 256:
						tlshhash = tlsh.hash(sourcedata)
						if cacheresult:
							tmpresult['tlshhash'] = tlshhash
						if not filehash in seensha256:
							hashresults.append({'sha256': filehash, 'tlshhash': tlshhash})
				seensha256.add(filehash)


				if cacheresult:
					cacheresults.append(tmpresult)

				## send intermediate results to the database, per 1000 files
				resultcounter += 1
				if resultcounter % 1000 == 0:
					resultqueue.put(('file', results))
					resultqueue.put(('hashes', hashresults))
					results = []
					hashresults = []

		## send remaining results to the database
		resultqueue.put(('file', results))

		## send remaining results to the database
		if hashresults != []:
			resultqueue.put(('hashes', hashresults))

		## remove the unpacking directory
		shutil.rmtree(unpackdirectory)

		print("Queued\n", task['version'])
		sys.stdout.flush()

		## send the results for the archive to the database
		resultqueue.put(('archive', copy.deepcopy(task)))

		if cacheresult:
			jsondumpfile = open(os.path.join(cachedir, "%s.json" % task['sha256']), 'w')
			json.dump(cacheresults, jsondumpfile)
			jsondumpfile.close()

		## tell the queue the task is done
		scanqueue.task_done()

def main(argv):
	parser = argparse.ArgumentParser()

	## the following options are provided on the commandline
	parser.add_argument("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_argument("-d", "--directory", action="store", dest="scandirectory", help="path to directory with files to be scanned", metavar="DIR")
	args = parser.parse_args()

	## checks for the scandirectory
	if args.scandirectory == None:
		parser.error("Directory with files to be scanned missing")

	if not os.path.exists(args.scandirectory):
		print("Directory to scan does not exist: %s" % args.scandirectory, file=sys.stderr)
		sys.exit(1)

	## then rewrite the path to an absolute path
	if not os.path.isabs(args.scandirectory):
		scandirectory = os.path.normpath(os.path.join(os.getcwd(), args.scandirectory))
	else:
		scandirectory = args.scandirectory

	## the archive directory should have some metadata present as JSON
	## the file is called "archives.json"
	jsonfilenamepath = os.path.join(scandirectory, "archives.json")
	if not os.path.exists(jsonfilenamepath):
		print("JSON metadata file '%s' does not exist, exiting" % jsonfilenamepath, file=sys.stderr)
		sys.exit(1)

	## then read the top level JSON data file and parse it
	jsonfile = open(jsonfilenamepath, 'r')
	try:
		archivemeta = json.load(jsonfile)
	except:
		jsonfile.close()
		print("Malformed JSON in %s, exiting" % jsonfilenamepath, file=sys.stderr)
		sys.exit(1)
	jsonfile.close()

	## some checks for the configuration file
	if args.cfg == None:
		parser.error("Configuration file missing")

	if not os.path.exists(args.cfg):
		parser.error("Configuration file does not exist")

	config = configparser.ConfigParser()
	configfile = open(args.cfg, 'r')

	try:
		config.readfp(configfile)
	except Exception:
		print("Cannot read configuration file", file=sys.stderr)
		sys.exit(1)

	## process the configuration file and store settings
	config_settings = {}

	for section in config.sections():
		if section == 'database':
			try:
				config_settings['postgresql_user'] = config.get(section, 'postgresql_user')
			except:
				pass
			try:
				config_settings['postgresql_password'] = config.get(section, 'postgresql_password')
			except:
				pass
			try:
				config_settings['postgresql_db'] = config.get(section, 'postgresql_db')
			except:
				pass
			try:
				config_settings['postgresql_host'] = config.get(section, 'postgresql_host')
			except:
				config_settings['postgresql_host'] = None
			try:
				config_settings['postgresql_port'] = config.get(section, 'postgresql_port')
			except:
				config_settings['postgresql_port'] = None
		elif section == 'createdatabase':
			cacheresult = False
			cachedir = None

			unpackprefix = None
			try:
				unpackprefix = config.get(section, 'unpackdirectory')
				if not os.path.isabs(unpackprefix):
					unpackprefix = os.path.normpath(os.path.join(os.getcwd(), unpackprefix))
				if not os.path.exists(unpackprefix):
					unpackprefix = None
			except:
				pass
			try:
				processors = int(config.get(section, 'processors'))
				cpuamount = max(min(processors, multiprocessing.cpu_count()) - 1, 1)
			except:
				cpuamount = max(multiprocessing.cpu_count() - 1, 1)

			try:
				cacheres = config.get(section, 'cacheresults')
				if cacheres == 'yes':
					cacheresult = True
			except:
				cacheresult = False
			try:
				cachedirectory = config.get(section, 'cachedirectory')
				if os.path.isdir(cachedirectory):
					## write a test file to see if the directory is writable
					testfile = tempfile.mkstemp(dir=cachedirectory)
					os.fdopen(testfile[0]).close()
					## remove the test file
					os.unlink(testfile[1])
					cachedir = cachedirectory
			except:
				## something happened, so don't do anything
				pass

	if cacheresult and cachedir == None:
		cacheresult = False
	if not 'postgresql_user' in config_settings:
		print("Database configuration information incomplete (postgresql_user)", file=sys.stderr)
		sys.exit(1)
	if not 'postgresql_password' in config_settings:
		print("Database configuration information incomplete (postgresql_password)", file=sys.stderr)
		sys.exit(1)
	if not 'postgresql_db' in config_settings:
		print("Database configuration information incomplete (postgresql_db)", file=sys.stderr)
		sys.exit(1)

	## first see if the database is up and running
	try:
		dbconnection = psycopg2.connect(database=config_settings['postgresql_db'], user=config_settings['postgresql_user'], password=config_settings['postgresql_password'], port=config_settings['postgresql_port'], host=config_settings['postgresql_host'])
		dbconnection.close()
	except:
		print("Database server not running or malconfigured, exiting.", file=sys.stderr)
		sys.exit(1)

	## see which files need to be unpacked and processed
	## first open the database
	dbconnection = psycopg2.connect(database=config_settings['postgresql_db'], user=config_settings['postgresql_user'], password=config_settings['postgresql_password'], port=config_settings['postgresql_port'], host=config_settings['postgresql_host'])
	dbcursor = dbconnection.cursor()

	## sort the metadata by filename. This is mostly cosmetic.
	archivemeta = sorted(archivemeta, key=lambda x: x['filename'])

	archivestoprocess = []

	## then check for each file if there already is a match
	for i in archivemeta:
		if not 'sha256' in i:
			continue
		dbcursor.execute("select * from archive where checksum=%s", (i['sha256'],))
		dbres = dbcursor.fetchall()
		if len(dbres) != 0:
			continue

		## only process if the archive actually exists
		if os.path.exists(os.path.join(scandirectory, i['filename'])):
			archivestoprocess.append(i)

	processmanager = multiprocessing.Manager()

	## first create a thread that writes results to the database
	scanqueue = processmanager.JoinableQueue(maxsize=0)
	reportqueue = processmanager.JoinableQueue(maxsize=0)
	processpool = []

	for i in archivestoprocess:
		scanqueue.put(i)

	processsleep = 30

	## create processes for unpacking archives
	for i in range(0,cpuamount):
		p = multiprocessing.Process(target=processarchive, args=(scanqueue, reportqueue, scandirectory, unpackprefix, cacheresult, cachedir, processsleep))
		processpool.append(p)

	## create one process to write to the database
	r = multiprocessing.Process(target=writetodb, args=(dbconnection, dbcursor, reportqueue))
	processpool.append(r)

	## start all the processes
	for p in processpool:
		p.start()

	scanqueue.join()
	reportqueue.join()

	## flush db connection, just in case
	dbconnection.commit()

	## terminate all the old processes
	for p in processpool:
		p.terminate()

	## and finally close the database cursor and connection
	dbcursor.close()
	dbconnection.close()

if __name__ == "__main__":
	main(sys.argv)
