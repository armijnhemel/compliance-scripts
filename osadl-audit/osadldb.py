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

import sys, os, subprocess, tempfile, hashlib, json, stat, shutil, copy
import argparse, configparser, multiprocessing
import psycopg2

usetlsh = False
try:
	import tlsh
	usetlsh = True
except:
	pass

## a thread that takes results and writes them to the database
def writetodb(dbconn, dbcursor, resultqueue):
	## cache some results
	dbcounter = 0
	while True:
		## get data from the result queue
		res = resultqueue.get()
		if res['type'] == 'file':
			dbcursor.execute("insert into fileinfo (packagename, version, fullfilename, filename, checksum) values (%s,%s,%s,%s,%s)", (res['packagename'], res['version'], res['filename'], os.path.basename(res['filename']), res['sha256']))
			if res['tlshhash'] != None:
				dbcursor.execute("insert into hashes (sha256, tlsh) values (%s,%s) ON CONFLICT DO NOTHING", (res['sha256'], res['tlshhash']))
			dbcounter += 1
			if dbcounter % 1000 == 0:
				dbconn.commit()
		elif res['type'] == 'archive':
			dbcursor.execute("insert into archive (packagename, version, archivename, checksum, project, downloadurl, website) values (%s,%s,%s,%s,%s,%s,%s)", (res['package'], res['version'], res['filename'], res['sha256'], res['project'], res['downloadurl'], res['downloadurl']))
			dbconn.commit()
		resultqueue.task_done()

## a thread to unpack an archive and walk results
def processarchive(scanqueue, resultqueue, sourcesdirectory, unpackprefix):
	while True:
		task = scanqueue.get()
		unpackdirectory = tempfile.mkdtemp(dir=unpackprefix)
		unpackdirectorylen = len(unpackdirectory) + 1
		## then for each file:
		## 1. unpack the archive
		## 2. compute hashes
		## 3. report results
		p = subprocess.Popen(['tar', 'ixf', os.path.join(sourcesdirectory, task['filename'])], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=unpackdirectory)
		p.communicate()
		if p.returncode != 0:
			shutil.rmtree(unpackdirectory)
			scanqueue.task_done()

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
				if usetlsh:
					## only compute TLSH for files that are 256 bytes are more
					if len(sourcedata) >= 256:
						tlshhash = tlsh.hash(sourcedata)

				resultqueue.put({'type': 'file', 'filename': fullfilename[unpackdirectorylen:], 'sha256': filehash, 'tlshhash': tlshhash, 'packagename': task['package'], 'version': task['version']})

		shutil.rmtree(unpackdirectory)
		archiveres = copy.deepcopy(task)
		archiveres['type'] = 'archive'
		resultqueue.put(archiveres)
		scanqueue.task_done()

## a convenience method to unpack a Linux kernel tarball into a temporary
## directory. The return value is the directory in which the data was
## unpacked.
def unpack_tarball(pathname, temporary_prefix=None):
	## first create a temporary directory
	unpackdirectory = tempfile.mkdtemp(dir=temporary_prefix)
	pass

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
		dbconnection = psycopg2.connect(database=config_settings['postgresql_db'], user=config_settings['postgresql_user'], password=config_settings['postgresql_password'])
		dbconnection.close()
	except:
		print("Database server not running or malconfigured, exiting.", file=sys.stderr)
		sys.exit(1)

	## see which files need to be unpacked and processed
	## first open the database
	dbconnection = psycopg2.connect(database=config_settings['postgresql_db'], user=config_settings['postgresql_user'], password=config_settings['postgresql_password'])
	dbcursor = dbconnection.cursor()

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

	## TODO: make configurable
	cpuamount = max(multiprocessing.cpu_count() - 1, 1)

	## TODO: make configurable
	unpackprefix = '/home/armijn/tmp'

	## first create a thread that writes results to the database
	scanqueue = processmanager.JoinableQueue(maxsize=0)
	reportqueue = processmanager.JoinableQueue(maxsize=0)
	processpool = []

	for i in archivestoprocess:
		scanqueue.put(i)

	for i in range(0,cpuamount):
		p = multiprocessing.Process(target=processarchive, args=(scanqueue, reportqueue, scandirectory, unpackprefix))
		processpool.append(p)

	r = multiprocessing.Process(target=writetodb, args=(dbconnection, dbcursor, reportqueue))
	processpool.append(r)

	for p in processpool:
		p.start()

	scanqueue.join()
	reportqueue.join()

	for p in processpool:
		p.terminate()

	## and finally close the database cursor and connection
	dbcursor.close()
	dbconnection.close()

if __name__ == "__main__":
	main(sys.argv)
