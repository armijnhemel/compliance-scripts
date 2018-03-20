Scripts used in the OSADL License Compliance Audit: http://lca.osadl.org/

These scripts perform a "delta scan" and focuses just on the files that cannot be found in files that are in the database. The database is made from official tarballs downloaded from www.kernel.org of the "regular" and "stable" kernel releases. In the future other releases (RT, LTSI) might be added too.

It is assumed that files that are in the kernel.org upstream have been looked at enough by many people. By focusing on just the delta the amount of files that need to be looked at is typically in the low hundreds instead of thousands.

A more depth description can be found here: https://lwn.net/Articles/552758/

Included in this directory are:

* audit.config -- same configuration file for audit script and database creation script
* kerneldownload.py -- simple kernel archive downloader
* osadlaudit.py -- audit script
* osadldb.py -- database creation script
* lca.sql -- database table definitions for PostgreSQL
* lca-drop.sql -- SQL to quickly drop all tables using psql
* README -- this file

A few dependencies are needed:
    * tlsh (optional)
    * requests (optional, just for downloader script) - Fedora package name: python3-requests
    * psutil - Fedora package name: python3-psutil
    * ScanCode
    * FOSSology (uses "nomossa", the standalone Nomos scanner for people who do not want to install/use/configure all of FOSSology. This can easily be replaced by the path of the regular "nomos" if there is already an existing FOSSology installation)

Installing ScanCode:

1. git clone https://github.com/nexB/scancode-toolkit
2. run the scancode program once so it self-configures
3. add the path of the scancode program to the configuration file (example: "audit.config")

Make sure that you have Git commit fea65d35a475553368db17a1d196e61a92974a74 or later (current on March 20, 2018).

Creating the database:

The database creation script requires PostgreSQL 9.5 or later and a recent psycopg2.

1. install PostgreSQL. This is outside of the scope of this document.

2. create a database and a user, for example:

    create database osadl;
    create user osadl with password 'osadl';
    grant all privileges on database osadl to osadl;

3. the database should accept password connections. In the file pg_hba.conf (typically located in /var/lib/pgsql/data ) you need to make sure that you can connect with a username/password. To set that for local connections add for example the following:

     local   all             all                                     password

Of course, you also need to make sure that this doesn't interfere with any other uses of PostgreSQL you might have.

4. create the database tables. These are defined in the file "lca.sql" and can be loaded into the database as follows:

    $ psql -U osadl < lca.sql

Populating the database:

This step is not needed if a prefab database is used (will be made available by OSADL for OSADL members).

1. download the Linux kernel source code releases (only tar.xz files are downloaded), or use a previously downloaded collection of downloaded sources. For both the "kerneldownload.py" script should be used to generate the correct metadata that is used:

    $ python3 kerneldownload.py -d /path/to/directory/with/tarballs

2. run the "osadldb.py" script. This script uses a configuration file. An example with some default values and their explanations can be found in "audit.config". The settings relevant to the database creation are in the [createdatabase] section.

    $ python3 osadldb.py -d /path/to/directory/with/tarballs -c /path/to/configuration/file

This problem is I/O bound and unpacking on SSD or (even better) ramdisk will very significantly speed up processing the tarballs. Using ramdisk having 7 threads unpacking and 1 thread writing data to the database is not a problem at all.

Running the audit script:

The audit script uses a configuration file. An example with some default values and their explanations can be found in "audit.config". The settings relevant to the audit are in the "audit" section.

    $ python3 osadlaudit -s /path/to/directory/with/sources/to/scan -c /path/to/configuration/file

When reading the data from a cache (JSON files) please be aware that it is very easy to swamp the database writing process, even with just a single process putting data into the task queue. Use this feature with care.


Dumping the database:

In case you need to dump the database (for example to be able to load it on a different machine). The following command will dump the database in "custom" format:

    $ pg_dump -U osadl -d osadl -F c -f /path/to/dump/file

It is important to realize that this format might change between versions of PostgreSQL. However, it is recommended if you want to (more) quickly load the data.

For a more portable version use the text format:

    $ pg_dump -U osadl -d osadl -f /path/to/dump/file

Restoring a database dump:

To restore a database either

    $ pg_restore -U osadl -d osadl -j 8 /path

or (when using a text dump):

    $ cat /path/to/text/dump | psql -U osadl -d osadl

or, if the file has been compressed with XZ:

    $ xzcat /path/to/text/dump | psql -U osadl -d osadl

During restoring the following innocent error message might pop up:

    Error

    pg_restore: [archiver (db)] Error while PROCESSING TOC:
    pg_restore: [archiver (db)] Error from TOC entry 3123; 0 0 COMMENT EXTENSION plpgsql
    pg_restore: [archiver (db)] could not execute query: ERROR:  must be owner of extension plpgsql
        Command was: COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';

but this can be ignored.

Afterwards you should be able to connect to the database:

    $ psql -U osadl -d osadl

and run queries.
