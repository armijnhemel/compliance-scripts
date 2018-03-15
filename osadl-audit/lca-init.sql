create table if not exists archive (packagename text, version text, archivename text, checksum text, project text, downloadurl text, website text);
create table if not exists fileinfo (packagename text, version text, fullfilename text, relativefilename text, filename text, checksum text);
create table if not exists hashes (sha256 text, tlsh text, primary key(sha256));
create index archive_index on archive(packagename, version);
create index archive_checksum_index on archive(checksum);
