REM Oracle Data Collection Script
REM Version: 2.2
REM
REM Changes since 2.2 (2026-11-12):
REM - Fixed dailyChangeRate being blank on the con_id=0 rollup row. It is now the root's
REM   dailyRedoSizeTB (redo is only maintained at the root) divided by the cumulative dbSizeTB
REM   of ALL pluggables (con_id>2, excluding CDB$ROOT and PDB$SEED), or 0 when the CDB has no
REM   PDBs plugged in yet.
REM - Fixed dailyChangeRate being understated on the per-container rows: the query joined
REM   cdb_segments to the archived-log rows with no join condition, multiplying sum(bytes) by the
REM   number of redo-day rows. Segment bytes are now summed per container and average daily redo
REM   is a single value before dividing. A container with zero segment bytes now yields NULL.
REM - KNOWN LIMITATIONS: (1) v$archived_log reports every row under con_id=0, so redo cannot be
REM   split per PDB: per-container dailyChangeRate is CDB-wide redo over that container's used
REM   space, not its own change rate -- use the con_id=0 row. (2) dailyRedoSizeTB counts every
REM   archive destination, so a standby doubles it (and dailyChangeRate); not yet fixed.
REM   (3) The 7-day average is rounded to 6 decimals of TB. Planned for v2.3: compute the rate in
REM   the Cowork skill and replace dailyChangeRate with better redo inputs (see README).
REM
REM Version 2.2 Updates (2026-09-10):
REM - Fixed dbSizeTB returning the same (wrong) value for every PDB in a CDB. It was built on
REM   plain dba_segments, which is not container-spanning -- queried from root, every row it
REM   returns is tagged with root's own con_id, so a PDB's con_id filter matched zero rows and
REM   fell back to the null-coalesce 0. Switched to containers(cdb_segments), the properly
REM   container-aware view, matching the pattern already used for every other DBA_-view-based
REM   per-PDB query in this script (encryptedDataSizeTB, biggestBigfileGB, etc).
REM - dailyChangeRate's denominator switched from allocated space (v$datafile) to actual used
REM   space (cdb_segments), so it now reflects the pct of real data that changes daily instead
REM   of pct of allocated-but-possibly-empty space. allocated_dbSizeTB's v$datafile query is
REM   now also wrapped in CONTAINERS() for consistency/defense, though v$datafile (unlike
REM   dba_segments) is reliably container-aware from root without it.
REM
REM Version 2.1 Updates (2026-09-09):
REM - Adds one rollup row per CDB representing the whole database as a single entity:
REM   con_id=0, conName is just the CDB name (the root's own name without ".CDB$ROOT").
REM   Storage fields are summed across the real PDBs only (excluding CDB$ROOT and
REM   PDB$SEED); dailyRedoSizeTB is copied from the root rather than summed, since the
REM   root already holds the CDB-wide redo total; biggestBigfileGB/GoldenGate/
REM   exadataEnabled use MAX() across root+PDBs; every other column is copied from the
REM   root. This makes con_id=0 consistently mean "one row per database" for both CDBs
REM   and standalone (11g-style) databases.
REM
REM Version 2.0 Updates (2026-09-03):
REM - Output field delimiter changed from comma to a tab character (chr(9)); some collected
REM   values (e.g. LogArchiveConfig, patchLevel) can legitimately contain commas.
REM - Added SET DEFINE OFF so an "&" in a collected value is not treated as a SQL*Plus
REM   substitution-variable prompt.
REM - dbSizeTB, allocated_dbSizeTB, encryptedDataSizeTB, dailyRedoSizeTB (previously
REM   dbSizeMB/allocated_dbSizeMB/encryptedDataSizeMB/dailyRedoSize) now report TB with
REM   6 decimal places instead of MB/bytes.
REM - biggestBigfileGB, bigfileDataSizeGB (previously *MB) now report GB with 6 decimal places.
REM - sgaMaxSizeGB, sgaTargetGB, pgaAggregateTargetGB, physMemoryGB (previously without the
REM   GB suffix) now report GB at full precision instead of raw bytes.
REM - dbSizeTB and allocated_dbSizeTB now coalesce to 0 instead of returning blank for
REM   containers with no visible segments or datafiles, such as PDB$SEED.

-- connect to the system schema
--conn SYSTEM@$1

-- create private temporary table to hold all  collected

create global temporary table rubrikDataCollection
	(
	con_id number,
	conName varchar2(128),
	dbSizeTB number,
	allocated_dbSizeTB number,
	biggestBigfileGB number,
	dailyChangeRate number,
	dailyRedoSizeTB number,	
	datafileCount number,		
	hostName varchar2(64),
	instName varchar2(16),
	dbVersion varchar2(17),
--	dbEdition varchar2(7),
-- updating dbEdition to support larger settings in v$instance.version
	dbEdition varchar2(100),
	platformName varchar2(101),
	dbName varchar2(9),
	dbUniqueName varchar2(30),
	dbID varchar2(200),
	flashbackEnabled varchar2(18),
	archiveLogEnabled varchar2(12),
	spfile varchar2(200),
	patchLevel varchar2(100),
	cpuCount number,
	blockSize number,
	racEnabled varchar2(20),
	sgaMaxSizeGB number,
	sgaTargetGB number,
	pgaAggregateTargetGB number,
	physMemoryGB number,
	dNFSenabled varchar2(20),
	GoldenGate varchar2(20),
	exadataEnabled varchar2(20),
	bctEnabled varchar2(20),
	LogArchiveConfig varchar2(200),
	ArchiveLagTarget number,
	tablespaceCount number,
	encryptedTablespaceCount number,
	encryptedDataSizeTB number,
	bigfileTablespaceCount number,
	bigfileDataSizeGB number,
	logfileCount number,
	tempfileCount number
	)
on commit preserve rows;

insert into rubrikDataCollection
(
con_id,
conName,
hostName,
instName,
dbVersion,
dbEdition,
platformName,
dbName,
dbUniqueName,
dbID,
flashbackEnabled,
archiveLogEnabled
)
select cont.con_id,
cont.name,
inst.host_name,
inst.instance_name,
inst.version_full,
inst.edition,
db.platform_name,
db.name,
db.db_unique_name,
cont.dbid,
db.flashback_on,
db.log_mode
from v$instance inst,
v$database db,
v$containers cont
/

UPDATE rubrikDataCollection rbk
SET spfile = (select decode(count(*), 0, 'NO', 'YES') from v$parameter where name='spfile')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

-- result is the latest patch
UPDATE rubrikDataCollection rbk
SET patchLevel = (select * from (select description from dba_registry_sqlpatch order by TARGET_BUILD_TIMESTAMP desc) where ROWNUM = 1)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET cpuCount = (SELECT value from v$parameter where name='cpu_count')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET blockSize = (SELECT value from v$parameter where name='db_block_size')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET racEnabled = (SELECT value from v$parameter where name='cluster_database')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET sgaMaxSizeGB = (SELECT value/1024/1024/1024 from v$parameter where name='sga_max_size')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET sgaTargetGB = (SELECT value/1024/1024/1024 from v$parameter where name='sga_target')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET pgaAggregateTargetGB = (SELECT value/1024/1024/1024 from v$parameter where name='pga_aggregate_target')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET physMemoryGB = (SELECT max(value)/1024/1024/1024 from dba_hist_osstat where stat_name = 'PHYSICAL_MEMORY_BYTES')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET dNFSenabled = (select decode(count(*), 0, 'NO', 'YES') from v$dnfs_servers)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

-- cdb_segments is inherently container-aware; containers() around it and around v$datafile
-- below is defensive, matching the pattern used for every other DBA_-view-based query
UPDATE rubrikDataCollection rbk
SET dbSizeTB = (select round(sum(bytes)/1024/1024/1024/1024,6) bytes from containers(cdb_segments) where con_id=rbk.con_id group by con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- v$datafile can use the containers clause
-- this query returns the total space ALLOCATED to each container
UPDATE rubrikDataCollection rbk
SET allocated_dbSizeTB = (select round(sum(bytes)/1024/1024/1024/1024,6) bytes from containers(v$datafile) where con_id=rbk.con_id group by con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

UPDATE rubrikDataCollection rbk
SET dbSizeTB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and dbSizeTB is null;

UPDATE rubrikDataCollection rbk
SET allocated_dbSizeTB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and allocated_dbSizeTB is null;


-- v$archive_dest is container-aware
-- if cont_id is 0, it means the entire CDB
UPDATE rubrikDataCollection rbk
SET GoldenGate = (select decode(count(*), 0, 'NO', 'YES') from v$archive_dest where status = 'VALID' and target = 'STANDBY' and con_id=0)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

-- this query addresses GoldenGate for each container
UPDATE rubrikDataCollection rbk
SET GoldenGate = (select decode(count(*), 0, 'NO', 'YES') from v$archive_dest where status = 'VALID' and target = 'STANDBY' and con_id=rbk.con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- gv$cell is container-aware 
-- if cont_id is 0, it means the entire CDB
UPDATE rubrikDataCollection rbk
SET exadataEnabled = (select decode(count(*), 0, 'NO', 'YES') from v$cell where con_id=0)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

-- this query addresses Exadata for each container (overkill)
UPDATE rubrikDataCollection rbk
SET exadataEnabled = (select decode(count(*), 0, 'NO', 'YES') from v$cell where con_id=rbk.con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- v$block_change_tracking is container-aware
-- for now, BCT is allowed only in CDB
UPDATE rubrikDataCollection rbk
SET bctEnabled = (select status from v$block_change_tracking)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET LogArchiveConfig = (SELECT value from v$parameter where name='log_archive_config')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

-- Need to explicitly set a value for LogArchiveConfig is the previous query returns a null value
UPDATE rubrikDataCollection rbk
SET LogArchiveConfig = 'NO'
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and LogArchiveConfig is null;

UPDATE rubrikDataCollection rbk
SET ArchiveLagTarget = (SELECT value from v$parameter where name='archive_lag_target')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);	

-- v$tablespace is container-aware
UPDATE rubrikDataCollection rbk
SET tablespaceCount = (select count(*)  from v$tablespace where con_id=rbk.con_id group by con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- containers clause works on dba_tablespaces 
UPDATE rubrikDataCollection rbk
SET encryptedTablespaceCount = (select count(*) from containers(dba_tablespaces) where encrypted='YES' and con_id=rbk.con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- containers clause works on dba_data_files and dba_tablespaces
UPDATE rubrikDataCollection rbk
SET encryptedDataSizeTB = (select round(sum(bytes)/1024/1024/1024/1024,6) from (select dbf.con_id,sum(bytes) bytes from containers(dba_data_files) dbf, containers(dba_tablespaces) tbsp where dbf.tablespace_name=tbsp.tablespace_name and dbf.con_id=tbsp.con_id and tbsp.encrypted='YES' group by dbf.con_id) where con_id=rbk.con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- need to explicitly set encryptedDataSizeTB if previous query returns a null value
UPDATE rubrikDataCollection rbk
SET encryptedDataSizeTB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and encryptedDataSizeTB is null;

UPDATE rubrikDataCollection rbk
SET bigfileTablespaceCount = (select count(*) from containers(dba_tablespaces) where bigfile='YES' and con_id=rbk.con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- containers clause works on dba_data_files and dba_tablespaces
UPDATE rubrikDataCollection rbk
SET biggestBigfileGB = (select round(sum(bytes)/1024/1024/1024,6) from (select dbf.con_id, max(bytes) bytes from containers(dba_data_files) dbf, containers(dba_tablespaces) tbsp where dbf.tablespace_name=tbsp.tablespace_name and dbf.con_id=tbsp.con_id and tbsp.bigfile='YES' group by dbf.con_id) where con_id=rbk.con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- need to explicitly set biggestBigfileGB if the previous query returns a null value
UPDATE rubrikDataCollection rbk
SET biggestBigfileGB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and biggestBigfileGB is null;

UPDATE rubrikDataCollection rbk
SET bigfileDataSizeGB = (select round(sum(bytes)/1024/1024/1024,6) from (select dbf.con_id, sum(bytes) bytes from containers(dba_data_files) dbf, containers(dba_tablespaces) tbsp where dbf.tablespace_name=tbsp.tablespace_name and dbf.con_id=tbsp.con_id and tbsp.bigfile='YES' group by dbf.con_id) where con_id=rbk.con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- need to explicitly set the bigfileDataSizeGB if the previous query returns a null value
UPDATE rubrikDataCollection rbk
SET bigfileDataSizeGB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and bigfileDataSizeGB is null;

-- cdb_segments and v$archived_log are container-aware
-- 20220310 removed division by 100 from change rate calc as it is skewing change rate down smcelhinney
-- 20230321 changed the denominator from allocated space (v$datafile) to actual used space
-- (cdb_segments), so this reflects the pct of real data that changes daily, not allocated
-- space that may never be touched -- smcelhinney
-- NOTE: dailyChangeRate is based on USED redo, i.e. the average daily volume of redo actually
-- generated and archived over the last 7 days (v$archived_log blocks*block_size), divided by
-- used segment space (cdb_segments). This gives a more accurate picture of real redo
-- utilization than raw redo log size / allocated database size.
-- Segment bytes are summed per container (s) and the CDB-wide average daily redo is a single
-- value (r), so the two sides are joined 1:1 on rbk.con_id. The earlier form joined cdb_segments
-- to the archived-log rows with no join condition, which multiplied sum(bytes) by the number of
-- redo-day rows and understated the rate by roughly that factor.
UPDATE rubrikDataCollection rbk
SET dailyChangeRate = (select round(r.avgRedo / nullif(s.bytes, 0), 8) from (select con_id, sum(bytes) bytes from containers(cdb_segments) group by con_id) s, (select avg(redo_size) avgRedo from (select trunc(completion_time) rundate, sum(blocks*block_size) redo_size from containers(v$archived_log) where first_time > sysdate - 7 group by trunc(completion_time))) r where s.con_id=rbk.con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- v$datafile is container-aware (no need for container clause)
UPDATE rubrikDataCollection rbk
SET datafileCount = (select count(*) from v$datafile where con_id=rbk.con_id group by con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- v$logfile is container-aware (no need for container clause)
UPDATE rubrikDataCollection rbk
SET logfileCount = (select count(*) from v$logfile where con_id=rbk.con_id group by con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- as Multitenant instance won't have con_id=0, the result will be add into the root container (con_id=1)
UPDATE rubrikDataCollection rbk
SET logfileCount = (SELECT  SUM(total)
FROM   ( 
            select count(*) total from v$logfile where con_id=0
            UNION ALL
            select count(*) total from v$logfile where con_id=1
        ))
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and rbk.con_id=1;

UPDATE rubrikDataCollection rbk
SET logfileCount = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and logfileCount is null;

-- v$tempfile is container-aware (no need for container clause)
UPDATE rubrikDataCollection rbk
SET tempfileCount = (select count(*) from v$tempfile where con_id=rbk.con_id group by con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- as Multitenant instance won't have con_id=0, the result will be add into the root container (con_id=1)
UPDATE rubrikDataCollection rbk
SET tempfileCount = (SELECT  SUM(total)
FROM   ( 
            select count(*) total from v$tempfile where con_id=0
            UNION ALL
            select count(*) total from v$tempfile where con_id=1
        ))
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and rbk.con_id=1;

-- need to explicitly set tempfileCount if the previous query returns a null value
UPDATE rubrikDataCollection rbk
SET tempfileCount = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and tempfileCount is null;

-- v$archived_log is container-aware (no need for container clause)
-- 20230322 - dailyRedoSize query originally changed to report MB; since v2.0 it reports TB (dailyRedoSizeTB) - smcelhinney
UPDATE rubrikDataCollection rbk
SET dailyRedoSizeTB = (select round(dailyRedoSizeTB/1024/1024/1024/1024,6) from (select con_id, avg(redo_size) dailyRedoSizeTB from (select con_id, trunc(completion_time) rundate, sum(blocks*block_size) redo_size from v$archived_log where first_time > sysdate - 7 group by trunc(completion_time), con_id) group by con_id) where con_id=rbk.con_id)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and con_id=rbk.con_id;

-- as Multitenant instance won't have con_id=0, the result will be add into the root container (con_id=1)
-- 20230322 - dailyRedoSize query originally changed to report MB; since v2.0 it reports TB (dailyRedoSizeTB) - smcelhinney
UPDATE rubrikDataCollection rbk
SET dailyRedoSizeTB = (select round(dailyRedoSizeTB/1024/1024/1024/1024,6) from (select con_id, avg(redo_size) dailyRedoSizeTB from (select con_id, trunc(completion_time) rundate, sum(blocks*block_size) redo_size from v$archived_log where first_time > sysdate - 7 group by trunc(completion_time), con_id) group by con_id) where con_id=0)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and rbk.con_id=1;

-- need to explicitly set dailyRedoSizeTB if the previous query returns a null value
UPDATE rubrikDataCollection rbk
SET dailyRedoSizeTB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and dailyRedoSizeTB is null;

-- update temp table with con_name for recorded con_id
update rubrikDataCollection rbk set con_id=0 where con_id is null;
-- update root container and pdb seed names to include cdb database name
update rubrikDataCollection rbk set conName=(select name ||'.CDB$ROOT'from v$database) where conName='CDB$ROOT';
update rubrikDataCollection rbk set conName=(select name ||'.PDB$SEED'from v$database) where conName='PDB$SEED';
-- update remaining pdbs to append CDB name so pdb/cdb relationships are not lost in the csv
update rubrikDataCollection rbk set conName=(select name ||'.' from v$database)||conName where con_id>2;

-- add a rollup row representing the whole CDB as a single "database": con_id=0, conName is
-- just the CDB name (the root's own conName without the ".CDB$ROOT" suffix). Storage fields
-- are summed across the real PDBs only (con_id>2, excluding CDB$ROOT and PDB$SEED) since those
-- are additive per container. dailyRedoSizeTB is copied from the root (con_id=1) rather than
-- summed, since the root row already holds the CDB-wide redo total -- summing the PDBs into it
-- too would double-count. biggestBigfileGB, GoldenGate, and exadataEnabled can each vary by
-- container, so those use MAX() across root+PDBs to reflect "true if true anywhere in the CDB".
-- Every other column is a constant instance-level attribute, so it is copied from the root.
insert into rubrikDataCollection
(con_id, conName, dbSizeTB, allocated_dbSizeTB, encryptedDataSizeTB, datafileCount,
 tablespaceCount, encryptedTablespaceCount, bigfileTablespaceCount, bigfileDataSizeGB,
 logfileCount, tempfileCount, dailyRedoSizeTB, biggestBigfileGB, GoldenGate, exadataEnabled,
 hostName, instName, dbVersion, dbEdition, platformName, dbName, dbUniqueName, dbID,
 flashbackEnabled, archiveLogEnabled, spfile, patchLevel, cpuCount, blockSize, racEnabled,
 sgaMaxSizeGB, sgaTargetGB, pgaAggregateTargetGB, physMemoryGB, dNFSenabled, bctEnabled,
 LogArchiveConfig, ArchiveLagTarget)
select 0,
       (select name from v$database),
       (select sum(dbSizeTB) from rubrikDataCollection where con_id>2),
       (select sum(allocated_dbSizeTB) from rubrikDataCollection where con_id>2),
       (select sum(encryptedDataSizeTB) from rubrikDataCollection where con_id>2),
       (select sum(datafileCount) from rubrikDataCollection where con_id>2),
       (select sum(tablespaceCount) from rubrikDataCollection where con_id>2),
       (select sum(encryptedTablespaceCount) from rubrikDataCollection where con_id>2),
       (select sum(bigfileTablespaceCount) from rubrikDataCollection where con_id>2),
       (select sum(bigfileDataSizeGB) from rubrikDataCollection where con_id>2),
       (select sum(logfileCount) from rubrikDataCollection where con_id>2),
       (select sum(tempfileCount) from rubrikDataCollection where con_id>2),
       dailyRedoSizeTB,
       (select max(biggestBigfileGB) from rubrikDataCollection where con_id=1 or con_id>2),
       (select max(GoldenGate) from rubrikDataCollection where con_id=1 or con_id>2),
       (select max(exadataEnabled) from rubrikDataCollection where con_id=1 or con_id>2),
       hostName, instName, dbVersion, dbEdition, platformName, dbName, dbUniqueName, dbID,
       flashbackEnabled, archiveLogEnabled, spfile, patchLevel, cpuCount, blockSize,
       racEnabled, sgaMaxSizeGB, sgaTargetGB, pgaAggregateTargetGB, physMemoryGB,
       dNFSenabled, bctEnabled, LogArchiveConfig, ArchiveLagTarget
from rubrikDataCollection
where con_id=1;

-- a CDB with no PDBs plugged in yet (only CDB$ROOT and PDB$SEED) makes every sum() above
-- aggregate an empty set, which returns NULL rather than 0 -- coalesce those to 0 to match
-- the same null-handling convention used for every other summed column in this script
update rubrikDataCollection rbk set dbSizeTB=0 where con_id=0 and dbSizeTB is null;
update rubrikDataCollection rbk set allocated_dbSizeTB=0 where con_id=0 and allocated_dbSizeTB is null;
update rubrikDataCollection rbk set encryptedDataSizeTB=0 where con_id=0 and encryptedDataSizeTB is null;
update rubrikDataCollection rbk set datafileCount=0 where con_id=0 and datafileCount is null;
update rubrikDataCollection rbk set tablespaceCount=0 where con_id=0 and tablespaceCount is null;
update rubrikDataCollection rbk set encryptedTablespaceCount=0 where con_id=0 and encryptedTablespaceCount is null;
update rubrikDataCollection rbk set bigfileTablespaceCount=0 where con_id=0 and bigfileTablespaceCount is null;
update rubrikDataCollection rbk set bigfileDataSizeGB=0 where con_id=0 and bigfileDataSizeGB is null;
update rubrikDataCollection rbk set logfileCount=0 where con_id=0 and logfileCount is null;
update rubrikDataCollection rbk set tempfileCount=0 where con_id=0 and tempfileCount is null;

-- dailyChangeRate for the rollup row (con_id=0): redo is only maintained at the root, so the
-- numerator is the root's dailyRedoSizeTB (the CDB-wide average daily used redo, con_id=1).
-- The denominator is the cumulative used segment space across ALL pluggables (con_id>2,
-- excluding CDB$ROOT and PDB$SEED), the same population the rollup's dbSizeTB sums. This
-- sidesteps the segment/archived-log cartesian join used for the per-container rows. A CDB
-- with no PDBs plugged in yet has no denominator, so it reports 0 like the other rollup columns.
update rubrikDataCollection rbk
set dailyChangeRate = (
      select case when sum(pdb.dbSizeTB) > 0
                  then round(max(root.dailyRedoSizeTB) / sum(pdb.dbSizeTB), 8)
                  else 0 end
      from rubrikDataCollection root, rubrikDataCollection pdb
      where root.con_id = 1
        and pdb.con_id > 2)
where rbk.con_id = 0;

commit;

-- format data collected for csv output
-- set markup csv on
set linesize 32000
set define off
set headsep off
set head off
set trimspool on
set trimout on
set feedback off
set pagesize 0
set wrap off

spool rbkDiscovery-v2.csv append

-- select * from rubrikDataCollection;
select con_id ||chr(9)||
        conName ||chr(9)||
        dbSizeTB ||chr(9)||
        allocated_dbSizeTB ||chr(9)||
        biggestBigfileGB ||chr(9)||
        dailyChangeRate ||chr(9)||
        dailyRedoSizeTB ||chr(9)||
        datafileCount ||chr(9)||
        hostName ||chr(9)||
        instName ||chr(9)||
        dbVersion ||chr(9)||
        dbEdition ||chr(9)||
        platformName ||chr(9)||
        dbName ||chr(9)||
        dbUniqueName ||chr(9)||
        dbID ||chr(9)||
        flashbackEnabled ||chr(9)||
        archiveLogEnabled ||chr(9)||
        spfile ||chr(9)||
        patchLevel ||chr(9)||
        cpuCount ||chr(9)||
        blockSize ||chr(9)||
        racEnabled ||chr(9)||
        sgaMaxSizeGB ||chr(9)||
        sgaTargetGB ||chr(9)||
        pgaAggregateTargetGB ||chr(9)||
        physMemoryGB ||chr(9)||
        dNFSenabled ||chr(9)||
        GoldenGate ||chr(9)||
        exadataEnabled ||chr(9)||
        bctEnabled ||chr(9)||
        LogArchiveConfig ||chr(9)||
        ArchiveLagTarget ||chr(9)||
        tablespaceCount ||chr(9)||
        encryptedTablespaceCount ||chr(9)||
        encryptedDataSizeTB ||chr(9)||
        bigfileTablespaceCount ||chr(9)||
        bigfileDataSizeGB ||chr(9)||
        logfileCount ||chr(9)||
        tempfileCount
 from rubrikDataCollection;

spool off

truncate table rubrikDataCollection;

drop table rubrikDataCollection;

exit;
