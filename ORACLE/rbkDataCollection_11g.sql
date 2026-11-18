REM Oracle Data Collection Script
REM Version: 2.0
REM
REM Changes since 2.0 (2026-11-12):
REM - Fixed dailyChangeRate being understated: the query joined dba_segments to the archived-log
REM   rows with no join condition, multiplying sum(bytes) by the number of redo-day rows. Segment
REM   bytes and average daily redo are now each reduced to a single value before dividing. A
REM   database with zero segment bytes now yields NULL instead of a divide-by-zero error.
REM - KNOWN LIMITATIONS: (1) dailyRedoSize counts every archive destination, so a standby
REM   doubles it (and dailyChangeRate); not yet fixed. (2) The 7-day average is rounded, so a
REM   peak-redo day cannot be seen. Planned for v2.3: compute the rate in the Cowork skill and
REM   replace dailyChangeRate with better redo inputs (see README). Not run against an 11g
REM   database in this round of testing.
REM
REM Version 2.0 Updates (2026-09-03):
REM - Output field delimiter changed from comma to a tab character (chr(9)); some collected
REM   values (e.g. LogArchiveConfig, patchLevel) can legitimately contain commas.
REM - Added SET DEFINE OFF so an "&" in a collected value is not treated as a SQL*Plus
REM   substitution-variable prompt.
REM - dbSizeTB, allocated_dbSizeTB, encryptedDataSizeTB, dailyRedoSizeTB (previously
REM   dbSizeMB/allocated_dbSizeMB/encryptedDataSizeMB/dailyRedoSize) now report TB with
REM   6 decimal places instead of MB.
REM - biggestBigfileGB, bigfileDataSizeGB (previously *MB) now report GB with 6 decimal places.
REM - sgaMaxSizeGB, sgaTargetGB, pgaAggregateTargetGB, physMemoryGB (previously without the
REM   GB suffix) now report GB at full precision instead of raw bytes.
REM - dbSizeTB and allocated_dbSizeTB now coalesce to 0 instead of returning blank if no
REM   segments or datafiles are visible.

-- connect to the system schema
--conn SYSTEM@$1

-- create temporary table to hold all  collected

create global temporary table  rubrikDataCollection
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
-- changing dbEdition size to support v$instance.version size
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
conName,
hostName,
instName,
dbVersion,
platformName,
dbName,
dbUniqueName,
dbID,
flashbackEnabled,
archiveLogEnabled
)
select db.name,
inst.host_name,
inst.instance_name,
inst.version,
db.platform_name,
db.name,
db.db_unique_name,
db.dbid,
db.flashback_on,
db.log_mode
from v$instance inst,
v$database db
/


-- to be improved
-- dbEdition (EE, SE) info
UPDATE rubrikDataCollection rbk
SET dbEdition = (select * from v$version where ROWNUM = 1)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET spfile = (select decode(count(*), 0, 'NO', 'YES') from v$parameter where name='spfile')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET patchLevel = (select * from (select comments from DBA_REGISTRY_HISTORY where ACTION_TIME is not null order by action_time desc) where ROWNUM = 1)
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
SET dNFSenabled = (select decode(count(*), 0, 'No', 'Yes') from v$dnfs_servers)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET dbSizeTB = (select round(sum(bytes)/1024/1024/1024/1024,6) bytes from dba_segments)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET allocated_dbSizeTB = (select round(sum(bytes)/1024/1024/1024/1024,6) BYTES from v$datafile)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

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

UPDATE rubrikDataCollection rbk
SET GoldenGate = (select decode(count(*), 0, 'No', 'Yes') from v$archive_dest where status = 'VALID' and target = 'STANDBY')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET exadataEnabled = (select decode(count(*), 0, 'No', 'Yes') from v$cell)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET bctEnabled = (select status from v$block_change_tracking)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET LogArchiveConfig = (SELECT value from v$parameter where name='log_archive_config')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET LogArchiveConfig = 'NO'
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and LogArchiveConfig is null;

UPDATE rubrikDataCollection rbk
SET ArchiveLagTarget = (SELECT value from v$parameter where name='archive_lag_target')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);	

UPDATE rubrikDataCollection rbk
SET tablespaceCount = (select count(*)  from v$tablespace)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET encryptedTablespaceCount = (select count(*) from dba_tablespaces where encrypted='YES')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET encryptedDataSizeTB = (select round(sum(bytes)/1024/1024/1024/1024,6) from (select sum(bytes) bytes from dba_data_files dbf, dba_tablespaces tbsp where dbf.tablespace_name=tbsp.tablespace_name and tbsp.encrypted='YES'))
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET encryptedDataSizeTB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and encryptedDataSizeTB is null;

UPDATE rubrikDataCollection rbk
SET bigfileTablespaceCount = (select count(*) from dba_tablespaces where bigfile='YES')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET biggestBigfileGB = (select round(sum(bytes)/1024/1024/1024,6) from (select max(bytes) bytes from dba_data_files dbf, dba_tablespaces tbsp where dbf.tablespace_name=tbsp.tablespace_name and tbsp.bigfile='YES'))
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET biggestBigfileGB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and biggestBigfileGB is null;

UPDATE rubrikDataCollection rbk
SET bigfileDataSizeGB = (select round(sum(bytes)/1024/1024/1024,6) from (select sum(bytes) bytes from dba_data_files dbf, dba_tablespaces tbsp where dbf.tablespace_name=tbsp.tablespace_name and tbsp.bigfile='YES'))
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET bigfileDataSizeGB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and bigfileDataSizeGB is null;

-- 20220310 smcelhinney removing division by 100 from dailyChangeRate as it negatively skews change rate
-- 20230321 updated change rate calculations to leverage dba_segments to determine actual space USED instead of ALLOCATED -  smcelhinney
-- Segment bytes (s) and average daily redo (r) are each reduced to a single value before they
-- are combined. The earlier form joined dba_segments to the archived-log rows with no join
-- condition, which multiplied sum(bytes) by the number of redo-day rows and understated the rate.
UPDATE rubrikDataCollection rbk
SET dailyChangeRate = (select round(r.avgRedo / nullif(s.bytes, 0), 8) from (select sum(bytes) bytes from dba_segments) s, (select avg(redo_size) avgRedo from (select trunc(completion_time) rundate, sum(blocks*block_size) redo_size from v$archived_log where first_time > sysdate - 7 group by trunc(completion_time))) r)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET datafileCount = (select count(*) from v$datafile)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET logfileCount = (select count(*) from v$logfile)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET logfileCount = (select count(*) from v$logfile)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET tempfileCount = (select count(*) from v$tempfile)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

-- 20230322 - dailyRedoSize query originally changed to report MB; since v2.0 it reports TB (dailyRedoSizeTB) - smcelhinney
UPDATE rubrikDataCollection rbk
SET dailyRedoSizeTB = (select round(dailyRedoSizeTB/1024/1024/1024/1024,6) from (select avg(redo_size) dailyRedoSizeTB from (select trunc(completion_time) rundate, sum(blocks*block_size) redo_size from v$archived_log where first_time > sysdate - 7 group by trunc(completion_time))))
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET dailyRedoSizeTB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and dailyRedoSizeTB is null;


-- update temp table with con_name for recorded con_id
update rubrikDataCollection rbk set con_id=0 where con_id is null;

commit;

-- format data collected for json output
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

select con_id ||chr(9)|| conName ||chr(9)|| dbSizeTB ||chr(9)|| allocated_dbSizeTB ||chr(9)||
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
