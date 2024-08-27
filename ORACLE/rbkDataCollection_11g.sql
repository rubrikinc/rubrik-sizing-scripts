REM Oracle Data Collection Script

-- connect to the system schema
--conn SYSTEM@$1

-- create temporary table to hold all  collected

create global temporary table  rubrikDataCollection
	(
	con_id number,
	conName varchar2(128),
	dbSizeMB number,
	allocated_dbSizeMB number,
	biggestBigfileMB number,
	dailyChangeRate number,
	dailyRedoSize number,	
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
	sgaMaxSize number,
	sgaTarget number,
	pgaAggregateTarget number,
	physMemory number,
	dNFSenabled varchar2(20),
	GoldenGate varchar2(20),
	exadataEnabled varchar2(20),
	bctEnabled varchar2(20),
	LogArchiveConfig varchar2(200),
	ArchiveLagTarget number,
	tablespaceCount number,
	encryptedTablespaceCount number,
	encryptedDataSizeMB number,
	bigfileTablespaceCount number,
	bigfileDataSizeMB number,
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
SET sgaMaxSize = (SELECT value from v$parameter where name='sga_max_size')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET sgaTarget = (SELECT value from v$parameter where name='sga_target')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET pgaAggregateTarget = (SELECT value from v$parameter where name='pga_aggregate_target')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET physMemory = (SELECT max(value) from dba_hist_osstat where stat_name = 'PHYSICAL_MEMORY_BYTES')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET dNFSenabled = (select decode(count(*), 0, 'No', 'Yes') from v$dnfs_servers)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET dbSizeMB = (select sum(bytes)/1024/1024 bytes from dba_segments)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET allocated_dbSizeMB = (select sum(bytes)/1024/1024 BYTES from v$datafile)
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

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
SET encryptedDataSizeMB = (select sum(bytes/1024/1024) from (select sum(bytes) bytes from dba_data_files dbf, dba_tablespaces tbsp where dbf.tablespace_name=tbsp.tablespace_name and tbsp.encrypted='YES'))
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET encryptedDataSizeMB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and encryptedDataSizeMB is null;

UPDATE rubrikDataCollection rbk
SET bigfileTablespaceCount = (select count(*) from dba_tablespaces where bigfile='YES')
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET biggestBigfileMB = (select sum(bytes/1024/1024) from (select max(bytes) bytes from dba_data_files dbf, dba_tablespaces tbsp where dbf.tablespace_name=tbsp.tablespace_name and tbsp.bigfile='YES'))
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET biggestBigfileMB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and biggestBigfileMB is null;

UPDATE rubrikDataCollection rbk
SET bigfileDataSizeMB = (select sum(bytes/1024/1024) from (select sum(bytes) bytes from dba_data_files dbf, dba_tablespaces tbsp where dbf.tablespace_name=tbsp.tablespace_name and tbsp.bigfile='YES'))
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET bigfileDataSizeMB = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and bigfileDataSizeMB is null;

-- 20220310 smcelhinney removing division by 100 from dailyChangeRate as it negatively skews change rate
-- 20230321 updated change rate calculations to leverage cdb_segments to determine actual space USED instead of ALLOCATED -  smcelhinney
UPDATE rubrikDataCollection rbk
SET dailyChangeRate = (select dailyChangeRate from (select round((avg(redo_size)/sum(sgmt.bytes)),8) dailyChangeRate from dba_segments sgmt, (select trunc(completion_time) rundate, sum(blocks*block_size) redo_size from v$archived_log where first_time > sysdate - 7 group by trunc(completion_time))))
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

-- 20230322 - updating query to return dailyRedoSize in MB - smcelhinney
UPDATE rubrikDataCollection rbk
SET dailyRedoSize = (select dailyRedoSize from (select avg(redo_size/1024/1024) dailyRedoSize from (select trunc(completion_time) rundate, sum(blocks*block_size) redo_size from v$archived_log where first_time > sysdate - 7 group by trunc(completion_time))))
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance);

UPDATE rubrikDataCollection rbk
SET dailyRedoSize = 0
WHERE instName = (select instance_name from v$instance)
and hostName= (select host_name from v$instance)
and dailyRedoSize is null;


-- update temp table with con_name for recorded con_id
update rubrikDataCollection rbk set con_id=0 where con_id is null;

commit;

-- format data collected for json output
set linesize 32000
set colsep ,,
set headsep off
set head off
set trimspool on
set trimout on
set feedback off
set pagesize 0
set wrap off

spool rbkDiscovery.csv append

-- 20230322 - reordering query output to logically group data - smcelhinney
-- 20240827 - changing column separator to prevent data shift due to DG setting in LogArchiveConfig - smcelhinney
select con_id ||',,'||
        conName ||',,'||
        dbSizeMB ||',,'||
        allocated_dbSizeMB ||',,'||
        dailyChangeRate ||',,'||
        dailyRedoSize ||',,'||
        datafileCount ||',,'||
        tablespaceCount ||',,'||
        encryptedTablespaceCount ||',,'||
        encryptedDataSizeMB ||',,'||
        biggestBigfileMB ||',,'||
        bigfileTablespaceCount ||',,'||
        bigfileDataSizeMB ||',,'||
        blockSize ||',,'||
        hostName ||',,'||
        instName ||',,'||
        dbVersion ||',,'||
        dbEdition ||',,'||
        platformName ||',,'||
        dbName ||',,'||
        dbUniqueName ||',,'||
        dbID ||',,'||
        flashbackEnabled ||',,'||
        archiveLogEnabled ||',,'||
        spfile ||',,'||
        patchLevel ||',,'||
        cpuCount ||',,'||
        racEnabled ||',,'||
        sgaMaxSize ||',,'||
        sgaTarget ||',,'||
        pgaAggregateTarget ||',,'||
        physMemory ||',,'||
        dNFSenabled ||',,'||
        GoldenGate ||',,'||
        exadataEnabled ||',,'||
        bctEnabled ||',,'||
        LogArchiveConfig ||',,'||
        ArchiveLagTarget ||',,'||
        logfileCount ||',,'||
        tempfileCount
 from rubrikDataCollection;

spool off

truncate table rubrikDataCollection;

drop table rubrikDataCollection;

exit;
