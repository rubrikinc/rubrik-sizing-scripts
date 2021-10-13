REM Oracle Data Collection Script

-- connect to the system schema
--conn SYSTEM@$1

-- create private temporary table to hold all  collected

create private temporary table ORA$PTT_rubrikDataCollection
	(con_id 	number,
	conName	varchar2(200),
	name   	varchar2(200),
	value   	varchar2(200),
	total		number)
on commit preserve definition;

insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'executionTime', to_char(systimestamp,'YYYY-MM-DD HH24:MI:SS TZH:TZM'), null from dual);

-- no container query for v$instance
insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'instName', instance_name, null from v$instance);

insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'hostName', host_name, null from v$instance);

insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'dbVersion', version_full, null from v$instance);

insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'dbEdition', edition, null from v$instance);

-- no container query for v$database
insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'platformName', platform_name, null from v$database);

insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'dbName', name, null from v$database);
 
insert into ORA$PTT_rubrikDataCollection ( 
select 1, null, 'dbUniqueName', db_unique_name, null from v$database);

insert into ORA$PTT_rubrikDataCollection ( 
select con_id, name, 'dbID', dbid, null  from v$containers);

insert into ORA$PTT_rubrikDataCollection ( 
select 1, null, 'flashbackEnabled', flashback_on, null  from v$database);

insert into ORA$PTT_rubrikDataCollection ( 
select 1, null, 'archiveLogEnabled', log_mode, null  from v$database);

--no container query for dba_registry_sqlpatch
insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'patchLevel', description, null from dba_registry_sqlpatch);

-- no container query for v$parameter
insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'cpuCount', null, value from v$parameter where name='cpu_count');

insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'blockSize', null, value from v$parameter where name='db_block_size');

insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'racEnabled', value, null  from v$parameter where name = 'cluster_database');

insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'sgaMaxSize', null, value from v$parameter where name='sga_max_size');

insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'sgaTarget', null, value from v$parameter where name='sga_target');

insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'pgaAggregateTarget', null, value from v$parameter where name='pga_aggregate_target');

-- no container query for dba_hist_osstat
insert into ORA$PTT_rubrikDataCollection (
select 1, null, 'physMemory', null, max(value) from dba_hist_osstat where stat_name = 'PHYSICAL_MEMORY_BYTES');

-- v$datafile is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection ( 
select con_id, null, 'dbSize', null, sum(bytes) from v$datafile group by con_id);
 
-- v$archive_dest is container-aware(no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select con_id, null, 'GoldenGate', decode(count(*), 0, 'No', 'Yes'), null  from v$archive_dest where status = 'VALID' and target = 'STANDBY' group by con_id);

-- gv$cell is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select con_id, null, 'exadataEnabled', decode(count(*), 0, 'No', 'Yes'), null  from gv$cell group by con_id);

-- v$dnfs_servers is a global setting - no need for container info
insert into ORA$PTT_rubrikDataCollection (
select 0, null, 'dNFSenabled', decode(count(*), 0, 'No', 'Yes'), null  from v$dnfs_servers);

-- v$block_change_tracking is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select con_id, null, 'bctEnabled', status, null from v$block_change_tracking);

insert into ORA$PTT_rubrikDataCollection (
select con_id, null, 'tablespaceCount', null, count(*)  from v$tablespace group by con_id);

-- containers clause works on dba_tablespaces 
insert into ORA$PTT_rubrikDataCollection (
select con_id, null, 'encryptedTablespaceCount', null, count(*) from containers(dba_tablespaces) where encrypted='YES' group by con_id);

insert into ORA$PTT_rubrikDataCollection (
select con_id, null, 'bigfileTablespaceCount', null, count(*) from containers(dba_tablespaces) where bigfile='YES' group by con_id);

-- containers clause works on dba_data_files and dba_tablespaces
insert into ORA$PTT_rubrikDataCollection (
select dbf.con_id, null, 'encryptedDataSize', null, sum(bytes) from containers(dba_data_files) dbf, containers(dba_tablespaces) tbsp where dbf.tablespace_name=tbsp.tablespace_name and dbf.con_id=tbsp.con_id and tbsp.encrypted='YES' group by dbf.con_id);

insert into ORA$PTT_rubrikDataCollection (
select dbf.con_id, null, 'bigfileDataSize', null, sum(bytes) from containers(dba_data_files) dbf, containers(dba_tablespaces) tbsp where dbf.tablespace_name=tbsp.tablespace_name and dbf.con_id=tbsp.con_id and tbsp.bigfile='YES' group by dbf.con_id);

insert into ORA$PTT_rubrikDataCollection (
select dbf.con_id, null, 'dailyChangeRate', null, round((avg(redo_size)/sum(dbf.bytes))/100,8) from containers(v$datafile) dbf, (select con_id, trunc(completion_time) rundate, sum(blocks*block_size) redo_size from containers(v$archived_log) where first_time > sysdate - 7 group by trunc(completion_time), con_id) group by dbf.con_id);

-- v$datafile is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select con_id, null, 'datafileCount', null, count(*) from v$datafile group by con_id);

-- v$logfile is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select con_id, null, 'logfileCount', null, count(*) from v$logfile group by con_id);

-- v$tempfile is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select con_id, null, 'tempfileCount', null, count(*) from v$tempfile group by con_id);

-- v$archived_log is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select con_id, null, 'dailyRedoSize', null, avg(redo_size) from (select con_id, trunc(completion_time) rundate, sum(blocks*block_size) redo_size from v$archived_log where first_time > sysdate - 7 group by trunc(completion_time), con_id) group by con_id);

-- update temp table with con_name for recorded con_id
update ORA$PTT_rubrikDataCollection rbk set con_id=1 where con_id=0 or con_id is null;
update ORA$PTT_rubrikDataCollection rbk set conName=(select name from v$containers where con_id=rbk.con_id) where conName is null;
-- update root container and pdb seed names to include cdb database name
update ORA$PTT_rubrikDataCollection rbk set conName=(select name ||'.CDB$ROOT'from v$database) where conName='CDB$ROOT';
update ORA$PTT_rubrikDataCollection rbk set conName=(select name ||'.PDB$SEED'from v$database) where conName='PDB$SEED';
-- update remaining pdbs to append CDB name so pdb/cdb relationships are not lost in the csv
update ORA$PTT_rubrikDataCollection rbk set conName=(select name ||'.' from v$database)||conName where con_id>2;

-- format data collected for csv output
set markup csv on
set colsep ,
set headsep off
set trimspool on
set head off
set feedback off
set pagesize 0

spool rbkDiscovery.csv append

select * from ORA$PTT_rubrikDataCollection;

spool off

exit;
