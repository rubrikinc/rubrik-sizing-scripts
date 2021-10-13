REM Oracle Data Collection Script

-- create private temporary table to hold all  collected

create private temporary table ORA$PTT_rubrikDataCollection
	(con_id 	number,
	conName	varchar2(20),
	name   	varchar2(200),
	value   	varchar2(200),
	total		number)
on commit preserve definition;

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'executionTime', to_char(systimestamp,'YYYY-MM-DD HH24:MI:SS TZH:TZM'), null from dual);

-- no container query for v$instance
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'instName', instance_name, null from v$instance);

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'hostName', host_name, null from v$instance);

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'dbVersion', version_full, null from v$instance);

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'dbEdition', edition, null from v$instance);

-- no container query for v$database
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'platformName', platform_name, null from v$database);

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'dbName', name, null from v$database);
 
insert into ORA$PTT_rubrikDataCollection ( 
select 0, '11g', 'dbUniqueName', db_unique_name, null from v$database);

insert into ORA$PTT_rubrikDataCollection ( 
--select con_id, name, 'dbID', dbid, null  from v$containers);
select 0, '11g', 'dbID', dbid, null from v$database);

insert into ORA$PTT_rubrikDataCollection ( 
select 0, '11g', 'flashbackEnabled', flashback_on, null  from v$database);

insert into ORA$PTT_rubrikDataCollection ( 
select 0, '11g', 'archiveLogEnabled', log_mode, null  from v$database);

--no container query for dba_registry_sqlpatch
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'patchLevel', description, null from dba_registry_sqlpatch);

-- no container query for v$parameter
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'cpuCount', null, value from v$parameter where name='cpu_count');

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'blockSize', null, value from v$parameter where name='db_block_size');

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'racEnabled', value, null  from v$parameter where name = 'cluster_database');

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'sgaMaxSize', null, value from v$parameter where name='sga_max_size');

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'sgaTarget', null, value from v$parameter where name='sga_target');

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'pgaAggregateTarget', null, value from v$parameter where name='pga_aggregate_target');

-- no container query for dba_hist_osstat
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'physMemory', null, max(value) from dba_hist_osstat where stat_name = 'PHYSICAL_MEMORY_BYTES');

-- v$datafile is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection ( 
select 0, '11g', 'dbSize', null, sum(bytes) from v$datafile);
 
-- v$archive_dest is container-aware(no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'GoldenGate', decode(count(*), 0, 'No', 'Yes'), null  from v$archive_dest where status = 'VALID' and target = 'STANDBY');

-- gv$cell is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'exadataEnabled', decode(count(*), 0, 'No', 'Yes'), null  from gv$cell);

-- v$dnfs_servers is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'dNFSenabled', decode(count(*), 0, 'No', 'Yes'), null  from v$dnfs_servers);

-- v$block_change_tracking is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'bctEnabled', status, null from v$block_change_tracking);

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'tablespaceCount', null, count(*)  from v$tablespace);

-- containers clause works on dba_tablespaces 
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'encryptedTablespaceCount', null, count(*) from dba_tablespaces where encrypted='YES');

insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'bigfileTablespaceCount', null, count(*) from dba_tablespaces where bigfile='YES' );

-- containers clause works on dba_data_files and dba_tablespaces
insert into ORA$PTT_rubrikDataCollection (
select dbf.0, '11g', 'encryptedDataSize', null, sum(bytes) from dba_data_files dbf, dba_tablespaces tbsp where dbf.tablespace_name=tbsp.tablespace_name and dbf.con_id=tbsp.con_id and tbsp.encrypted='YES' group by dbf.con_id);

insert into ORA$PTT_rubrikDataCollection (
select dbf.0, '11g', 'bigfileDataSize', null, sum(bytes) from dba_data_files dbf, dba_tablespaces tbsp where dbf.tablespace_name=tbsp.tablespace_name and tbsp.bigfile='YES');

insert into ORA$PTT_rubrikDataCollection (
select dbf.0, '11g', 'dailyChangeRate', null, round((avg(redo_size)/sum(dbf.bytes))/100,8) from v$datafile dbf, (select trunc(completion_time) rundate, sum(blocks*block_size) redo_size from v$archived_log where first_time > sysdate - 7 group by trunc(completion_time)));

-- v$datafile is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'datafileCount', null, count(*) from v$datafile );

-- v$logfile is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'logfileCount', null, count(*) from v$logfile );

-- v$tempfile is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'tempfileCount', null, count(*) from v$tempfile );

-- v$archived_log is container-aware (no need for container clause)
insert into ORA$PTT_rubrikDataCollection (
select 0, '11g', 'dailyRedoSize', null, avg(redo_size) from (select con_id, trunc(completion_time) rundate, sum(blocks*block_size) redo_size from v$archived_log where first_time > sysdate - 7 group by trunc(completion_time), con_id) );

-- update temp table with con_name for recorded con_id
--update ORA$PTT_rubrikDataCollection rbk set con_id=1 where con_id=0 or con_id is null;
--update ORA$PTT_rubrikDataCollection rbk set conName=(select name from v$containers where con_id=rbk.con_id) where conName is null;

-- format data collected for json output
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
