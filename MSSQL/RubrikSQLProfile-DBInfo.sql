/**********************************************************
Rubrik SQL Server profile queries.
DBInfo
*********************************************************/

/**********************************************************
Get what Enterprise Features are enabled
*********************************************************/
IF OBJECT_ID('tempdb.dbo.##enterprise_features') IS NOT NULL
DROP TABLE ##enterprise_features
 
CREATE TABLE ##enterprise_features(
	ServerName	 SYSNAME,
	dbid		 SYSNAME,
	dbname       SYSNAME,
	feature_name VARCHAR(100),
	feature_id   INT
)
EXEC sp_MSforeachdb
	N' USE [?] 
	--	IF (SELECT COUNT(*) FROM sys.dm_db_persisted_sku_features) > 0 
	--	BEGIN 
	INSERT INTO ##enterprise_features 
	SELECT @@SERVERNAME, dbid=DB_ID(), dbname=DB_NAME(),feature_name,feature_id 
	FROM sys.dm_db_persisted_sku_features 
	--	END ';

/**********************************************************
Get how many database files each database has
*********************************************************/
IF OBJECT_ID('tempdb.dbo.##database_files') IS NOT NULL
DROP TABLE ##database_files
 
CREATE TABLE ##database_files(
	ServerName    SYSNAME,
	database_id   SYSNAME,
	DatabaseName  NVARCHAR(50),
	NumberOfFiles INT
)
INSERT INTO ##database_files
SELECT @@servername AS ServerName,
	database_id, 
	DB_NAME(database_id) as DatabaseName, 
	COUNT(database_id) as NumberOfFiles
FROM sys.master_files
GROUP BY database_id;
/**********************************************************
Get Availability Info
*********************************************************/
IF OBJECT_ID('tempdb.dbo.##AG_Info') IS NOT NULL
DROP TABLE ##AG_Info

CREATE TABLE ##AG_Info(
	ServerName    SYSNAME,
	DatabaseName  NVARCHAR(50),
	AG_Name NVARCHAR(50),
)
IF (SELECT cast(left(cast(serverproperty('productversion') AS VARCHAR), 4) AS DECIMAL(5, 1))) >= 11
BEGIN
    INSERT INTO ##AG_Info
    SELECT @@servername AS ServerName
        , db_name(drs.database_id) AS dbname
        , ag_name
    FROM sys.dm_hadr_database_replica_states drs
    JOIN sys.dm_hadr_name_id_map map
    ON drs.group_id = map.ag_id
END
ELSE
BEGIN   
    INSERT INTO ##AG_Info
    SELECT @@servername AS ServerName
        , null as dbname
        , null as ag_name
END;
/**********************************************************
Create the output for the server
*********************************************************/

WITH LogBackupInfo 
AS
(
    SELECT database_name
	    ,AVG(DATEDIFF(ss,backup_start_date,backup_finish_date)/1.0) AS AverageLogBackupTime
	    ,SUM(backup_size/1024.0/1024.0) AS LogBackupTotalMB
    FROM msdb.dbo.backupset
    WHERE type = 'L'
	    AND backup_finish_date > DATEADD(dd,-7,GETDATE())
    GROUP BY database_name
),
FullBackupInfo 
AS
(
    SELECT database_name
	    ,AVG(backup_size/1024.0/1024.0) AS AverageBackupSizeMB
	    ,AVG(DATEDIFF(ss,backup_start_date,backup_finish_date)/1.0) AS AverageBackupTime
    FROM msdb.dbo.backupset
    WHERE type = 'D'
    GROUP BY database_name
),
LogBackupInterval
AS
(
	SELECT a.database_name, a.backup_start_date, ISNULL( b.PrevBkpDate, a.backup_start_date ) PreviousBackupStartDate, DATEDIFF(mi,ISNULL( b.PrevBkpDate, a.backup_start_date ), a.backup_start_date) BackupInterval 
	FROM msdb.dbo.backupset a 
	OUTER APPLY (	SELECT TOP 1 backup_start_date AS  PrevBkpDate 
					FROM msdb.dbo.backupset bb WHERE bb.database_guid = a.database_guid 
						AND bb.type = a.type  AND bb.backup_start_date < a.backup_start_date and bb.backup_start_date > DATEADD(dd,-7,GETDATE()) ORDER BY bb.backup_start_date DESC) b
					WHERE type = 'L'
						AND backup_start_date > DATEADD(dd,-7,GETDATE())
),
EnterpriseFeatures
AS
(
	SELECT dbname AS 'DatabaseName'
		,[ChangeCapture]
		,[ColumnStoreIndex]
		,[Compression]
		,[MultipleFSContainers]
		,[InMemoryOLTP]
		,[Partitioning]
		,[TransparentDatabaseEncryption]
	FROM 
	(SELECT dbname, feature_name FROM   ##enterprise_features) e
	PIVOT
	( COUNT(feature_name) FOR feature_name IN ([ChangeCapture], [ColumnStoreIndex], [Compression], [MultipleFSContainers],[InMemoryOLTP],[Partitioning],[TransparentDatabaseEncryption]) )
	AS PVT
), 
DBInfo
AS
(
	select 
		db.name
		,convert(bigint,sum(mf.size/128.0)) DBTotalSizeMB

	FROM sys.databases db
	JOIN sys.master_files mf ON db.database_id = mf.database_id
	group by db.name
),
DBFiles
AS
(
	SELECT * FROM ##database_files
),
AGInfo
AS(
    SELECT * FROM ##AG_Info
)

SELECT
	@@SERVERNAME AS ServerName
    ,SERVERPROPERTY('ProductVersion') AS SQLVersion
	,db.name
	,db.recovery_model_desc
	,ISNULL(lbi.LogBackupTotalMB,0) AS SevenDayLogBackupMB
	,ISNULL(fbi.AverageBackupSizeMB,0) AS AverageFullMB
	,ISNULL(fbi.AverageBackupTime,0) AS AverageFullTimeSec
	,ISNULL(lbi.AverageLogBackupTime,0) AS AverageLogTimeSec
	,DBInfo.DBTotalSizeMB
    ,AVG(lbii.BackupInterval) AS AverageLogBackupInterval
	,ISNULL(ef.ChangeCapture,0) AS ChangeCapture
	,ISNULL(ef.ColumnStoreIndex,0) AS ColumnStoreIndex
	,ISNULL(ef.[Compression],0) AS Compression
	,ISNULL(ef.[MultipleFSContainers],0) AS FILESTREAM
	,ISNULL(ef.[InMemoryOLTP], 0) AS InMemoryOLTP
	,ISNULL(ef.[Partitioning],0) AS Partitioning
	,ISNULL(ef.[TransparentDatabaseEncryption],0) as TransparentDatabaseEncryption
	,DBFiles.NumberOfFiles
    ,AG_Name
FROM sys.databases db
JOIN DBInfo ON db.name = DBInfo.name
LEFT OUTER JOIN LogBackupInfo lbi ON db.name = lbi.database_name
LEFT OUTER JOIN FullBackupInfo fbi ON db.name = fbi.database_name
LEFT OUTER JOIN LogBackupInterval lbii ON db.name = lbii.database_name
LEFT OUTER JOIN EnterpriseFeatures ef ON db.name = ef.DatabaseName
LEFT OUTER JOIN AGInfo agi on db.name = agi.DatabaseName
JOIN DBFiles ON db.name = DBFiles.DatabaseName
WHERE db.database_id != 2
GROUP BY db.name
	,db.recovery_model_desc
	,DBInfo.DBTotalSizeMB
	,ISNULL(lbi.LogBackupTotalMB,0)
	,ISNULL(fbi.AverageBackupSizeMB,0)
	,ISNULL(fbi.AverageBackupTime,0)
	,ISNULL(lbi.AverageLogBackupTime,0)
	,ISNULL(ef.ChangeCapture,0)
	,ISNULL(ef.[ColumnStoreIndex],0)
	,ISNULL(ef.[Compression],0)
	,ISNULL(ef.[MultipleFSContainers],0)
	,ISNULL(ef.[InMemoryOLTP],0)
	,ISNULL(ef.[Partitioning],0)
	,ISNULL(ef.[TransparentDatabaseEncryption],0)
	,DBFiles.NumberOfFiles
    ,AG_Name
ORDER BY name
