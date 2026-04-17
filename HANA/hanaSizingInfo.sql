

SELECT usage_type, SUM(used_size)/1000000000
FROM M_DISK_USAGE
where usage_type in ('DATA','LOG')
group by usage_type;

SELECT layer_name, VALUE as "BACKINT_CHANNEL_COUNT"
FROM SYS.M_INIFILE_CONTENTS
WHERE FILE_NAME = 'global.ini'
  AND LAYER_NAME != 'DEFAULT'
  AND KEY = 'parallel_data_backup_backint_channels';
