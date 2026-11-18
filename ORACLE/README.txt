##########
#
# Rubrik Data Collection for Oracle Tooling
#
# Version: 2.2
#
# Developer: Shawn McElhinney
#
# Purpose:
# This utility is designed to collect data from Oracle databases to assist with Rubrik solution sizing.
# NOTE: Starting with v2.3, all output from this utility will be managed by an Oracle sizing Claude Cowork skill.
# The utility will connect to the databases you define in collectionInput.lst and execute the appropriate rbkDataCollection.sql (based on your db version) to gather the data required 
# to begin properly sizing your Rubrik solution for Oracle.
#
# Component files:
# collectionInput.lst -- a space-separated list of the databases in your landscape. Simply provide single line entries for each database in the following format:
# hostname databasePort OracleSID databaseRelease
# where databaseRelease is in a 3 digit format representing MAJOR and DOT release. For example: 10gR2 -> 102; 11gR2 -> 112; 12cR1 -> 121 etc.
# save this file after update as it will be an input for the shell script.
#
# rbkDataCollection.sql -- sql script that collects pertinent database information to assist with sizing Rubrik for Oracle and dump output to a tab-delimited file named rbkDiscovery-v2.csv. Fields are tab-delimited (not comma) since several collected values, such as LOGARCHIVECONFIG and PATCHLEVEL, can legitimately contain commas.
#
# dataCollector.sh -- This script will verify the existence of SQL*Plus, read through collectioInput.lst, execute rbkDataCollection.sql, and write the rbkDiscovery-v2.csv header once at the start of a fresh collection run. At runtime, user will be prompted to enter the SYSTEM password for the associated databases. Output from the sql queries are appended to rbkDiscovery-v2.csv, which is what your Rubrik Sales Engineer will require to help with sizing.
#
# dataCollector.ps1 -- Windows (PowerShell) equivalent of dataCollector.sh. Same input file, same sql scripts, same rbkDiscovery-v2.csv output, and the same SYSTEM password prompt per database (read as a SecureString and passed to SQL*Plus over stdin, never on the command line). Use it when the machine running the collection is Windows. The OS the databases run on does not matter for either script: both connect over the network, so either collector works against Oracle on Windows, Linux, or Unix.
#
# Execution Steps:
# 1 - Update collectionInput.lst file with all Oracle databases that will be integrated with Rubrik. Enter the hostname, databasePort, ORACLE_SID and version for each instance or CDB (please check the expected format in collectionInput.lst-EXAMPLE file). If you utilizes PDB's in 12c+, the script will gather information for all PDBs that are installed in the CDB, plus one extra rollup row (CON_ID=0, CONNAME = the CDB name) summarizing the whole CDB as a single database -- CON_ID=0 identifies exactly one row per database, whether it's a CDB or a standalone (11g-style) instance. If you utilizes RAC cluster, please add the instances of one node only.
#
# 2 - Ensure you have the SYSTEM password for all databases referenced in collectionInput.lst file. NOTE: a SYSTEM password containing a double quote (") will break the CONNECT command and the collection for that database will fail. Use a password without a double quote, or temporarily change the password for the collection run.
#
# 3 - Execute dataCollector.sh from an interactive terminal session (not cron, or ssh without a pty) and provide the SYSTEM password when prompted for each database listed in collectionInput.lst. The password is read directly from the terminal and is never passed on a command line or logged.
#
# 4 - Compress the resulting rbkDiscovery-v2.csv & work with your Rubrik Sales Engineer to transfer the file to them via the most secure mechanism available.
#
# Running on Windows:
# Prerequisites: Windows PowerShell 5.1 or PowerShell 7+, and SQL*Plus -- either a full Oracle client/database home, or Oracle Instant Client (Basic + SQL*Plus packages) -- plus network access to each database listener.
# 1 - Update collectionInput.lst exactly as in step 1 above; the format is identical.
# 2 - Open an interactive PowerShell window and run, from the ORACLE folder:
#       powershell -ExecutionPolicy Bypass -File .\dataCollector.ps1
#     If sqlplus.exe is not on the PATH or under %ORACLE_HOME%, you will be prompted for its folder, or pass it up front:
#       powershell -ExecutionPolicy Bypass -File .\dataCollector.ps1 -SqlPlusPath C:\oracle\instantclient_19_21
# 3 - Enter the SYSTEM password when prompted for each database. On Windows, a password containing a double quote (") or a non-ASCII character is rejected up front, since it cannot be passed to the CONNECT command safely.
# 4 - Send rbkDiscovery-v2.csv as in step 4 above. A Windows run writes CRLF line endings; a dataCollector.sh run writes LF.
# NOTE: the duplicate-row check compares hosts by short name and ignores case, because Windows databases typically report v$instance.host_name as an upper-case short name (e.g. DBHOST01) even when collectionInput.lst uses a lower-case FQDN.
#
##########
#
# Changes since 2.2 (2026-11-11):
#
# - Renamed the output file from rbkDiscovery.csv to rbkDiscovery-v2.csv. dataCollector.sh, all
#   four rbkDataCollection*.sql variants, and this README now use the new name. Existing
#   rbkDiscovery.csv files from earlier runs are not renamed automatically.
# - Starting with v2.3, all output from these scripts will be managed by an Oracle sizing Claude
#   Cowork skill.
# - Added dataCollector.ps1, a PowerShell collector for running the collection from a Windows
#   machine. It uses the same collectionInput.lst, rbkDataCollection*.sql scripts, and
#   rbkDiscovery-v2.csv output as dataCollector.sh; no sql script changes were needed for it.
# - Added .gitattributes to keep dataCollector.sh LF and dataCollector.ps1 CRLF on checkout.
# - Fixed DAILYCHANGERATE being blank on the CON_ID=0 rollup row in rbkDataCollection.sql,
#   _121.sql, and _12c.sql. The rollup row is now calculated as the root container's
#   DAILYREDOSIZETB (redo is only maintained at the root, and already covers the whole CDB)
#   divided by the cumulative DBSIZETB of ALL pluggables (CON_ID>2, excluding CDB$ROOT and
#   PDB$SEED -- the same population that DBSIZETB on the rollup row sums). A CDB with no PDBs
#   plugged in yet reports 0.
# - Fixed DAILYCHANGERATE being understated on the per-container (and 11g) rows. The query joined
#   the segments view to the archived-log subquery with no join condition, so every segment row
#   was paired with every daily-redo row: sum(bytes) was multiplied by the number of redo-day
#   rows while avg(redo_size) was not, and the rate came out low by roughly that factor (about
#   7x or more with the 7-day window). Segment bytes are now summed per container and the
#   average daily redo is reduced to a single value before the two are divided. A container
#   with zero segment bytes now reports blank instead of raising a divide-by-zero error.
#   Applies to all four rbkDataCollection*.sql scripts. Expect DAILYCHANGERATE to be noticeably
#   higher than in earlier versions for the same database; values collected before this change
#   are not comparable.
# - Tested against a 19c CDB with 8 PDBs (rbkDataCollection.sql and _12c.sql; the _121 and _11g
#   scripts were not run). The CON_ID=0 DAILYCHANGERATE equals the root DAILYREDOSIZETB divided
#   by the sum of the PDB DBSIZETB values, and the per-container rates are exactly 4x the
#   pre-fix values, matching the number of redo-day rows the old join multiplied by.
#
# KNOWN LIMITATIONS (how to read DAILYCHANGERATE and DAILYREDOSIZETB):
# - Use the CON_ID=0 row for the database-level change rate. Redo is not tracked per PDB:
#   every v$archived_log row reports CON_ID=0, so a per-PDB redo figure cannot be collected.
#   The per-container DAILYCHANGERATE rows are therefore the CDB-wide average daily redo divided
#   by that container's own used space, NOT that container's own change rate. A small PDB
#   will show a very high value, and the CDB$ROOT row (a tiny used size) is not meaningful.
# - DAILYREDOSIZETB sums v$archived_log for every archive destination. A database that archives
#   to a standby or a second local destination has one row per log per destination, so its redo
#   is counted once per destination (twice with one standby). DAILYCHANGERATE is overstated by
#   the same factor. Verified on the test CDB: 75 logs on dest_id 1 and 75 on dest_id 2 (a
#   standby), identical sizes. Not yet fixed; the plan below addresses it.
# - DAILYREDOSIZETB is a 7-day average rounded to 6 decimal places of TB (about 1 MB), so a
#   low-redo database keeps few significant digits, and a peak-redo day cannot be seen.
#
# PLANNED FOR v2.3 (Oracle sizing Claude Cowork skill hand-off):
# - The skill will calculate change rate itself from DBSIZETB (used segment space, collected for
#   every container) and DAILYREDOSIZETB, so the formula can change without asking customers
#   to re-run collection. Until then, treat the DAILYCHANGERATE column as informational.
# - DAILYCHANGERATE is planned to be removed and replaced with better redo inputs: higher
#   precision, a peak daily value, the number of days in the window, and redo counted for a
#   single archive destination. This will be the next change to the output layout, made once
#   alongside the skill.
#
##########
#
# Version 2.2 Updates (2026-09-10):
#
# - Fixed DBSIZETB returning the same (wrong) value for every PDB in a CDB. It was built on
#   plain dba_segments, which is not container-spanning -- queried from root, every row it
#   returns is tagged with root's own con_id, so a PDB's con_id filter matched zero rows and
#   fell back to the null-coalesce 0. Switched to cdb_segments (wrapped in CONTAINERS() where
#   that's available -- not in the 12.1 script, since CONTAINERS() isn't available until
#   12.2), matching the pattern already used for every other DBA_-view-based per-PDB query.
# - DAILYCHANGERATE's denominator switched from allocated space (v$datafile) to actual used
#   space (cdb_segments), so it now reflects the pct of real data that changes daily instead
#   of pct of allocated-but-possibly-empty space. ALLOCATED_DBSIZETB's v$datafile query is
#   also now wrapped in CONTAINERS() (where available) for consistency/defense, though
#   v$datafile (unlike dba_segments) is reliably container-aware from root without it.
# - Confirmed functional on non-CDB databases as well as CDBs: the cdb_segments change in
#   rbkDataCollection.sql, _121.sql, and _12c.sql also returns correct sizes when run against a
#   12c+ non-CDB. rbkDataCollection_11g.sql uses dba_segments instead of cdb_segments, since
#   11g has no cdb_* views; its DAILYCHANGERATE denominator also uses dba_segments (used space).
#
##########
#
# Version 2.1 Updates (2026-09-09):
#
# - rbkDataCollection.sql, _121.sql, and _12c.sql now add one rollup row per CDB, with
#   CON_ID=0 and CONNAME set to just the CDB name (the root's own name without the
#   ".CDB$ROOT" suffix). Storage fields (DBSIZETB, ALLOCATED_DBSIZETB, ENCRYPTEDDATASIZETB,
#   DATAFILECOUNT, TABLESPACECOUNT, ENCRYPTEDTABLESPACECOUNT, BIGFILETABLESPACECOUNT,
#   BIGFILEDATASIZEGB, LOGFILECOUNT, TEMPFILECOUNT) are summed across that CDB's real PDBs
#   only (excluding CDB$ROOT and PDB$SEED, which stay as their own separate rows).
#   DAILYREDOSIZETB is copied from the root row rather than summed, since the root already
#   holds the CDB-wide redo total and summing the PDBs into it too would double-count it.
#   BIGGESTBIGFILEGB, GOLDENGATE, and EXADATAENABLED use MAX() across the root and its PDBs,
#   since those can each vary by container. Every other column is copied from the root row.
# - This makes CON_ID=0 consistently mean "one row per database" across every script
#   version: it already did for standalone (11g-style) databases, and now it does for CDBs
#   too, without removing the existing per-PDB detail rows.
#
##########
#
# Version 2.0 Updates (2026-09-03):
#
# - COMPATIBILITY WARNING: version 2.0 changed the output format in two ways that are not
#   backward compatible: (1) the field delimiter changed from comma to tab, and (2) several
#   columns were renamed and now report different units (see the renames below). Output
#   produced by any pre-2.0 version of these scripts will NOT convert correctly into the 2.0+
#   tab-delimited layout and column names that downstream analysis expects. Re-run data
#   collection with the current scripts rather than trying to convert old output.
#   Renamed columns:
#     DBSIZEMB              -> DBSIZETB
#     ALLOCATED_DBSIZEMB    -> ALLOCATED_DBSIZETB
#     ENCRYPTEDDATASIZEMB   -> ENCRYPTEDDATASIZETB
#     DAILYREDOSIZE         -> DAILYREDOSIZETB
#     BIGGESTBIGFILEMB      -> BIGGESTBIGFILEGB
#     BIGFILEDATASIZEMB     -> BIGFILEDATASIZEGB
#     SGAMAXSIZE            -> SGAMAXSIZEGB
#     SGATARGET             -> SGATARGETGB
#     PGAAGGREGATETARGET    -> PGAAGGREGATETARGETGB
#     PHYSMEMORY            -> PHYSMEMORYGB
# - Changed the rbkDiscovery.csv field delimiter from comma to a tab character (chr(9)), since
#   some collected values (e.g. LOGARCHIVECONFIG, PATCHLEVEL) can legitimately contain commas.
#   Added SET DEFINE OFF to the SQL scripts so an "&" in a collected value is not treated as a
#   SQL*Plus substitution-variable prompt.
# - dataCollector.sh now writes the rbkDiscovery.csv header once at the start of a fresh
#   collection run, instead of the header never being generated at all.
# - DBSIZEMB, ALLOCATED_DBSIZEMB, ENCRYPTEDDATASIZEMB, and DAILYREDOSIZE are now reported in TB
#   (6 decimal places) as DBSIZETB, ALLOCATED_DBSIZETB, ENCRYPTEDDATASIZETB, and
#   DAILYREDOSIZETB. This also fixes an inconsistency where DAILYREDOSIZE was previously
#   returned in raw bytes by some script versions and in MB by others.
# - BIGGESTBIGFILEMB and BIGFILEDATASIZEMB are now reported in GB (6 decimal places) as
#   BIGGESTBIGFILEGB and BIGFILEDATASIZEGB.
# - SGAMAXSIZE, SGATARGET, PGAAGGREGATETARGET, and PHYSMEMORY are now reported in GB at full
#   precision (not rounded) as SGAMAXSIZEGB, SGATARGETGB, PGAAGGREGATETARGETGB, and
#   PHYSMEMORYGB, instead of raw bytes.
# - Fixed DBSIZETB and ALLOCATED_DBSIZETB returning blank instead of 0 for containers with no
#   visible segments or datafiles, such as PDB$SEED.
# - dataCollector.sh no longer builds the sqlplus connection string with eval, which embedded
#   the SYSTEM password directly on the command line and re-parsed it through the shell. The
#   password is now fed to sqlplus via a CONNECT statement over stdin, closing a command
#   injection risk and keeping the password out of `ps` output. A failed connection now reports
#   which database failed instead of failing silently.
# - Added WHENEVER SQLERROR EXIT SQL.SQLCODE and an exit-code check, so SQL*Plus errors (such as a
#   bad password) stop that database's collection.
# - Warns and asks for confirmation before re-collecting a host/SID that already has a row in
#   rbkDiscovery.csv, rather than silently adding a duplicate row on a rerun.
# - Validates that dbversion is numeric before selecting a sql script, and skips the entry with a
#   clear message instead of silently falling through to the newest sql script.
# - Removed the unnecessary use of cat, and quoted variable expansions so paths and values
#   containing spaces are handled correctly.
#
##########
