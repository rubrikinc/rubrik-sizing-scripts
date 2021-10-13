##########
#
# Rubrik Data Collection for Oracle Tooling
# 
# Version: 1.0
#
# Developer: Shawn McElhinney
#
# Purpose:
# This utility is designed to collect data from Oracle databases to assist with Rubrik solution sizing.
# The utility will connect to the databases you define in collectionInput.lst and execute the appropriate rbkDataCollection.sql (based on your db version) to gather the data required 
# to begin properly sizing your Rubrik solution for Oracle.
#
# Component files:
# collectionInput.lst -- a space-separated list of the databases in your landscape. Simply provide single line entries for each database in the following format:
# hostname databasePort OracleSID databaseRelease
# where databaseRelease is in the format 11g, 12c, etc.
# save this file after update as it will be an input for the shell script.
#
# rbkDataCollection.sql -- sql script that collects pertinent database information to assist with sizing Rubrik for Oracle and dump output to a comma-separated file named rbkDiscovery.csv.
#
# dataCollector.sh -- This script will verify the existence of SQL*Plus, read through collectioInput.lst, execute rbkDataCollection.sql. At runtime, user will be prompted to enter the SYSTEM password for the associated databases. Output from the sql queries are dumped to rbkDiscovery.csv, which is what your Rubrik Sales Engineer will require to help with sizing.
#
# Execution Steps:
# 1 - Update collectionInput.lst with all Oracle databases that will be integrated with Rubrik. Enter the hostname databasePort ORACLE_SID for each CDB, RAC Cluster or 11g instance. If you utilizes PDB's in 12c+, the script will gather information for all PDBs that are installed in the CDB.
#
# 2 - Ensure you have the SYSTEM password for all databases referenced in collectionInput.lst. 
#
# 3 - execute dataCollector.sh provide the appropriate SYSTEM password when prompted
#
# 4 - Compress the resulting rbkDiscovery.csv & work with your Rubrik Sales Engineer to transfer the file to them via the most secure mechanism available.
#
########## 
