#!/bin/bash

#####
#
# name: dataCollector.sh
#
# version: 2.0
#
# assumptions: This utility assumes that the dba has access to the following information:
# 	- SYSTEM account is used to access required dba* and v$* views
#	- Hostname of all database hosts
#	- Database Listener port for all databases 
#	- Database Service Name for all databases
#	- Database version is provided for databases as a 3 digit number representing the MAJOR (ie: 12c) and DOT (ie: 12.1) release (for example:10gR2 -> 102; 11gR2 -> 112; 12cR1 -> 121 etc. )
#	- access to sqlplus on the host executing the utility
# 
# description: shell script to collect data on all Oracle databases defined as input
#
# input: collectionInput.lst -- a comma separated input file containing the following input:
# 	databaseHostname,dbPort,dbServiceName,dbRelease
# 	a unique entry should exist for EACH database requiring data collection
#
# output: rbkDiscovery-v2.csv -- a tab-delimited list of critical database information required
# 	for properly sizing Oracle databases on Rubrik.
#
# additional files: rbkDataCollection.sql -- the sql file executed to collect database information
#
#####
#
# Version 2.0 Updates (2026-09-03):
# - Writes the rbkDiscovery-v2.csv header once at the start of a fresh collection run.
# - Replaced the eval-based sqlplus connection string, which embedded the SYSTEM password
#   directly on the command line and re-parsed it through the shell, with a CONNECT
#   statement fed to sqlplus via stdin -- closes a command injection risk and keeps the
#   password out of `ps` output.
# - Added WHENEVER SQLERROR EXIT SQL.SQLCODE plus an exit-code check so a bad password,
#   host, or connection now reports which database failed instead of failing silently.
# - Warns and asks for confirmation before re-collecting a host/SID that already has a row
#   in rbkDiscovery-v2.csv, rather than silently adding a duplicate row on a rerun.
# - Validates dbversion is numeric before selecting a sql script, and skips the entry with a
#   clear message instead of silently falling through to the newest sql script.
# - Removed the unnecessary use of cat, and quoted variable expansions throughout so paths
#   and values containing spaces are handled correctly.
#
#####

#####
#
# Validate existance of sqlplus 
#
#####
FILE=`which sqlplus`
while ! [ -f "$FILE" ]
do
echo "sqlplus not found. Please provide an ORACLE_HOME location containing sqlplus."
#accept user input
unset FILE
read OH
#update $FILE to new value & recheck
echo "$OH"
export ORACLE_HOME="$OH"
export PATH="$PATH:$ORACLE_HOME/bin"
FILE=`which sqlplus`
echo "$FILE"
done

# sleep 2

#####
# 
# Verify collectionInput.lst exists & has content
# loop through collectionInput.lst to collect required variables
#
#####

# confirm collectionInput.lst exists

echo "Checking existance of collectionInput.lst"
INPUT=collectionInput.lst

[ ! -f "$INPUT" ] && { echo "Error: $0 file not found."; exit 2; }

if [ -s "$INPUT" ]
then

	OUTPUT=rbkDiscovery-v2.csv

	# write the header once per collection run; leaves an existing file's data untouched
	if [ ! -s "$OUTPUT" ]
	then
		printf 'CON_ID\tCONNAME\tDBSIZETB\tALLOCATED_DBSIZETB\tBIGGESTBIGFILEGB\tDAILYCHANGERATE\tDAILYREDOSIZETB\tDATAFILECOUNT\tHOSTNAME\tINSTNAME\tDBVERSION\tDBEDITION\tPLATFORMNAME\tDBNAME\tDBUNIQUENAME\tDBID\tFLASHBACKENABLED\tARCHIVELOGENABLED\tSPFILE\tPATCHLEVEL\tCPUCOUNT\tBLOCKSIZE\tRACENABLED\tSGAMAXSIZEGB\tSGATARGETGB\tPGAAGGREGATETARGETGB\tPHYSMEMORYGB\tDNFSENABLED\tGOLDENGATE\tEXADATAENABLED\tBCTENABLED\tLOGARCHIVECONFIG\tARCHIVELAGTARGET\tTABLESPACECOUNT\tENCRYPTEDTABLESPACECOUNT\tENCRYPTEDDATASIZETB\tBIGFILETABLESPACECOUNT\tBIGFILEDATASIZEGB\tLOGFILECOUNT\tTEMPFILECOUNT\n' > "$OUTPUT"
	fi

	IFS=' '

	# collect values to create connect string to databases listed
	while read host port sid dbversion junk
	do
		echo "Connecting to database: $sid"
		echo "$dbversion"

		# validate dbversion up front rather than letting a malformed value fall
		# through the numeric "test" comparisons below and silently default to
		# the newest sql script
		if ! [[ "$dbversion" =~ ^[0-9]+$ ]]
		then
			echo "Skipping $sid: dbversion '$dbversion' is not a valid number. Expected a 3-digit release code (e.g. 112, 121, 193)."
			continue
		fi

		# warn if this host/SID already has a row in the output file, to avoid
		# silently creating duplicate rows on a rerun
		if [ -s "$OUTPUT" ] && awk -F'\t' -v h="$host" -v s="$sid" 'NR>1 && $9==h && $10==s {found=1} END{exit !found}' "$OUTPUT"
		then
			echo "Database $sid on host $host already has a row in $OUTPUT."
			read -p "Collect it again anyway? Duplicate rows will be added. [y/N]: " confirm < /dev/tty
			case "$confirm" in
				[Yy]*) ;;
				*) echo "Skipping $sid."; continue ;;
			esac
		fi

		unset passwd
		unset sql
		#echo "-n Enter SYSTEM password for database "$sid" and press [ENTER]:"
		#printf '%s' "Enter the SYSTEM Password for database "$sid" and press [ENTER]: "
		# NOTE: the password is wrapped in double quotes in the CONNECT statement below,
		# so a SYSTEM password that itself contains a double quote (") will break the
		# CONNECT command and the collection for that database will fail.
		echo "Enter SYSTEM password"
		read -s passwd < /dev/tty

# determine database version from collectionInput.lst & set appropriate sql script for execution
		if test "$dbversion" -lt 120
		then
			sql="rbkDataCollection_11g.sql"
		elif test "$dbversion" -lt 122
		then
			sql="rbkDataCollection_121.sql"
		elif test "$dbversion" -lt 180
		then
			sql="rbkDataCollection_12c.sql"
		else
			sql="rbkDataCollection.sql"
		fi
		echo "$sql"
		# connect via a CONNECT statement fed through stdin instead of embedding
		# the password in the sqlplus command line: keeps it out of `ps` output
		# and out of eval, so shell metacharacters in the password can't be executed
		sqlplus /nolog <<SQLPLUS_EOF
WHENEVER SQLERROR EXIT SQL.SQLCODE
CONNECT system/"${passwd}"@"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=${host})(PORT=${port}))(CONNECT_DATA=(SID=${sid})))"
@${sql}
SQLPLUS_EOF
		if [ "$?" -ne 0 ]
		then
			echo "Data collection failed for database: $sid - check the SYSTEM password and connection details."
		fi
		unset passwd
		done < "$INPUT"
else
        echo "$INPUT is empty."
	exit 3;
fi

exit; 
