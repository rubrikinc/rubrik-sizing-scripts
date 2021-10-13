#!/bin/bash

#####
#
# name: dataCollector.sh 
#
# version: 1.0
# 
# assumptions: This utility assumes that the dba has access to the following information:
# 	- SYSTEM account is used to access required dba* and v$* views
#	- Hostname of all database hosts
#	- Database Listener port for all databases 
#	- Database Service Name for all databases
#	- Database version is provided for databases (11g, 12c, 19c, etc)
#	- access to sqlplus on the host executing the utility
# 
# description: shell script to collect data on all Oracle databases defined as input
#
# input: collectionInput.lst -- a comma separated input file containing the following input:
# 	databaseHostname,dbPort,dbServiceName,dbRelease
# 	a unique entry should exist for EACH database requiring data collection
#
# output: rbkDiscovery.csv -- a comma separated list of critical database information required
# 	for properly sizing Oracle databases on Rubrik.
#
# additional files: rbkDataCollection.sql -- the sql file executed to collect database information
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
echo $OH
export ORACLE_HOME=$OH
export PATH=$PATH:$ORACLE_HOME/bin
FILE=`which sqlplus`
echo $FILE
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

	IFS=' '

	# collect values to create connect string to databases listed
	cat $INPUT | while read host port sid dbversion junk
	do
		echo "Connecting to database: "$sid
		echo $dbversion
		unset passwd
		unset login
		unset sql
		unset runSql
		#echo "-n Enter SYSTEM password for database "$sid" and press [ENTER]:"
		#printf '%s' "Enter the SYSTEM Password for database "$sid" and press [ENTER]: "
		echo "Enter SYSTEM password"
		read -s passwd < /dev/tty
		login=system/$passwd
		
# determine database version from collectionInput.lst & set appropriate sql script for execution
		if test "$dbversion" = "11g"
		then
			sql="rbkDataCollection_11g.sql"
		else		
			sql="rbkDataCollection.sql"
		fi
		echo $sql
		# build sqlplus connection command based on collectionInput
		runSql="sqlplus "$login"@\"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST="$host")(PORT="$port"))(CONNECT_DATA=(SID="$sid")))\" @"$sql""
		# execute the resulting sqlplus command
		eval "$runSql" 
		done
else
        echo "$INPUT is empty."
	exit 3;
fi

exit; 
