#!/bin/bash
#$ -cwd
#$ -q seal,free*,pub*
#$ -j y

#export RD_WORKSPACE=IdeaProjects

echo 'Extracting PAPI features...'
scripts/papi_extraction.sh $1
cd ../android-reflection-analysis
echo 'Extracting reflection features...'
./ru.sh $1
cd ../revealdroid
echo 'Extracting native external calls...'
./extract_native_external_calls.py $1
