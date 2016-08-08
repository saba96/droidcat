#!/bin/bash

cat benign-ext-highcov.10m.trainedFamilies |\
	while read fam;
	do
		echo "Results for family $fam ..."
		#python multipleModels_tab_perFamily.py false false "$fam" 2>/dev/null
		python multipleModels_tab_perFamily.py false true "$fam" 2>/dev/null
	done

exit 0
