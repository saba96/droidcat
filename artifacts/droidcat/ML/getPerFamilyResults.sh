#!/bin/bash

#cat benign-ext-highcov.10m.trainedFamilies |\
#cat nontrivialFamilies |\
cat nontrivialFamilies.highcov.10m |\
	while read famline;
	do
        fam=`echo $famline | awk '{print $1}'`

		echo "Accuracy Results for family $fam ..."
		#python multipleModels_tab_perFamily.py false false "$fam" 2>/dev/null
		#python multipleModels_tab_perFamily.py false true "$fam" 2>/dev/null
		python multipleModels_loo_perFamily.py false true "$fam" 2>/dev/null

		#echo "Precion/Recall/F1 Results for family $fam ..."
		#python multipleModels_loo_perFamily.py false false "$fam" 2>/dev/null

	done

exit 0
