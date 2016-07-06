#for rep in firstrep secondrep thirdrep
#do
	#rep="singleAppLogs_benign_set2_highcov_10m"
	rep="singleAppLogs_benign_set1_highcov_10m"
	for category in explicit implicit
	do
		#allSecurityReport_new.sh benign-new-$rep $category
		allSecurityReport_new.sh $rep $category
	done
#done
exit 0
