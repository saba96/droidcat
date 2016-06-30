for rep in firstrep secondrep thirdrep
do
	for category in explicit implicit
	do
		#allGeneralReport_new.sh benign-new-$rep $category
		allGeneralReport_new.sh $rep $category
	done
done
exit 0
