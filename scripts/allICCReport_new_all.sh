for rep in firstrep secondrep thirdrep
do
	for category in explicit implicit
	do
		allICCReport_new.sh benign-new-$rep $category
	done
done
exit 0