echo "over-time detection"
time bash compute_mudflow_results_all.sh  | grep -a -E "^train on year|^data_main_test"

echo "same period detection"

time bash compute_mudflow_results_all_sameperiod.sh | grep -a -E "^train on year|^data_main_test"
