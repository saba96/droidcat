How to use DroidFax

1. Download apps from Google Play

scripts/smartAppDownload.sh apk-list number-of-samples

where apk-list is a text file containing the entire pool of apks (each per line) from which you want to randomly select and download up to number-of-samples apps.

2. run static analysis (including the instrumentation) of all selected apps

you can do so on an individual app using "scripts/cgInstr.sh apk-file", or using scripts/instrAll.sh to do all at once.

3. run instrumented apps (or app pairs) and generate call traces

"scripts/runAllApps_monkey.sh" for single-app executions, and "scripts/runAllPairs_monkey.sh" for inter-app executions.

4. analyze traces and compute metrics

do so for general metrics, single-app ICC metrics, inter-app ICC metrics, and security metrics using "scripts/allGeneralReport_all.sh", "scripts/allICCReport_all.sh", "scripts/allInterAppICCReport_all.sh", and "scripts/allSecurityReport_all.sh", respectively.

5. compute statistics and produce figures and tabular data results

5.1 general metrics statistics

callercalleeRanking.py - rank callers and callees by their out/in degress in the dynamic call graph
compcov.py - compute component level coverage
compdist.R - compute component distribution
covstat.py - compute coverages at class and method levels
edgefreqRanking-cdf.R - call frequency ranking plotted using CDF (cumulative distribution function)
edgefreqRanking-scatter.R - call frequency ranking plotted using stacked scatter plots
gdistcov-combine.R - compute execution composition in the unique call view, combining method and class level in one figure
gdistcovIns-combine.R - compute execution composition in the call instance view, combining method and class level in one figure
gdistcovIns.R - compute execution composition in the unique call view, producing method and class level in separate figures
gdistcov.R - compute execution composition in the call instance view, producing method and class level in separate figures
callback.R - calculate callback usage
eventHandler.R - plot event handler categorization with percentage distribution
eventHandler-tab.R - tabulate event handler categorization with percentage distribution
lifecycleMethod.R - plot lifecyle method categorization with percentage distribution
lifecycleMethod-tab.R - tabulate lifecyle method categorization with percentage distribution
5.2 ICC metrics statistics

for ICCs from single-app traces:

gicc.R - compute ICC categorization producing separate figures
gicc-combine.R - compute ICC categorization combining all plots in one figure
iccdataextras-combine.R - compute ICC data carriage combining all plots in one figure
iccdataextras.R - compute ICC data carriage producing separate figures
for ICCs from inter-app traces:

ginterIcc.R - compute ICC categorization producing separate figures
interIccDataExtras.R - compute ICC data carriage producing separate figures
5.3 security metrics and statistics

srcsink.R - calculate source and sink usage and reachable taint flow (at method level) on the dynamic call graph
src.R - plot source categorization with percentage distribution
src-tab.R - tabulate source categorization with percentage distribution
sink.R - plot sink categorization with percentage distribution
sink-tab.R - tabulate sink categorization with percentage distribution