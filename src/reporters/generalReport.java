/**
 * File: src/reporter/generalReport.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 01/06/16		hcai		created; for computing basic android app code characteristics with 
 *                          respect to call traces gathered from executions
 * 01/07/16		hcai		added coverage statistics           
 * 01/09/16		hcai		first working version of basic (coverage related) statistics
 * 01/15/16		hcai		added class ranking by edge frequency and call in/out degrees; added component type distribution statistics              
*/
package reporters;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.PrintStream;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import dua.Extension;
import dua.Forensics;
import dua.global.ProgramFlowGraph;

import soot.*;

import dynCG.*;
import dynCG.callGraph.CGEdge;
import dynCG.callGraph.CGNode;
import iacUtil.iccAPICom;

public class generalReport implements Extension {
	
	protected static reportOpts opts = new reportOpts();
	protected final traceStat stater = new traceStat();
	
	protected final Set<String> allCoveredClasses = new HashSet<String>();
	protected final Set<String> allCoveredMethods = new HashSet<String>();
	
	public final static String AndroidClassPattern = "(android|com\\.example\\.android|com\\.google|com\\.android|dalvik)\\.(.)+"; 
	public final static String OtherSDKClassPattern = "(gov\\.nist|java|javax|junit|libcore|net\\.oauth|org\\.apache|org\\.ccil|org\\.javia|" +
			"org\\.jivesoftware|org\\.json|org\\.w3c|org\\.xml|sun|com\\.adobe|com\\.svox|jp\\.co\\.omronsoft|org\\.kxml2|org\\.xmlpull)\\.(.)+";

	// application code coverage statistics
	protected final covStat appClsCov = new covStat("Application Class");
	protected final covStat appMethodCov = new covStat("Application Method");
	// user/third-party library code coverage  
	protected final covStat ulClsCov = new covStat("Library Class");
	protected final covStat ulMethodCov = new covStat("Library Method");
	// framework library (Android SDK) code coverage  
	protected final covStat sdkClsCov = new covStat("SDK Class");
	protected final covStat sdkMethodCov = new covStat("SDK Method");
	
	String packName = "";

	public static void main(String args[]){
		args = preProcessArgs(opts, args);
		
		if (opts.traceFile==null || opts.traceFile.isEmpty()) {
			// nothing to do
		}

		generalReport grep = new generalReport();
		// examine catch blocks
		dua.Options.ignoreCatchBlocks = false;
		dua.Options.skipDUAAnalysis = true;
		dua.Options.modelAndroidLC = false;
		dua.Options.analyzeAndroid = true;
		
		soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_apk);
		
		//output as APK, too//-f J
		soot.options.Options.v().set_output_format(soot.options.Options.output_format_dex);
		soot.options.Options.v().set_force_overwrite(true);
		
		Scene.v().addBasicClass("com.ironsource.mobilcore.BaseFlowBasedAdUnit",SootClass.SIGNATURES);
		
		Forensics.registerExtension(grep);
		Forensics.main(args);
	}
	
	protected static String[] preProcessArgs(reportOpts _opts, String[] args) {
		opts = _opts;
		args = opts.process(args);
		
		String[] argsForDuaF;
		int offset = 0;

		argsForDuaF = new String[args.length + 2 - offset];
		System.arraycopy(args, offset, argsForDuaF, 0, args.length-offset);
		argsForDuaF[args.length+1 - offset] = "-paramdefuses";
		argsForDuaF[args.length+0 - offset] = "-keeprepbrs";
		
		return argsForDuaF;
	}
	
	/**
	 * Descendants may want to use customized event monitors
	 */
	/** mapping from component type to component classes */
	Map<String, Set<String>> sct2cc = new HashMap<String, Set<String>>();
	Map<String, Set<String>> dct2cc = new HashMap<String, Set<String>>();
	
	protected void init() {
		packName = ProgramFlowGraph.appPackageName;
		
		for (String ctn : iccAPICom.component_type_names) {
			sct2cc.put(ctn, new HashSet<String>());
			dct2cc.put(ctn, new HashSet<String>());
		}
		
		// set up the trace stating agent
		stater.setPackagename(packName);
		stater.setTracefile(opts.traceFile);
		
		// parse the trace
		stater.stat();
		
		Set<CGNode> allCGNodes = stater.getCG().getInternalGraph().vertexSet();
		for (CGNode n : allCGNodes) {
			allCoveredClasses.add(n.getSootClassName());
			allCoveredMethods.add(n.getSootMethodName());
		}
	}
	
	public void run() {
		System.out.println("Running static analysis for method/class coverage characterization");
		System.out.println(Scene.v().getPkgList());
		
		init();
		
		traverse();
		
		String dir = System.getProperty("user.dir");

		try {
			if (opts.debugOut) {
				report (System.out);
				rankingEdgeFreqByClass (System.out);
				rankingCallerByClass (System.out);
				rankingCalleeByClass (System.out);
				componentTypeDist(System.out);
			}
			else {
				String fngdistcov = dir + File.separator + "gdistcov.txt";
				PrintStream psgdistcov = new PrintStream (new FileOutputStream(fngdistcov,true));
				report(psgdistcov);

				String fnedgefreq = dir + File.separator + "edgefreq.txt";
				PrintStream psedgefreq = new PrintStream (new FileOutputStream(fnedgefreq,true));
				rankingEdgeFreqByClass(psedgefreq);
				
				String fncallerrank = dir + File.separator + "callerrank.txt";
				PrintStream pscallerrank = new PrintStream (new FileOutputStream(fncallerrank,true));
				rankingCallerByClass(pscallerrank);

				String fncalleerank = dir + File.separator + "calleerank.txt";
				PrintStream pscalleerank = new PrintStream (new FileOutputStream(fncalleerank,true));
				rankingCalleeByClass(pscalleerank);
				
				String fncompdist = dir + File.separator + "compdist.txt";
				PrintStream pscompdist = new PrintStream (new FileOutputStream(fncompdist,true));
				componentTypeDist(pscompdist);
			}
		}
		catch (Exception e) {e.printStackTrace();}
			
		System.exit(0);
	}

	Set<String> traversedClasses = new HashSet<String>();
	Set<String> traversedMethods = new HashSet<String>();
	
	Set<String> coveredAppClasses = new HashSet<String>();
	Set<String> coveredULClasses = new HashSet<String>();
	Set<String> coveredSDKClasses = new HashSet<String>();
	
	public static String getComponentType(SootClass cls) {
		FastHierarchy har = Scene.v().getOrMakeFastHierarchy();
		if (har.isSubclass(cls, iccAPICom.COMPONENT_TYPE_ACTIVITY))
			return "Activity";
		if (har.isSubclass(cls, iccAPICom.COMPONENT_TYPE_SERVICE))
			return "Service";
		if (har.isSubclass(cls, iccAPICom.COMPONENT_TYPE_RECEIVER))
			return "BroadcaseReceiver";
		if (har.isSubclass(cls, iccAPICom.COMPONENT_TYPE_PROVIDER))
			return "ContentProvider";
		return "Unknown";
	}
	
	public void traverse() {
		/* traverse all classes */
		Iterator<SootClass> clsIt = Scene.v().getClasses().iterator(); //ProgramFlowGraph.inst().getAppClasses().iterator();
		while (clsIt.hasNext()) {
			SootClass sClass = (SootClass) clsIt.next();
			if ( sClass.isPhantom() ) {	continue; }
			boolean isAppCls = false, isSDKCls = false, isULCls = false;
			//if ( sClass.isApplicationClass() ) {
			if (sClass.getName().contains(packName)) {	
				appClsCov.incTotal();
				if (allCoveredClasses.contains(sClass.getName())) {
					appClsCov.incCovered();
				}
				isAppCls = true;
				coveredAppClasses.add(sClass.getName());
			}
			else {
				// differentiate user library from SDK library
				if (sClass.getName().matches(AndroidClassPattern) || sClass.getName().matches(OtherSDKClassPattern)) {
					sdkClsCov.incTotal();
					if (allCoveredClasses.contains(sClass.getName())) {
						sdkClsCov.incCovered();
					}
					isSDKCls = true;
					coveredSDKClasses.add(sClass.getName());
				}
				//else if (!sClass.getName().contains(packName)) {
				else {	
					ulClsCov.incTotal();
					if (allCoveredClasses.contains(sClass.getName())) {
						ulClsCov.incCovered();
					}
					isULCls = true;
					coveredULClasses.add(sClass.getName());
				}
			}
			traversedClasses.add(sClass.getName());
			
			
			String ctn = getComponentType(sClass);
			if (ctn.compareTo("Unknown")!=0) {
				sct2cc.get(ctn).add( sClass.getName() );
				if (allCoveredClasses.contains(sClass.getName())) {
					dct2cc.get( ctn ).add( sClass.getName() );	
				}
			}
			
			/* traverse all methods of the class */
			Iterator<SootMethod> meIt = sClass.getMethods().iterator();
			while (meIt.hasNext()) {
				SootMethod sMethod = (SootMethod) meIt.next();
				if ( !sMethod.isConcrete() ) {
					// skip abstract methods and phantom methods, and native methods as well
					//continue; 
				}
				String meId = sMethod.getSignature();
				
				if (isAppCls) {
					appMethodCov.incTotal();
					if (allCoveredMethods.contains(meId)) {
						appMethodCov.incCovered();
					}
				}
				else if (isSDKCls ){
					sdkMethodCov.incTotal();
					if (allCoveredMethods.contains(meId)) {
						sdkMethodCov.incCovered();
					}
				}
				else {
					assert isULCls;
					ulMethodCov.incTotal();
					if (allCoveredMethods.contains(meId)) {
						ulMethodCov.incCovered();
					}
				}
				
				traversedMethods.add(meId);
				
			} // -- while (meIt.hasNext()) 
			
		} // -- while (clsIt.hasNext())
	}
	
	public void report(PrintStream os) {
		/** report statistics for the current trace */
		if (opts.debugOut) {
			os.println(appClsCov);
			os.println(appMethodCov);
			os.println(ulClsCov);
			os.println(ulMethodCov);
			os.println(sdkClsCov);
			os.println(sdkMethodCov);
		}
		
		int sclsTotal = appClsCov.getTotal()+ulClsCov.getTotal()+sdkClsCov.getTotal();
		if (opts.debugOut) {
			os.println();
			os.println("Total classes: " +  sclsTotal);
			os.print("distribution: application user-lib sdk ");
			os.println(appClsCov.getTotal()*1.0/sclsTotal + " " + ulClsCov.getTotal()*1.0/sclsTotal + " " + sdkClsCov.getTotal()*1.0/sclsTotal);
		}
		
		int dclsTotal = (appClsCov.getCovered()+ulClsCov.getCovered()+sdkClsCov.getCovered());
		if (opts.debugOut) {
			os.println("Covered classes: " +  dclsTotal);
			os.print("distribution: application user-lib sdk ");
			os.println(appClsCov.getCovered()*1.0/dclsTotal + " " + ulClsCov.getCovered()*1.0/dclsTotal + " " + sdkClsCov.getCovered()*1.0/dclsTotal);
			os.println("Covered classes seen in the dynamic callgraph: " + allCoveredClasses.size() );
		}
		
		int smeTotal = (appMethodCov.getTotal()+ulMethodCov.getTotal()+sdkMethodCov.getTotal());
		if (opts.debugOut) {
			os.println();
			os.println("Total methods: " + smeTotal);
			os.print("distribution: application user-lib sdk ");
			os.println(appMethodCov.getTotal()*1.0/smeTotal + " " + ulMethodCov.getTotal()*1.0/smeTotal + " " + sdkMethodCov.getTotal()*1.0/smeTotal);
		}
		
		int dmeTotal = (appMethodCov.getCovered()+ulMethodCov.getCovered()+sdkMethodCov.getCovered());
		if (opts.debugOut) {
			os.println("Covered methods: " +  dmeTotal);
			os.print("distribution: application user-lib sdk ");
			os.println(appMethodCov.getCovered()*1.0/dmeTotal + " " + ulMethodCov.getCovered()*1.0/dmeTotal + " " + sdkMethodCov.getCovered()*1.0/dmeTotal);
			os.println("Covered methods seen in the dynamic callgraph: " + allCoveredMethods.size() );
			
			os.println();
			allCoveredClasses.removeAll(traversedClasses);
			os.println("covered classes not found during traversal: " + allCoveredClasses);
			allCoveredMethods.removeAll(traversedMethods);
			os.println("covered methods not found during traversal: " + allCoveredMethods);
		}
		
		if (opts.debugOut) {
			os.println("*** tabulation *** ");
			os.println("format: class_app\t class_ul\t class_sdk\t class_all\t method_app\t method_ul\t method_sdk\t method_all");
		}
		DecimalFormat df = new DecimalFormat("#.####");
		
		if (opts.debugOut) {
			os.println("[static]");
		}
		os.println(appClsCov.getTotal() + "\t" + ulClsCov.getTotal() + "\t" + sdkClsCov.getTotal() + "\t" + sclsTotal + "\t" + 
						   appMethodCov.getTotal() + "\t" + ulMethodCov.getTotal() + "\t" + sdkMethodCov.getTotal() + "\t" + smeTotal);
		
		if (opts.debugOut) {
			os.println("[dynamic]");
		}
		os.println(appClsCov.getCovered() + "\t" + ulClsCov.getCovered() + "\t" + sdkClsCov.getCovered() + "\t" + dclsTotal + "\t" +
				   appMethodCov.getCovered() + "\t" + ulMethodCov.getCovered() + "\t" + sdkMethodCov.getCovered() + "\t" + dmeTotal);
		
		if (opts.debugOut) {
			os.println("[dynamic/static ratio]");
		}
		os.println(df.format(appClsCov.getCoverage()) + "\t" + df.format(ulClsCov.getCoverage()) + "\t" + df.format(sdkClsCov.getCoverage()) + "\t" + 
				df.format(1.0*dclsTotal/sclsTotal) + "\t" + 
				df.format(appMethodCov.getCoverage()) + "\t" + df.format(ulMethodCov.getCoverage()) + "\t" + df.format(sdkMethodCov.getCoverage()) + "\t" + 
				df.format(1.0*dmeTotal/smeTotal));
	}
	
	/** rank covered classes/methods by call frequency and out/in degrees */
	private String getCategory(String nameCls) {
		if (coveredAppClasses.contains(nameCls)) return "App";
		if (coveredULClasses.contains(nameCls)) return "UserLib";
		if (coveredSDKClasses.contains(nameCls)) return "SDK";
		return "Unknown";
	}

	public void rankingEdgeFreqByClass(PrintStream os) {
		List<CGEdge> orderedEdges = stater.getCG().listEdgeByFrequency(false);
		
		if (opts.debugOut) {
			os.println("*** edge frequency ranking *** ");
			os.println("format: rank\t class_source\t class_tgt");
		}
		for (CGEdge e : orderedEdges) {
			os.println(e.getFrequency() + "\t " + getCategory(e.getSource().getSootClassName()) + "\t " + getCategory(e.getTarget().getSootClassName()));
		}
	}
	public void rankingCallerByClass(PrintStream os) {
		List<CGNode> orderedCallers = stater.getCG().listCallers(false);
		if (opts.debugOut) {
			os.println("*** caller (out-degree) ranking *** ");
			os.println("format: rank\t class");
			os.println("[caller]");
		}
		for (CGNode n : orderedCallers) {
			os.println(stater.getCG().getInternalGraph().outDegreeOf(n) + "\t" + getCategory(n.getSootClassName()));
		}
	}
	public void rankingCalleeByClass(PrintStream os) {
		List<CGNode> orderedCallees = stater.getCG().listCallees(false);
		
		if (opts.debugOut) {
			os.println("*** callee (in-degree) ranking *** ");
			os.println("format: rank\t class");
			os.println("[callee]");
		}
		for (CGNode n : orderedCallees) {
			os.println(stater.getCG().getInternalGraph().inDegreeOf(n) + "\t" + getCategory(n.getSootClassName()));
		}
	}
	
	/** distribution regarding the four component types */
	public void componentTypeDist(PrintStream os) {
		if (opts.debugOut) {
			os.println("*** component type distribution *** ");
			os.println("format: activity\t service\t broadcast_receiver\t content_provider");
			os.println("[static]");
		}
		for (String ctn : iccAPICom.component_type_names) {
			os.print(sct2cc.get(ctn).size() + "\t ");
		}
		os.println();
		if (opts.debugOut) {
			os.println("[dynamic]");
		}
		for (String ctn : iccAPICom.component_type_names) {
			os.print(dct2cc.get(ctn).size() + "\t ");
		}
		os.println();
	}
}  

/* vim :set ts=4 tw=4 tws=4 */

