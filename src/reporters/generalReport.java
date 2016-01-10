/**
 * File: src/reporter/generalReport.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 01/06/16		hcai		created; for computing basic android app code characteristics with 
 *                          respect to call traces gathered from executions
 * 01/07/16		hcai		added coverage statistics           
 * 01/09/16		hcai		first working version of basic (coverage related) statistics              
*/
package reporters;

import iacUtil.*;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import dua.Extension;
import dua.Forensics;
import dua.global.ProgramFlowGraph;
import dua.method.CFG;
import dua.method.CFG.CFGNode;
import dua.method.CallSite;
import dua.util.Util;

import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.ExceptionalBlockGraph;
import soot.util.*;

import dynCG.*;
import dynCG.callGraph.CGNode;


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
	protected void init() {
		packName = ProgramFlowGraph.appPackageName;
		
		// set up the trace stating agent
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
		System.out.println("Running static analysis for characterization");

		init();
		
		traverse();
		
		report();
		
		System.exit(0);
	}
	
	/** store the coverage at different levels of granularity */
	class covStat {
		public covStat () {
			covered = 0;
			total = 0;
			tag = "unknown";
		}
		public covStat(String _tag) {
			this();
			tag = _tag;
		}
		private String tag;
		private int covered;
		private int total; 
		public void incCovered (int increment) { covered += increment; }
		public void incTotal (int increment) { total += increment; }
		public void incCovered () { incCovered(1); }
		public void incTotal () { incTotal(1); }
		public int getCovered() { return covered; }
		public int getTotal() { return total; }
		public double getCoverage () {
			if (total == 0) return .0D;
			return (double)(covered * 1.0 / total); 
		}
		@Override public String toString() {
			return tag + " " + covered + " covered out of " + total + " for a coverage of " + getCoverage(); 
		}
	}
	
	Set<String> traversedClasses = new HashSet<String>();
	Set<String> traversedMethods = new HashSet<String>();
	
	public void traverse() {
		/* traverse all classes */
		Iterator<SootClass> clsIt = Scene.v().getClasses().iterator(); //ProgramFlowGraph.inst().getAppClasses().iterator();
		while (clsIt.hasNext()) {
			SootClass sClass = (SootClass) clsIt.next();
			//if ( sClass.isPhantom() ) {	continue; }
			boolean isAppCls = false, isSDKCls = false, isULCls = false;
			//if ( sClass.isApplicationClass() ) {
			if (sClass.getName().contains(packName)) {	
				appClsCov.incTotal();
				if (allCoveredClasses.contains(sClass.getName())) {
					appClsCov.incCovered();
				}
				isAppCls = true;
			}
			else {
				// differentiate user library from SDK library
				if (sClass.getName().matches(AndroidClassPattern) || sClass.getName().matches(OtherSDKClassPattern)) {
					sdkClsCov.incTotal();
					if (allCoveredClasses.contains(sClass.getName())) {
						sdkClsCov.incCovered();
					}
					isSDKCls = true;
				}
				//else if (!sClass.getName().contains(packName)) {
				else {	
					ulClsCov.incTotal();
					if (allCoveredClasses.contains(sClass.getName())) {
						ulClsCov.incCovered();
					}
					isULCls = true;
				}
			}
			traversedClasses.add(sClass.getName());
			
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
					ulMethodCov.incTotal();
					if (allCoveredMethods.contains(meId)) {
						ulMethodCov.incCovered();
					}
				}
				
				traversedMethods.add(meId);
				
			} // -- while (meIt.hasNext()) 
			
		} // -- while (clsIt.hasNext())
	}
	
	public void report() {
		/** report statistics for the current trace */
		System.out.println(appClsCov);
		System.out.println(appMethodCov);
		System.out.println(ulClsCov);
		System.out.println(ulMethodCov);
		System.out.println(sdkClsCov);
		System.out.println(sdkMethodCov);
		
		System.out.println("Total classes: " + (appClsCov.getTotal()+ulClsCov.getTotal()+sdkClsCov.getTotal()) );
		System.out.println("Covered classes: " + (appClsCov.getCovered()+ulClsCov.getCovered()+sdkClsCov.getCovered()) );
		System.out.println("Covered classes seen in the dynamic callgraph: " + allCoveredClasses.size() );
		
		System.out.println("Total methods: " + (appMethodCov.getTotal()+ulMethodCov.getTotal()+sdkMethodCov.getTotal()) );
		System.out.println("Covered methods: " + (appMethodCov.getCovered()+ulMethodCov.getCovered()+sdkMethodCov.getCovered()) );
		System.out.println("Covered methods seen in the dynamic callgraph: " + allCoveredMethods.size() );
		
		allCoveredClasses.removeAll(traversedClasses);
		System.out.println("covered classes not found during traversal: " + allCoveredClasses);
		allCoveredMethods.removeAll(traversedMethods);
		System.out.println("covered methods not found during traversal: " + allCoveredMethods);
	}
}  

/* vim :set ts=4 tw=4 tws=4 */

