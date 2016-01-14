/**
 * File: src/reporter/iccReport.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 01/12/16		hcai		created; for computing ICC related statistics in android app call traces
*/
package reporters;

import iacUtil.*;

import java.io.File;
import java.text.DecimalFormat;
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
import dynCG.traceStat.ICCIntent;


public class iccReport implements Extension {
	
	protected static reportOpts opts = new reportOpts();
	protected final traceStat stater = new traceStat();
	
	// gross ICC coverage statistics
	protected final covStat inIccCov = new covStat("Incoming ICC Coverage");
	protected final covStat outIccCov = new covStat("Outgoing ICC Coverage");
	
	String packName = "";

	public static void main(String args[]){
		args = preProcessArgs(opts, args);
		
		if (opts.traceFile==null || opts.traceFile.isEmpty()) {
			// nothing to do
		}

		iccReport grep = new iccReport();
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
		
		for (ICCIntent iit : stater.getAllICCs()) {
			if (iit.isIncoming()) {
				coveredInICCs.add(iit);
			}
			else {
				coveredOutICCs.add(iit);
			}
		}
	}
	
	public void run() {
		System.out.println("Running static analysis for ICC distribution characterization");

		init();
		
		traverse();
		
		report();
		
		System.exit(0);
	}
	
	/** obtaining all statically resolved ICCs needs a separate analysis such as IC3 */ 
	//Set<ICCIntent> traversedInICCs = new HashSet<ICCIntent>();
	//Set<ICCIntent> traversedOutICCs = new HashSet<ICCIntent>();
	Set<ICCIntent> coveredInICCs = new HashSet<ICCIntent>();
	Set<ICCIntent> coveredOutICCs = new HashSet<ICCIntent>();
	
	public void traverse() {
		/* traverse all classes */
		Iterator<SootClass> clsIt = Scene.v().getClasses().iterator(); //ProgramFlowGraph.inst().getAppClasses().iterator();
		while (clsIt.hasNext()) {
			SootClass sClass = (SootClass) clsIt.next();
			if ( sClass.isPhantom() ) {	continue; }
			boolean isAppCls = false, isSDKCls = false, isULCls = false;
			//if ( sClass.isApplicationClass() ) {
			if (sClass.getName().contains(packName)) {	
				isAppCls = true;
			}
			else {
				// differentiate user library from SDK library
				if (sClass.getName().matches(generalReport.AndroidClassPattern) || sClass.getName().matches(generalReport.OtherSDKClassPattern)) {
					isSDKCls = true;
				}
				//else if (!sClass.getName().contains(packName)) {
				else {	
					isULCls = true;
				}
			}
			
			if (!sClass.isApplicationClass()) {
				continue;
			}
			
			System.out.println("now on class " + sClass.getName());
			
			/* traverse all methods of the class */
			Iterator<SootMethod> meIt = sClass.getMethods().iterator();
			while (meIt.hasNext()) {
				SootMethod sMethod = (SootMethod) meIt.next();
				if ( !sMethod.isConcrete() ) {
                    // skip abstract methods and phantom methods, and native methods as well
                    continue; 
                }
                if ( sMethod.toString().indexOf(": java.lang.Class class$") != -1 ) {
                    // don't handle reflections now either
                    continue;
                }
				String meId = sMethod.getSignature();
				
				Body body = sMethod.retrieveActiveBody();
				PatchingChain<Unit> pchn = body.getUnits();
				
				Iterator<Unit> itchain = pchn.snapshotIterator();
				while (itchain.hasNext()) {
					Stmt s = (Stmt)itchain.next();
					if (iccAPICom.is_IntentSendingAPI(s)) {
						outIccCov.incTotal();
					}
					else if (iccAPICom.is_IntentReceivingAPI(s)) {
						inIccCov.incTotal();
					}
				}
				
			} // -- while (meIt.hasNext()) 
			
		} // -- while (clsIt.hasNext())
	}
	
	public void report() {
		/** report statistics for the current trace */
		if (opts.debugOut) {
			System.out.println(inIccCov);
			System.out.println(outIccCov);
		}
		
		System.out.println("tabulation");
		DecimalFormat df = new DecimalFormat("#.####");
	}
}  

/* vim :set ts=4 tw=4 tws=4 */

