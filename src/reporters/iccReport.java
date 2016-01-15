/**
 * File: src/reporter/iccReport.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 01/12/16		hcai		created; for computing ICC related statistics in android app call traces
 * 01/14/16		hcai		done the first version : mainly dynamic ICC statics
*/
package reporters;

import iacUtil.*;

import java.io.File;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;
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
	
	Set<ICCIntent> coveredInICCs = new HashSet<ICCIntent>();
	Set<ICCIntent> coveredOutICCs = new HashSet<ICCIntent>();
	
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
		stater.setPackagename(packName);
		stater.setTracefile(opts.traceFile);
		
		// parse the trace
		stater.stat();
		
		for (ICCIntent iit : stater.getAllICCs()) {
			if (iit.isIncoming()) {
				coveredInICCs.add(iit);
				
				inIccCov.incCovered();
			}
			else {
				coveredOutICCs.add(iit);
				
				outIccCov.incCovered();
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
	Map<SootMethod, Set<Stmt>> traversedInICCs = new HashMap<SootMethod, Set<Stmt>>();
	Map<SootMethod, Set<Stmt>> traversedOutICCs = new HashMap<SootMethod, Set<Stmt>>();
	
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
						Set<Stmt> sites = traversedOutICCs.get(sMethod);
						if (null==sites) {
							sites = new HashSet<Stmt>();
							traversedOutICCs.put(sMethod, sites);
						}
						sites.add(s);
					}
					else if (iccAPICom.is_IntentReceivingAPI(s)) {
						inIccCov.incTotal();
						Set<Stmt> sites = traversedInICCs.get(sMethod);
						if (null==sites) {
							sites = new HashSet<Stmt>();
							traversedInICCs.put(sMethod, sites);
						}
						sites.add(s);
					}
				}
				
			} // -- while (meIt.hasNext()) 
			
		} // -- while (clsIt.hasNext())
	}
	
	public void report() {
		/** report statistics for the current trace */
		/*
		if (opts.debugOut) {
			System.out.println(inIccCov);
			System.out.println(outIccCov);
		}
		*/
		System.out.println("*** overview ***");
		System.out.println("format: s_in\t s_out\t d_in\t d_out");
		System.out.println(inIccCov.getTotal() +"\t " + outIccCov.getTotal() + "\t " + 
				inIccCov.getCovered() + "\t " + outIccCov.getCovered());				
		
		System.out.println("*** tabulation ***");
		System.out.println("format: int_ex_inc\t int_ex_out\t int_im_inc\t int_im_out\t ext_ex_inc\t ext_ex_out\t ext_im_inc\t ext_im_out");
		DecimalFormat df = new DecimalFormat("#.####");
		
		// dynamic
		int int_ex_inc=0, int_ex_out=0, int_im_inc=0, int_im_out=0, ext_ex_inc=0, ext_ex_out=0, ext_im_inc=0, ext_im_out=0;
		for (ICCIntent itn : coveredInICCs) {
			if (itn.isExplicit()) {
				if (itn.isExternal()) ext_ex_inc ++;
				else int_ex_inc ++;
			}
			else {
				if (itn.isExternal()) ext_im_inc ++;
				else int_im_inc ++;
			}
		}
		for (ICCIntent itn : coveredOutICCs) {
			if (itn.isExplicit()) {
				if (itn.isExternal()) ext_ex_out ++;
				else int_ex_out ++;
			}
			else {
				if (itn.isExternal()) ext_im_out ++;
				else int_im_out ++;
			}
		}
		System.out.println("[ALL]");
		//System.out.println("int_ex_inc\t int_ex_out\t int_im_inc\t int_im_out\t ext_ex_inc\t ext_ex_out\t ext_im_inc\t ext_im_out");
		System.out.println(int_ex_inc+ "\t " + int_ex_out+ "\t " + int_im_inc+ "\t " + int_im_out+ "\t " + ext_ex_inc+ "\t " 
				+ ext_ex_out+ "\t " + ext_im_inc+ "\t " + ext_im_out);
		
		//// for ICC carrying data only
		int_ex_inc=0; int_ex_out=0; int_im_inc=0; int_im_out=0; ext_ex_inc=0; ext_ex_out=0; ext_im_inc=0; ext_im_out=0;
		for (ICCIntent itn : coveredInICCs) {
			if (!itn.hasData()) continue;
			if (itn.isExplicit()) {
				if (itn.isExternal()) ext_ex_inc ++;
				else int_ex_inc ++;
			}
			else {
				if (itn.isExternal()) ext_im_inc ++;
				else int_im_inc ++;
			}
		}
		for (ICCIntent itn : coveredOutICCs) {
			if (!itn.hasData()) continue;
			if (itn.isExplicit()) {
				if (itn.isExternal()) ext_ex_out ++;
				else int_ex_out ++;
			}
			else {
				if (itn.isExternal()) ext_im_out ++;
				else int_im_out ++;
			}
		}
		System.out.println("[hasData]");
		//System.out.println("int_ex_inc\t int_ex_out\t int_im_inc\t int_im_out\t ext_ex_inc\t ext_ex_out\t ext_im_inc\t ext_im_out");
		System.out.println(int_ex_inc+ "\t " + int_ex_out+ "\t " + int_im_inc+ "\t " + int_im_out+ "\t " + ext_ex_inc+ "\t " 
				+ ext_ex_out+ "\t " + ext_im_inc+ "\t " + ext_im_out);
		
		//// for ICC carrying extraData only
		int_ex_inc=0; int_ex_out=0; int_im_inc=0; int_im_out=0; ext_ex_inc=0; ext_ex_out=0; ext_im_inc=0; ext_im_out=0;
		for (ICCIntent itn : coveredInICCs) {
			if (!itn.hasExtras()) continue;
			if (itn.isExplicit()) {
				if (itn.isExternal()) ext_ex_inc ++;
				else int_ex_inc ++;
			}
			else {
				if (itn.isExternal()) ext_im_inc ++;
				else int_im_inc ++;
			}
		}
		for (ICCIntent itn : coveredOutICCs) {
			if (!itn.hasExtras()) continue;
			if (itn.isExplicit()) {
				if (itn.isExternal()) ext_ex_out ++;
				else int_ex_out ++;
			}
			else {
				if (itn.isExternal()) ext_im_out ++;
				else int_im_out ++;
			}
		}
		System.out.println("[hasExtras]");
		//System.out.println("int_ex_inc\t int_ex_out\t int_im_inc\t int_im_out\t ext_ex_inc\t ext_ex_out\t ext_im_inc\t ext_im_out");
		System.out.println(int_ex_inc+ "\t " + int_ex_out+ "\t " + int_im_inc+ "\t " + int_im_out+ "\t " + ext_ex_inc+ "\t " 
				+ ext_ex_out+ "\t " + ext_im_inc+ "\t " + ext_im_out);
	} 
}  

/* vim :set ts=4 tw=4 tws=4 */

