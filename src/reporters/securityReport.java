/**
 * File: src/reporter/securityReport.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 01/15/16		hcai		created; reporting security related statistics
 * 01/18/16		hcai		done drafting the preliminary statistics (coverage centric only)
 * 01/23/16		hcai		added callback methods (separately for lifecycle methods and event handlers) statistics
*/
package reporters;

import iacUtil.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
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
import soot.jimple.infoflow.android.data.parsers.PermissionMethodParser;
import soot.jimple.infoflow.android.source.data.ISourceSinkDefinitionProvider;
import soot.jimple.infoflow.android.source.data.SourceSinkDefinition;
import soot.jimple.infoflow.android.source.parsers.xml.XMLSourceSinkParser;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.ExceptionalBlockGraph;
import soot.util.*;

import dynCG.*;
import dynCG.callGraph.CGNode;
import dynCG.traceStat.ICCIntent;


public class securityReport implements Extension {
	
	protected static reportOpts opts = new reportOpts();
	protected final traceStat stater = new traceStat();
	
	// gross ICC coverage statistics
	protected final covStat srcCov = new covStat("source coverage");
	protected final covStat sinkCov = new covStat("sink coverage");

	protected final covStat lifecycleCov = new covStat("lifecylce method coverage");
	protected final covStat eventhandlerCov = new covStat("event handler coverage");
	
	protected final Set<String> allCoveredClasses = new HashSet<String>();
	protected final Set<String> allCoveredMethods = new HashSet<String>();
	
	String packName = "";
	
	Set<String> coveredSources = new HashSet<String>();
	Set<String> coveredSinks = new HashSet<String>();
	
	Set<String> allSources = new HashSet<String>();
	Set<String> allSinks = new HashSet<String>();
	
	Set<String> callbackClses = new HashSet<String>();
	Set<SootClass> callbackSootClses = new HashSet<SootClass>();
	
	Set<String> traversedLifecycleMethods = new HashSet<String>();
	Set<String> traversedEventHandlerMethods = new HashSet<String>();
	Set<String> coveredLifecycleMethods = new HashSet<String>();
	Set<String> coveredEventHandlerMethods = new HashSet<String>();
	
	public static void main(String args[]){
		args = preProcessArgs(opts, args);
		
		if (opts.traceFile==null || opts.traceFile.isEmpty()) {
			// nothing to do
			return;
		}
		if (opts.srcsinkFile==null || opts.srcsinkFile.isEmpty()) {
			// this report relies on an externally purveyed list of taint sources and sinks
			return;
		}
		if (opts.callbackFile ==null || opts.callbackFile.isEmpty()) {
			// this report relies on an externally purveyed list of android callback interfaces
			return;
		}

		securityReport grep = new securityReport();
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
	 * Loads the set of interfaces that are used to implement Android callback
	 * handlers from a file on disk
	 * @return A set containing the names of the interfaces that are used to
	 * implement Android callback handlers
	 */
	private Set<String> loadAndroidCallbacks() throws IOException {
		Set<String> androidCallbacks = new HashSet<String>();
		BufferedReader rdr = null;
		try {
			String fileName = opts.callbackFile;
			if (!new File(fileName).exists()) {
				throw new RuntimeException("Callback definition file not found");
			}
			rdr = new BufferedReader(new FileReader(fileName));
			String line;
			while ((line = rdr.readLine()) != null)
				if (!line.isEmpty())
					androidCallbacks.add(line);
		}
		finally {
			if (rdr != null)
				rdr.close();
		}
		return androidCallbacks;
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
		
		ISourceSinkDefinitionProvider parser = null;
		String sourceSinkFile = opts.srcsinkFile;

		String fileExtension = sourceSinkFile.substring(sourceSinkFile.lastIndexOf("."));
		fileExtension = fileExtension.toLowerCase();
		
		try {
			if (fileExtension.equals(".xml"))
				parser = XMLSourceSinkParser.fromFile(sourceSinkFile);
			else if(fileExtension.equals(".txt"))
				parser = PermissionMethodParser.fromFile(sourceSinkFile);
		}
		catch (Exception e) {
			System.err.println("Failed in parsing the source-sink file: ");
			e.printStackTrace(System.err);
			System.exit(-1);
		}
		
		
		for (SourceSinkDefinition ssdef : parser.getSources()) {
			allSources.add(ssdef.getMethod().getSignature());
		}
		for (SourceSinkDefinition ssdef : parser.getSinks()) {
			allSinks.add(ssdef.getMethod().getSignature());
		}

		Set<CGNode> allCGNodes = stater.getCG().getInternalGraph().vertexSet();
		for (CGNode n : allCGNodes) {
			if (allSources.contains(n.getSootMethodName())) {
				coveredSources.add(n.getSootMethodName());
				srcCov.incCovered();
			}
			if (allSinks.contains(n.getSootMethodName())) {
				coveredSinks.add(n.getSootMethodName());
				sinkCov.incCovered();
			}
			
			allCoveredClasses.add(n.getSootClassName());
			allCoveredMethods.add(n.getSootMethodName());
		}
		
		try {
			callbackClses.addAll(loadAndroidCallbacks());
			for (String clsname : callbackClses) {
				callbackSootClses.add( Scene.v().getSootClass(clsname) );
			}
		}
		catch (Exception e) {
			System.err.println("Failed in parsing the androidCallbacks file: ");
			e.printStackTrace(System.err);
			System.exit(-1);
		}
	}

	public boolean isCallbackClass(SootClass cls) {
		FastHierarchy har = Scene.v().getOrMakeFastHierarchy();
		for (SootClass scls : callbackSootClses) {
			if (har.getAllSubinterfaces(scls).contains(cls)) {
				return true;
			}
			if (har.getAllImplementersOfInterface(scls).contains(cls)) {
				return true;
			}
		}
		return false;
	}
	
	public void run() {
		System.out.println("Running static analysis for ICC distribution characterization");

		init();
		
		traverse();
		
		report();
		
		System.exit(0);
	}
	
	/** obtaining all statically resolved ICCs needs a separate analysis such as IC3 */ 
	Set<String> traversedSinks = new HashSet<String>();
	Set<String> traversedSources = new HashSet<String>();
		
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
			
			boolean isCallbackCls = isCallbackClass(sClass);
			
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

				if (generalReport.getComponentType(sClass).compareTo("Unknown")!=0 && 
					AndroidEntryPointConstants.isLifecycleMethod(sMethod.getName())) {
					traversedLifecycleMethods.add(meId);
					lifecycleCov.incTotal();

					if (allCoveredMethods.contains( meId )) {
						coveredLifecycleMethods.add(meId);
						lifecycleCov.incCovered();
					}
				}
				
				if (isCallbackCls && sMethod.getName().startsWith("on")) {
					traversedEventHandlerMethods.add(meId);
					eventhandlerCov.incTotal();
					
					if (allCoveredMethods.contains(meId)) {
						coveredEventHandlerMethods.add(meId);
						eventhandlerCov.incCovered();
					}
				}
				
				Body body = sMethod.retrieveActiveBody();
				PatchingChain<Unit> pchn = body.getUnits();
				
				Iterator<Unit> itchain = pchn.snapshotIterator();
				while (itchain.hasNext()) {
					Stmt s = (Stmt)itchain.next();
					if (!s.containsInvokeExpr()) {
						continue;
					}
					String calleename = s.getInvokeExpr().getMethod().getSignature();
					if (allSources.contains(calleename)) {
						traversedSources.add(calleename);
						srcCov.incTotal();
					}
					if (allSinks.contains(calleename)) {
						traversedSinks.add(calleename);
						sinkCov.incTotal();
					}
				}
				
			} // -- while (meIt.hasNext()) 
			
		} // -- while (clsIt.hasNext())
	}
	
	public void report() {
		/** report statistics for the current trace */
		
		if (opts.debugOut) {
			System.out.println(srcCov);
			System.out.println(sinkCov);
			
			System.out.println(lifecycleCov);
			System.out.println(eventhandlerCov);
		}
		
		System.out.println("*** tabulation ***");
		System.out.println("format: s_source\t s_sink\t d_source\t d_sink");
		System.out.println(srcCov.getTotal() +"\t " + sinkCov.getTotal() + "\t " + 
				srcCov.getCovered() + "\t " + sinkCov.getCovered());				

		System.out.println("format: s_lifecycle\t s_eventHandler\t d_lifecycle\t d_eventHandler");
		System.out.println(lifecycleCov.getTotal() +"\t " + eventhandlerCov.getTotal() + "\t " + 
				lifecycleCov.getCovered() + "\t " + eventhandlerCov.getCovered());				
		
		//System.out.println("*** tabulation ***");
		//System.out.println("format: int_ex_inc\t int_ex_out\t int_im_inc\t int_im_out\t ext_ex_inc\t ext_ex_out\t ext_im_inc\t ext_im_out");
		DecimalFormat df = new DecimalFormat("#.####");
	}
}  

/* vim :set ts=4 tw=4 tws=4 */

