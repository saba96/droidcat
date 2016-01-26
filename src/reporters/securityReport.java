/**
 * File: src/reporter/securityReport.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 01/15/16		hcai		created; reporting security related statistics
 * 01/18/16		hcai		done drafting the preliminary statistics (coverage centric only)
 * 01/23/16		hcai		added callback methods (separately for lifecycle methods and event handlers) statistics
 * 01/25/16		hcai		added the use of the exhaustive set of source/sink produced by SuSi; and categorized 
 * 							sources and sinks in the code and the traces
*/
package reporters;

import iacUtil.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
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
import soot.jimple.infoflow.android.data.AndroidMethod;
import soot.jimple.infoflow.android.data.AndroidMethod.CATEGORY;
import soot.jimple.infoflow.android.data.parsers.CategorizedAndroidSourceSinkParser;
import soot.jimple.infoflow.android.data.parsers.PermissionMethodParser;
import soot.jimple.infoflow.android.source.data.ISourceSinkDefinitionProvider;
import soot.jimple.infoflow.android.source.data.SourceSinkDefinition;
import soot.jimple.infoflow.android.source.parsers.xml.XMLSourceSinkParser;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.ExceptionalBlockGraph;
import soot.util.*;
import soot.jimple.infoflow.android.data.AndroidMethod.*;

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
	
	/** for uncategorized source/sink */
	Set<String> allSources = new HashSet<String>();
	Set<String> allSinks = new HashSet<String>();
	Set<String> traversedSinks = new HashSet<String>();
	Set<String> traversedSources = new HashSet<String>();
	Set<String> coveredSources = new HashSet<String>();
	Set<String> coveredSinks = new HashSet<String>();
	// total number of instances of src/sink being called
	int allSrcInCalls = 0;
	int allSinkInCalls = 0;
	
	/** for categorized source/sink */
	Map<String, CATEGORY> allCatSrcs = new HashMap<String,CATEGORY>();
	Map<String, CATEGORY> allCatSinks = new HashMap<String,CATEGORY>();
	Map<CATEGORY, Set<String>> traversedCatSrcs = new HashMap<CATEGORY, Set<String>>();
	Map<CATEGORY, Set<String>> traversedCatSinks = new HashMap<CATEGORY, Set<String>>();
	Map<CATEGORY, Set<String>> coveredCatSrcs = new HashMap<CATEGORY, Set<String>>();
	Map<CATEGORY, Set<String>> coveredCatSinks = new HashMap<CATEGORY, Set<String>>();
	// total number of instances of src/sink being called
	Map<CATEGORY, Integer> allCatSrcInCalls = new HashMap<CATEGORY, Integer>();
	Map<CATEGORY, Integer> allCatSinkInCalls = new HashMap<CATEGORY, Integer>();
	
	/** for method-level taint flow */
	
	
	/** for callbacks */
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
			if (opts.catsink==null || opts.catsrc==null) {
				// this report relies on an externally purveyed list of taint sources and sinks
				return;
			}
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
		
		if (opts.srcsinkFile != null) {
			readSrcSinks();
		}
		else if (opts.catsink!=null && opts.catsrc!=null) {
			readCatSrcSinks();
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
	
	protected void readSrcSinks() {
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
				
				allSrcInCalls += stater.getCG().getTotalInCalls(n.getMethodName());
			}
			if (allSinks.contains(n.getSootMethodName())) {
				coveredSinks.add(n.getSootMethodName());
				sinkCov.incCovered();
	
				allSinkInCalls += stater.getCG().getTotalInCalls(n.getMethodName());
			}
			
			allCoveredClasses.add(n.getSootClassName());
			allCoveredMethods.add(n.getSootMethodName());
		}
	}

	protected void readCatSrcSinks() {
		Set<CATEGORY> allcats = new HashSet<CATEGORY>();
		allcats.addAll(Arrays.asList(CATEGORY.ALL.getDeclaringClass().getEnumConstants()));
		CategorizedAndroidSourceSinkParser catsrcparser = 
			new CategorizedAndroidSourceSinkParser(allcats, opts.catsrc, true, false);
		CategorizedAndroidSourceSinkParser catsinkparser = 
			new CategorizedAndroidSourceSinkParser(allcats, opts.catsink, false, true);

		try {
			for (AndroidMethod am : catsrcparser.parse()) {
				allCatSrcs.put(am.getSignature(), am.getCategory());
				
			}
			for (AndroidMethod am : catsinkparser.parse()) {
				allCatSinks.put(am.getSignature(), am.getCategory());
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		Set<CGNode> allCGNodes = stater.getCG().getInternalGraph().vertexSet();
		for (CGNode n : allCGNodes) {
			String mename = n.getSootMethodName();
			if (allCatSrcs.keySet().contains(mename)) {
				srcCov.incCovered();

				CATEGORY cat = allCatSrcs.get(mename);
				Set<String> cts = coveredCatSrcs.get(cat);
				if (null==cts) {
					cts = new HashSet<String>();
					coveredCatSrcs.put(cat, cts);
				}
				cts.add(mename);
				
				Integer cct = allCatSrcInCalls.get(cat); 
				if (cct==null) {
					cct = 0;
				}
				int curn = stater.getCG().getTotalInCalls(n.getMethodName());
				cct += curn;
				allCatSrcInCalls.put(cat, cct);
				
				allSrcInCalls += curn;
			}
			if (allCatSinks.keySet().contains(mename)) {
				sinkCov.incCovered();

				CATEGORY cat = allCatSinks.get(mename);
				Set<String> cts = coveredCatSinks.get(cat);
				if (null==cts) {
					cts = new HashSet<String>();
					coveredCatSinks.put(cat, cts);
				}
				cts.add(mename);

				Integer cct = allCatSinkInCalls.get(cat); 
				if (cct==null) {
					cct = 0;
				}
				int curn = stater.getCG().getTotalInCalls(n.getMethodName());
				cct += curn;
				allCatSinkInCalls.put(cat, cct);
				
				allSinkInCalls += curn;
			}
			
			allCoveredClasses.add(n.getSootClassName());
			allCoveredMethods.add(n.getSootMethodName());
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
		System.out.println("Running static analysis for security-relevant feature characterization");

		init();
		
		traverse();
		
		String dir = System.getProperty("user.dir");

		try {
			if (opts.debugOut) {
				reportSrcSinks (System.out);
				reportCallbacks (System.out);
			}
			else {
				String fnsrcsink = dir + File.separator + "srcsink.txt";
				PrintStream pssrcsink = new PrintStream (new FileOutputStream(fnsrcsink,true));
				reportSrcSinks (pssrcsink);

				String fncb = dir + File.separator + "callback.txt";
				PrintStream pscb = new PrintStream (new FileOutputStream(fncb,true));
				reportCallbacks(pscb);
			}
		}
		catch (Exception e) {e.printStackTrace();}
		
		System.exit(0);
	}
	
	/** obtaining all statically resolved ICCs needs a separate analysis such as IC3 */ 
	
	int totalCls = 0, totalMethods = 0;
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
			totalCls ++;
			boolean isCallbackCls = isCallbackClass(sClass);
			
			/* traverse all methods of the class */
			Iterator<SootMethod> meIt = sClass.getMethods().iterator();
			while (meIt.hasNext()) {
				SootMethod sMethod = (SootMethod) meIt.next();
				String meId = sMethod.getSignature();
				
				totalMethods ++;

				if (generalReport.getComponentType(sClass).compareTo("Unknown")!=0 && 
					AndroidEntryPointConstants.isLifecycleMethod(sMethod.getSubSignature())) {
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

				if ( !sMethod.isConcrete() ) {
                    // skip abstract methods and phantom methods, and native methods as well
                    continue; 
                }
                if ( sMethod.toString().indexOf(": java.lang.Class class$") != -1 ) {
                    // don't handle reflections now either
                    //continue;
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
					
					if (opts.srcsinkFile != null) {
						if (allSources.contains(calleename)) {
							traversedSources.add(calleename);
							srcCov.incTotal();
						}
						if (allSinks.contains(calleename)) {
							traversedSinks.add(calleename);
							sinkCov.incTotal();
						}
					}
					else if (opts.catsink!=null && opts.catsrc!=null) {
						if (allCatSrcs.keySet().contains(calleename)) {
							srcCov.incTotal();

							Set<String> cts = traversedCatSrcs.get(allCatSrcs.get(calleename));
							if (null==cts) {
								cts = new HashSet<String>();
								traversedCatSrcs.put(allCatSrcs.get(calleename), cts);
							}
							cts.add(calleename);
						}
						if (allCatSinks.keySet().contains(calleename)) {
							sinkCov.incTotal();

							Set<String> cts = traversedCatSrcs.get(allCatSinks.get(calleename));
							if (null==cts) {
								cts = new HashSet<String>();
								traversedCatSinks.put(allCatSinks.get(calleename), cts);
							}
							cts.add(calleename);
						}
					}
				}
				
			} // -- while (meIt.hasNext()) 
			
		} // -- while (clsIt.hasNext())
	}
	
	public void reportSrcSinks(PrintStream os) {
		/** report statistics for the current trace */
		if (opts.debugOut) {
			os.println(srcCov);
			os.println(sinkCov);
		}
		if (opts.debugOut) {
			os.println("*** tabulation ***");
			os.println("format: s_source\t s_sink\t d_source\t d_sink\t s_all\t d_all\t d_allSrcInCall\t d_allSinkInCall");
		}
		os.println(srcCov.getTotal() +"\t " + sinkCov.getTotal() + "\t " + 
				srcCov.getCovered() + "\t " + sinkCov.getCovered() + "\t" +
				totalMethods + "\t" + allCoveredMethods.size() + "\t" +
				allSrcInCalls + "\t" + allSinkInCalls);				
		
		if (opts.catsink==null || opts.catsrc==null) {
			return;
		}

		// list src/sink by category if applicable
		os.println("[SOURCE]");
		if (opts.debugOut) {
			os.println("format: category\t s_source\t d_source\t d_allSrcInCall");
		}
		for (CATEGORY cat : traversedCatSrcs.keySet()) {
			os.println( cat + "\t" + traversedCatSrcs.get(cat) + "\t" + 
					(coveredCatSrcs.containsKey(cat)?coveredCatSrcs.get(cat).size():0) + "\t" +
					(allCatSrcInCalls.containsKey(cat)?allCatSrcInCalls.get(cat):0) );
		}

		os.println("[SINK]");
		if (opts.debugOut) {
			os.println("format: category\t s_sink\t d_sink\t d_allSinkInCall");
		}
		for (CATEGORY cat : traversedCatSinks.keySet()) {
			os.println( cat + "\t" + traversedCatSinks.get(cat) + "\t" + 
					(coveredCatSinks.containsKey(cat)?coveredCatSinks.get(cat).size():0) + "\t" +
					(allCatSinkInCalls.containsKey(cat)?allCatSinkInCalls.get(cat):0) );
		}
	}
	
	public void reportCallbacks(PrintStream os) {
		/** report statistics for the current trace */
		if (opts.debugOut) {
			os.println(lifecycleCov);
			os.println(eventhandlerCov);
		}
		
		if (opts.debugOut) {
			os.println("*** tabulation ***");
			os.println("format: s_lifecycle\t s_eventHandler\t d_lifecycle\t d_eventHandler\t s_all\t d_all");
		}
		os.println(lifecycleCov.getTotal() +"\t " + eventhandlerCov.getTotal() + "\t " + 
				lifecycleCov.getCovered() + "\t " + eventhandlerCov.getCovered() + "\t" +				
				totalMethods + "\t" + allCoveredMethods.size());				
	}
}  

/* vim :set ts=4 tw=4 tws=4 */

