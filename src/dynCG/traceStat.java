/**
 * File: src/dynCG/traceStat.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 12/10/15		hcai		created; for parsing traces and calculating statistics 
 * 01/05/16		hcai		the first basic, working version
 * 01/13/16		hcai		added call site tracking for each ICC instance
*/
package dynCG;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jgrapht.*;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.alg.*;
import org.jgrapht.traverse.*;

import android.content.Intent;
import dynCG.callGraph.CGEdge;
import iacUtil.iccAPICom;

public class traceStat {
	
	private String appPackname=""; // package name set in the Manifest file
	traceStat (String _traceFn, String packname) {
		appPackname = packname;
		this.traceFn = _traceFn;
	}
	
	private String traceFn; // name of trace file
	public traceStat (String _traceFn) {
		this.traceFn = _traceFn;
	}
	
	public traceStat () {
		traceFn = null;
	}
	public void setPackagename (String packname) { this.appPackname = packname; }
	public void setTracefile (String tfname) { this.traceFn = tfname; }
	
	public static class ICCIntent { //extends Intent {
		public static final String INTENT_SENT_DELIMIT = "[ Intent sent ]";
		public static final String INTENT_RECV_DELIMIT = "[ Intent received ]";
		public static final String[] fdnames = {
			"Action", "Categories", "PackageName", "DataString", "DataURI", "Scheme", "Flags", "Type", "Extras", "Component"};
		public int ts;
		/*
		String action = null;
		String packagename = null;
		String data = null;
		String uri = null;
		String scheme = null;
		String flags = null;
		String type = null;
		String extras = null;
		String component = null;
		*/
		protected boolean bExternal = true;
		protected boolean bIncoming = false;
		public void setExternal (boolean _bv) { bExternal = _bv; }
		public void setIncoming (boolean _bv) { bIncoming = _bv; }
		// mapping from intent field name to field value
		protected Map<String, String> fields = new HashMap<String, String>();
		
		protected String callsite; // the call site that sends or receives this Intent

		ICCIntent() {
			for (String fdname : fdnames) {
				fields.put(fdname, "null");
			}
			ts = -1;
			callsite = "";
		}
		
		public String toString() {
			String ret = fields.toString() + "\n";
			ret += "ts: " + this.ts + "\n";
			ret += "External ICC: " + bExternal + "\n";
			ret += "Incoming ICC: " + bIncoming + "\n";
			ret += "Explicit ICC: " + isExplicit() + "\n";
			ret += "HasExtras: " + hasExtras() + "\n";
			ret += "call site: " + callsite + "\n";
			return ret;
		}
		
		// instantiate from a list of field values in the trace
		ICCIntent (List<String> infolines) {
			this();
			for (int i=0; i<infolines.size(); ++i) {
				String line = infolines.get(i).trim();
				for (String fdname : fdnames) {
					String prefix = fdname + "=";
					if (line.startsWith(prefix)) {
						String fdval = line.substring(line.indexOf(prefix) + prefix.length());
						if (fdname.compareTo("Categories")==0 && fdval.compareTo("null")!=0) {
							String _fdval = "";
							for (int j = 0; j < Integer.valueOf(fdval); ++j) {
								line = infolines.get(++i).trim();
								_fdval += line; 
								if (j>0) _fdval += ";";
							}
							fdval = _fdval;
						}
						fields.put(fdname, fdval);
						break;
					}
				}
			}
		}
		
		public void setTS (int _ts) { this.ts = _ts; }
		public int getTS () { return this.ts; }
		
		public String getCallsite() { return callsite; }
		public void setCallsite (String stmt) { callsite = stmt; }
		
		public boolean isExplicit () {
			return fields.get("Component").compareTo("null")!=0;
		}
		
		public boolean hasExtras () {
			return fields.get("Extras").compareTo("null")!=0;
		}
		
		public boolean hasData() {
			return (fields.get("DataString").compareTo("null")!=0) || (fields.get("DataURI").compareTo("null")!=0);
		}
		
		public boolean isExternal() {
			return bExternal;
		}
		public boolean isIncoming() {
			return bIncoming;
		}
		
		public String getFields (String fdname) {
			return fields.get(fdname);
		}
	}
	
	private callGraph cg = new callGraph();
	private List<ICCIntent> allIntents = new ArrayList<ICCIntent>();
	
	public callGraph getCG () { return cg; }
	public List<ICCIntent> getAllICCs () { return allIntents; }
	
	protected ICCIntent readIntentBlock(BufferedReader br) throws IOException {
		List<String> infolines = new ArrayList<String>();
		/*
		int i = 1;
		int total = ICCIntent.fdnames.length;
		String line = null;
		while (i <= total) {
			line = br.readLine();
			if (line == null) break;
			line = line.trim();
			infolines.add(line);
			if (line.startsWith("Categories") && !line.endsWith("=null")) {
				total += Integer.valueOf(line.substring(line.indexOf('=')+1));
			}
			i++;
		}
		*/
		br.mark(1000);
		String line = br.readLine().trim();
		
		while (line != null) {
			boolean stop = true;;
			for (String fdname : ICCIntent.fdnames) {
				if (line.startsWith(fdname)) {
					infolines.add(line);
					if (fdname.equalsIgnoreCase("Categories") && !line.endsWith("=null")) {
						int ninnerlns = Integer.valueOf(line.substring(line.indexOf('=')+1));
						for (int k=0; k < ninnerlns; ++k) {
							infolines.add(br.readLine().trim());
						}
					}
					stop = false;
					break;
				}
			}
			if (stop) break;
			br.mark(1000);
			line = br.readLine().trim();
		}
		
		// not enough lines read for an expected intent block
		if (null == line) {
			throw new IOException("unexpected end reached before reading an Intent object block");
		}
		br.reset();
		
		return new ICCIntent (infolines);
	}
	
	protected int parseTrace (String fnTrace) {
		try {
			BufferedReader br = new BufferedReader (new FileReader(fnTrace));
			String line = br.readLine().trim();
			int ts = 0; // time stamp, for ordering all the method and ICC calls
			while (line != null) {
				// try to retrieve a block of intent info
				boolean boutICC = line.contains(ICCIntent.INTENT_SENT_DELIMIT);
				boolean binICC = line.contains(ICCIntent.INTENT_RECV_DELIMIT);
				if (boutICC || binICC) {
					ICCIntent itn = readIntentBlock(br);
					itn.setIncoming(binICC);
					
					//if (comp != null && comp.contains(appPackname)) {
					// look ahead one more line to find the receiver component
					line = br.readLine().trim();
					if (line.contains(callGraph.CALL_DELIMIT)) {
						CGEdge ne = cg.addCall(line,ts);
						ts ++;
						
						if (binICC) {
							if (iccAPICom.is_IntentReceivingAPI(ne.getTarget().getMethodName())) {
								itn.setCallsite(ne.toString());
							}
							
							String comp = itn.getFields("Component");
							if (comp != null) {
								//String recvCls = line.substring(line.indexOf('<')+1, line.indexOf(": "));
								String recvCls = ne.getSource().getSootClassName();
								if (!this.appPackname.isEmpty()) {
									recvCls = this.appPackname;
								}
								if (comp.contains(recvCls)) {
									itn.setExternal(false);
								}
							}
						}
						else { // outgoing ICC
							if (iccAPICom.is_IntentSendingAPI(ne.getTarget().getMethodName())) {
								itn.setCallsite(ne.getTarget().getSootMethodName());
							}
						}
					}
					
					itn.setTS(ts);
					ts ++;
					allIntents.add(itn);
					
					line = br.readLine().trim();
					continue;
				}
				
				// try to retrieve a call line
				if (line.contains(callGraph.CALL_DELIMIT)) {
					cg.addCall(line,ts);
					ts ++;
				}
				
				// others
				line = br.readLine();
			}
		} catch (FileNotFoundException e) {
			System.err.println("DID NOT find the given file " + fnTrace);
			e.printStackTrace();
			return -1;
		} catch (IOException e) {
			System.err.println("ERROR in reading trace from given file " + fnTrace);
			e.printStackTrace();
			return -1;
		}
		
		return 0;
	}
	
	public void dumpInternals() {
		System.out.println("=== " + allIntents.size() + " Intents === ");
		for (int k = 0; k < allIntents.size(); k++) {
			System.out.println(allIntents.get(k));
		}
		System.out.println(this.cg);
		this.cg.listEdgeByFrequency();
		this.cg.listCallers();
		this.cg.listCallees();
	}
	
	public void stat() {
		if (this.traceFn == null) return;
		parseTrace (this.traceFn);
	}

	public static void main(String[] args) {
		// at least one argument is required: trace file name
		if (args.length < 1) {
			System.err.println("too few arguments.");
			return;
		}

		traceStat stater = new traceStat (args[0]);
		stater.stat();
		
		stater.dumpInternals();

		return;
	}
}

/* vim :set ts=4 tw=4 tws=4 */

