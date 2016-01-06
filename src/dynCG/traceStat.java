/**
 * File: src/dynCG/traceStat.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 12/10/15		hcai		created; for parsing traces and calculating statistics 
 * 01/05/16		hcai		the first basic, working version
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

public class traceStat {
	/*
	private String appPackname; // package name set in the Manifest file
	traceStat (String packname) {
		appPackname = packname;
	}
	*/
	private String traceFn; // name of trace file
	traceStat (String _traceFn) {
		this.traceFn = _traceFn;
	}
	
	public static class ICCIntent extends Intent {
		public static final String INTENT_SENT_DELIMIT = "[ Intent sent ]";
		public static final String INTENT_RECV_DELIMIT = "[ Intent received ]";
		public static final String[] fdnames = {
			"Action", "Categories", "PackageName", "DataString", "DataURI", "Scheme", "Flags", "Type", "Extras", "Component"};
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
		protected boolean bExternal = false;
		protected boolean bIncoming = false;
		public void setExternal (boolean _bv) { bExternal = _bv; }
		public void setIncoming (boolean _bv) { bIncoming = _bv; }
		// mapping from intent field name to field value
		protected Map<String, String> fields = new HashMap<String, String>();

		ICCIntent() {
			for (String fdname : fdnames) {
				fields.put(fdname, "null");
			}
		}
		
		public String toString() {
			String ret = fields.toString() + "\n";
			ret += "External ICC: " + bExternal + "\n";
			ret += "Incoming ICC: " + bIncoming + "\n";
			ret += "Explicit ICC: " + isExplicit() + "\n";
			ret += "HasExtras: " + hasExtras() + "\n";
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
		
		public boolean isExplicit () {
			return fields.get("Component")!=null;
		}
		
		public boolean hasExtras () {
			return fields.get("Extras")!=null;
		}
		
		public boolean hasData() {
			return (fields.get("DataString")!=null) || (fields.get("DataURI")!=null);
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
	
	protected ICCIntent readIntentBlock(BufferedReader br) throws IOException {
		List<String> infolines = new ArrayList<String>();
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
		
		// not enough lines read for an expected intent block
		if (null == line) {
			throw new IOException("unexpected end reached before reading an Intent object block");
		}
		
		return new ICCIntent (infolines);
	}
	
	protected int parseTrace (String fnTrace) {
		try {
			BufferedReader br = new BufferedReader (new FileReader(fnTrace));
			String line = br.readLine().trim();
			while (line != null) {
				// try to retrieve a block of intent info
				boolean boutICC = line.contains(ICCIntent.INTENT_SENT_DELIMIT);
				boolean binICC = line.contains(ICCIntent.INTENT_RECV_DELIMIT);
				if (boutICC || binICC) {
					ICCIntent itn = readIntentBlock(br);
					itn.setIncoming(binICC);
					String comp = itn.getFields("Component");
					//if (comp != null && comp.contains(appPackname)) {
					if (comp != null && binICC) {
						// look ahead one more line to find the receiver component
						line = br.readLine().trim();
						if (line.contains(callGraph.CALL_DELIMIT)) {
							String recvCls = line.substring(line.indexOf('<')+1, line.indexOf(": "));
							if (comp.contains(recvCls)) {
								itn.setExternal(false);
							}
							cg.addCall(line);
						}
					}
					allIntents.add(itn);
					
					line = br.readLine().trim();
					continue;
				}
				
				// try to retrieve a call line
				if (line.contains(callGraph.CALL_DELIMIT)) {
					cg.addCall(line);
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
	}
	
	public void stat() {
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

