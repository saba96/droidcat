/**
 * File: src/eventTracker/Options.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 02/04/17		hcai		created; for instrumentation that inserts probes for monitoring all events
*/
package eventTracker;

import java.util.ArrayList;
import java.util.List;

public class Options {
	protected boolean debugOut = false;
	protected boolean dumpJimple = false;
	protected boolean instr3rdparty = false;
	
	public String catCallbackFile = null; // if this argument is given, then instrument for monitoring events also
	
	protected boolean debugOut() { return debugOut; }
	protected boolean dumpJimple() { return dumpJimple; }
	protected boolean instr3rdparty() { return instr3rdparty; }
	
	public String[] process(String[] args) {
		//args = super.process(args);
		
		List<String> argsFiltered = new ArrayList<String>();
		for (int i = 0; i < args.length; ++i) {
			String arg = args[i];

			if (arg.equals("-debug")) {
				debugOut = true;
			}
			else if (arg.equals("-dumpJimple")) {
				dumpJimple = true;
			}
			else if (arg.equals("-catcallback")) {
				catCallbackFile = args[i+1];
				i++;
			}
			else if (arg.equals("-instr3rdparty")) {
				instr3rdparty = true;
			}
			else {
				argsFiltered.add(arg);
			}
		}
		
		String[] arrArgsFilt = new String[argsFiltered.size()];
		//return super.process( (String[]) argsFiltered.toArray(arrArgsFilt) );
		return (String[]) argsFiltered.toArray(arrArgsFilt);
	}
}

/* vim :set ts=4 tw=4 tws=4 */

