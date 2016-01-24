/**
 * File: src/intentTracker/iccAPICom.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 09/28/15		hcai		common Android ICC API resources and relevant functionalities 
 * 10/14/15		hcai		add monitoring of intent receipts
*/
package iacUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import soot.Scene;
import soot.SootClass;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

public class iccAPICom {
	 final static String[] __IntentSendingAPIs = {
		        "startActivity",
		        "startActivities",
		        "startActivityForResult",
		        "startActivityFromChild",
		        "startActivityFromFragment",
		        "startActivityIfNeeded",
		        "startNextMatchingActivity",
		        "sendBroadcast",
		        "sendBroadcastAsUser",
		        "sendOrderedBroadcast",
		        "sendOrderedBroadcastAsUser",
		        "sendStickyBroadcast",
		        "sendStickyBroadcastAsUser",
		        "sendStickyOrderedBroadcast",
		        "sendStickyOrderedBroadcastAsUser",
		        "removeStickyBroadcast",
		        "removeStickyBroadcastAsUser",
		        "bindService",
		        "startService",
		        "stopService",
		        "startIntentSender",
		        "startIntentSenderForResult",
		        "startIntentSenderFromChild"
		    };
	 
	    final static List<String> g__IntentSendingAPIs = new ArrayList<String> (Arrays.asList(__IntentSendingAPIs));

		public static boolean is_IntentSendingAPI(Stmt u) {
			if (!u.containsInvokeExpr()) {
				return false;
			}
			InvokeExpr inv = u.getInvokeExpr();
			// simple and naive decision based on textual matching
			return g__IntentSendingAPIs.contains(inv.getMethod().getName());
		}
		
		//////////////////////////////////////////
	    final static String[] __IntentReceivingAPIs = {
	        "getIntent",
	        "getParentActivityIntent",
	    };
	    
	    final static List<String> g__IntentReceivingAPIs = new ArrayList<String> (Arrays.asList(__IntentReceivingAPIs));

		public static boolean is_IntentReceivingAPI(Stmt u) {
			if (!(u instanceof AssignStmt)) {
				return false;
			}
			if (!u.containsInvokeExpr()) {
				return false;
			}
			InvokeExpr inv = u.getInvokeExpr();
			// simple and naive decision based on textual matching
			return g__IntentReceivingAPIs.contains(inv.getMethod().getName());
		}
		
		public static boolean is_IntentReceivingAPI(String cs) {
			for (String s : g__IntentReceivingAPIs) {
				if (cs.contains(s)) return true;
			}
			return false;
		}
		
		public static boolean is_IntentSendingAPI(String cs) {
			for (String s : g__IntentSendingAPIs) {
				if (cs.contains(s)) return true;
			}
			return false;
		}
		
		public static final SootClass COMPONENT_TYPE_ACTIVITY = Scene.v().getSootClass("android.app.Activity");
		public static final SootClass COMPONENT_TYPE_SERVICE = Scene.v().getSootClass("android.app.Service");
		public static final SootClass COMPONENT_TYPE_RECEIVER = Scene.v().getSootClass("android.content.BroadcastReceiver");
		public static final SootClass COMPONENT_TYPE_PROVIDER = Scene.v().getSootClass("android.content.ContentProvider");
		public static final SootClass COMPONENT_TYPE_UNKNOWN = Scene.v().getSootClass("java.lang.Object");
		
		public static final SootClass COMPONENT_TYPE_APPLICATION = Scene.v().getSootClass("android.app.Application");
		public static final SootClass COMPONENT_TYPE_GCMBASEINTENTSERVICECLASS = Scene.v().getSootClass("com.google.android.gcm.GCMBaseIntentService");
		public static final SootClass COMPONENT_TYPE_GCMLISTENERSERVICECLASS = Scene.v().getSootClass("com.google.android.gms.gcm.GcmListenerService");
		
		public static final SootClass[] component_type_classes = 
			{COMPONENT_TYPE_ACTIVITY, COMPONENT_TYPE_SERVICE,  COMPONENT_TYPE_RECEIVER, COMPONENT_TYPE_PROVIDER, 
			COMPONENT_TYPE_APPLICATION, COMPONENT_TYPE_GCMBASEINTENTSERVICECLASS, COMPONENT_TYPE_GCMLISTENERSERVICECLASS,
			COMPONENT_TYPE_UNKNOWN};
		public static final String[] component_type_names = {"Activity", "Service", "BroadcaseReceiver", "ContentProvider", "Application"};
}

/* vim :set ts=4 tw=4 tws=4 */
