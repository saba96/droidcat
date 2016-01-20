/**
 * File: src/dynCG/callGraph.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 12/10/15		hcai		created; for representing dynamic call graph
 * 01/05/16		hcai		the first basic, working version
*/
package dynCG;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jgrapht.*;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.alg.*;
import org.jgrapht.traverse.*;

/** represent the dynamic call graph built from whole program path profiles */
public class callGraph {
	public static final String CALL_DELIMIT = " -> ";
	// bijective mapping between string and integer tagging of canonically named method (package + class + method signature)
	public static final Map<String, Integer> g_me2idx = new HashMap<String, Integer>();
	public static final Map<Integer, String> g_idx2me = new HashMap<Integer,String>();
	
	public String toString() {
		return "dynamic conflated call graph: " + g_me2idx.size() + " methods; " + 
				this._graph.vertexSet().size() + " nodes; " + this._graph.edgeSet().size() + " edges.";
	}

	public static class CGNode {
		// method index
		private Integer idx;
		CGNode() {
			this(-1);
		}
		CGNode(int _idx) {
			idx = _idx;
		}
		public int getIndex () {
			return idx;
		}
		public String getMethodName() {
			if (-1 == idx) {
				return null;
			}
			return g_idx2me.get(this.idx);
		}
		public String getSootMethodName() {
			return "<" + getMethodName() + ">";
		}
		public String getSootClassName() {
			String ret = getMethodName();
			if (ret == null) return null;
			if (ret.indexOf(":")==-1) {
				System.err.println("weird node: " + ret);
				System.exit(-1);
			}
			return ret.substring(0, ret.indexOf(":"));
		}
		public boolean equals(Object other) {
			return ((CGNode)other).idx.intValue() == this.idx.intValue();
		}
		public int hashCode() {
			return idx.hashCode();
		}
		
		public String toString() {
			return getMethodName() + "[" + idx + "]";
		}
	}
	
	public static class CGNodeFactory implements VertexFactory<CGNode> {
		@Override
		public CGNode createVertex() {
			return new CGNode();
		}
	}
	
	public static class CGEdge {
		private CGNode src;
		private CGNode tgt;
		/* keep the time stamp of each instance, in the order of enrollment */
		/* then the size of this collection indicates the frequency of this call */
		private Set<Integer> tss = new LinkedHashSet<Integer>();
		CGEdge(CGNode _src, CGNode _tgt) {
			src = _src;
			tgt = _tgt;
		}
		public void addInstance (int ts) {
			tss.add(ts);
		}
		public CGNode getSource() {
			return src;
		}
		public CGNode getTarget() {
			return tgt;
		}
		
		public int getFrequency() { return tss.size(); }
		public Set<Integer> getAllTS () { return tss; }
		
		public String toString() {
			return "["+g_idx2me.get(src.getIndex()) + "->" + g_idx2me.get(tgt.getIndex())+"]:" + getFrequency();
		}
	}
	
	public static class CGEdgeFactory implements EdgeFactory<CGNode,CGEdge> {
		@Override
		public CGEdge createEdge(CGNode v0, CGNode v1) {
			return new CGEdge(v0, v1);
		}
	}
	
	private final DirectedGraph<CGNode, CGEdge> _graph = new DefaultDirectedGraph<CGNode, CGEdge>(new CGEdgeFactory());
	
	callGraph() {
	}
	
	public DirectedGraph<CGNode, CGEdge> getInternalGraph() { return _graph; }
	
	private CGEdge addEdge(CGNode src, CGNode tgt, int ts) {
		_graph.addVertex(src);
		_graph.addVertex(tgt);
		if (!_graph.containsEdge(src, tgt)) {
			_graph.addEdge(src, tgt);
		}
		CGEdge ret = _graph.getEdge(src, tgt);
		ret.addInstance(ts);
		return ret;
	}
	
	private CGNode getCreateNode(int mid) {
		CGNode tobe = new CGNode(mid);
		if (!_graph.containsVertex(tobe)) return tobe;
		for (CGNode n : _graph.vertexSet()) {
			if (tobe.equals(n)) {
				return n;
			}
		}
		return null;
		//throw new Exception("impossible error!");
	}
	
	public CGEdge addCall (int caller, int callee, int ts) {
		//addEdge(new CGNode(caller), new CGNode(callee));
		return addEdge (getCreateNode(caller), getCreateNode(callee), ts);
	}
	
	public int addMethod (String mename) {
		if (g_me2idx.keySet().contains(mename)) return g_me2idx.get(mename);
		int curidx = g_me2idx.size();
		g_me2idx.put(mename, curidx);
		
		assert !g_idx2me.containsKey(curidx);
		assert g_idx2me.size() == curidx;
		g_idx2me.put(curidx, mename);
		
		return curidx;
	}

	public CGEdge addCall (String traceLine, int ts) {
		traceLine = traceLine.trim();
		assert traceLine.contains(CALL_DELIMIT);
		String[] segs = traceLine.split(CALL_DELIMIT);
		assert segs.length == 2;
		for (int k = 0; k < segs.length; ++k) {
			segs[k] = segs[k].trim();
			if (segs[k].startsWith("<")) {
				segs[k] = segs[k].substring(1);
			}
			if (segs[k].endsWith(">")) {
				segs[k] = segs[k].substring(0, segs[k].length()-1);
			}
		}
		
		return addCall (addMethod (segs[0]), addMethod (segs[1]), ts);
	}
	
	public CGNode getNodeByName (String mename) {
		for (CGNode cgn : _graph.vertexSet()) {
			if (cgn.getMethodName().equalsIgnoreCase(mename)) return cgn;
		}
		return null;
	}
	
	public CGEdge getEdgeByName(String caller, String callee) {
		CGNode src = getNodeByName (caller);
		CGNode tgt = getNodeByName (callee);
		if (null == src || null == tgt) return null;
		
		return _graph.getEdge(src, tgt);
	}
	
	public Set<CGNode> getAllCallees (String caller) {
		Set<CGNode> ret = new HashSet<CGNode>();
		
		CGNode src = getNodeByName (caller);
		if (null == src) return ret;
		
		for (CGEdge oe : _graph.outgoingEdgesOf(src)) {
			ret.add(oe.getTarget());
		}
		return ret;
	}

	public Set<CGNode> getAllCallers (String callee) {
		Set<CGNode> ret = new HashSet<CGNode>();
		
		CGNode tgt = getNodeByName (callee);
		if (null == tgt) return ret;
		
		for (CGEdge ie : _graph.incomingEdgesOf(tgt)) {
			ret.add(ie.getSource());
		}
		return ret;
	}
	
	public List<CGEdge> getPath(String caller, String callee) {
		CGNode src = getNodeByName (caller);
		CGNode tgt = getNodeByName (callee);
		if (null == src || null == tgt) return new ArrayList<CGEdge>();
		
		DijkstraShortestPath<CGNode, CGEdge> finder = new DijkstraShortestPath<CGNode, CGEdge>(_graph, src, tgt);
		return finder.getPath().getEdgeList();
	}

	public boolean isReachable (String caller, String callee) {
		return !getPath(caller, callee).isEmpty();
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	static class CGEdgeComparator implements Comparator<CGEdge> {
		private CGEdgeComparator() {
		}
		
		private static final CGEdgeComparator cgcSingleton = new CGEdgeComparator(); 
		public static final CGEdgeComparator inst() { return cgcSingleton; }

		public int compare(CGEdge a, CGEdge b) {
			if ( a.getFrequency() > b.getFrequency() ) {
				return 1;
			}
			else if ( a.getFrequency() < b.getFrequency() ) {
				return -1;
			}
			return 0;
		}
	}
	
	public List<CGEdge> listEdgeByFrequency() { return listEdgeByFrequency(true); }
	public List<CGEdge> listEdgeByFrequency(boolean verbose) {
		if (verbose) {
			System.out.println("\n==== call frequencies ===\n ");
		}
		List<CGEdge> allEdges = new ArrayList<CGEdge>();
		allEdges.addAll(this._graph.edgeSet());
		Collections.sort(allEdges, CGEdgeComparator.inst());
		if (verbose) {
			for (CGEdge e : allEdges) {
				System.out.println(e);
			}
		}
		return allEdges;
	}
	
	public List<CGNode> listCallers() { return listCallers(true); }
	public List<CGNode> listCallers(boolean verbose) {
		if (verbose) {
			System.out.println("\n==== caller ranked by non-ascending fan-out  === \n");
		}
		List<CGNode> allNodes = new ArrayList<CGNode>();
		allNodes.addAll(this._graph.vertexSet());
		Collections.sort(allNodes, new Comparator<CGNode>() {
			public int compare(CGNode a, CGNode b) {
				if ( _graph.outDegreeOf(a) > _graph.outDegreeOf(b) ) {
					return 1;
				}
				else if ( _graph.outDegreeOf(a) < _graph.outDegreeOf(b) ) {
					return -1;
				}
				return 0;
			}
		});
		if (verbose) {
			for (CGNode n : allNodes) {
				System.out.println(n+":"+_graph.outDegreeOf(n));
			}
		}
		return allNodes;
	}
	
	public List<CGNode> listCallees() { return listCallees(true); }
	public List<CGNode> listCallees(boolean verbose) {
		if (verbose) {
			System.out.println("\n==== callee ranked by non-ascending fan-in  === \n");
		}
		List<CGNode> allNodes = new ArrayList<CGNode>();
		allNodes.addAll(this._graph.vertexSet());
		Collections.sort(allNodes, new Comparator<CGNode>() {
			public int compare(CGNode a, CGNode b) {
				if ( _graph.inDegreeOf(a) > _graph.inDegreeOf(b) ) {
					return 1;
				}
				else if ( _graph.inDegreeOf(a) < _graph.inDegreeOf(b) ) {
					return -1;
				}
				return 0;
			}
		});
		if (verbose) {
			for (CGNode n : allNodes) {
				System.out.println(n+":"+_graph.inDegreeOf(n));
			}
		}
		return allNodes;
	}
}

/* vim :set ts=4 tw=4 tws=4 */

