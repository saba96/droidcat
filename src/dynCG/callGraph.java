/**
 * File: src/dynCG/callGraph.java
 * -------------------------------------------------------------------------------------------
 * Date			Author      Changes
 * -------------------------------------------------------------------------------------------
 * 12/10/15		hcai		created; for representing dynamic call graph
 *
*/
package dynCG;

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

/** represent the dynamic call graph built from whole program path profiles */
public class callGraph {
	public static final String CALL_DELIMIT = "->";
	// bijective mapping between string and integer tagging of canonically named method (package + class + method signature)
	public static final Map<String, Integer> g_me2idx = new HashMap<String, Integer>();
	public static final Map<Integer, String> g_idx2me = new HashMap<Integer,String>();

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
		CGEdge(CGNode _src, CGNode _tgt) {
			src = _src;
			tgt = _tgt;
		}
		public CGNode getSource() {
			return src;
		}
		public CGNode getTarget() {
			return tgt;
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
	
	private void addEdge(CGNode src, CGNode tgt) {
		_graph.addVertex(src);
		_graph.addVertex(tgt);
		_graph.addEdge(src, tgt);
	}
	
	public void addCall (int caller, int callee) {
		addEdge(new CGNode(caller), new CGNode(callee));
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

	public void addCall (String traceLine) {
		traceLine = traceLine.trim();
		assert traceLine.contains(CALL_DELIMIT);
		String[] segs = traceLine.split(CALL_DELIMIT);
		assert segs.length == 2;
		
		addCall (addMethod (segs[0]), addMethod (segs[1]));
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
}

/* vim :set ts=4 tw=4 tws=4 */

