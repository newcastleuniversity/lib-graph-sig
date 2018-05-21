package eu.prismacloud.primitives.grs.graph;

import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.DefaultWeightedEdge;
import org.jgrapht.graph.SimpleGraph;

public class GSGraph { // implements IGraph {

  private SimpleGraph<GSVertex, DefaultEdge> g =
      new SimpleGraph<GSVertex, DefaultEdge>(DefaultEdge.class);
  static final double DEFAULT_EDGE_WEIGHT = 19;
  //        DefaultWeightedEdge (DefaultWeightedEdge.class);
  private DefaultWeightedEdge e1;

  public void addVertex(GSVertex name) {
    g.addVertex(name);
  }

  public DefaultEdge addEdge(GSVertex v1, GSVertex v2) {

    return g.addEdge(v1, v2);
  }

  public GSGraph() {}

  public SimpleGraph<GSVertex, DefaultEdge> createGraph() {
    SimpleGraph<GSVertex, DefaultEdge> g =
        new SimpleGraph<GSVertex, DefaultEdge>(DefaultEdge.class);
    GSVertex v1 = new GSVertex();
    GSVertex v2 = new GSVertex();

    g.addVertex(v1);
    g.addVertex(v2);

    DefaultEdge edge = g.addEdge(v1, v2);

    // traverse graph
    // Graphs.getOppositeVertex(g, edge, v1).colour = "red";
    return g;
  }

  public void addConnectingVertex(GSVertex vertex, String label) {

    GSVertex signerConnectingVertex = new GSVertex();
    signerConnectingVertex.setLabel(label);
  }
}
