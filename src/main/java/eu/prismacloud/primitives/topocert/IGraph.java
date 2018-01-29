package eu.prismacloud.primitives.topocert;

import eu.prismacloud.primitives.grs.graph.GSVertex;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;

import java.util.ArrayList;


public interface IGraph {
  void  addVertices(ArrayList<IVertex> vertices);
  void  addVertex(IVertex vertex);
  void  addEdges(ArrayList<IEdge> edges);
  void  addEdge(IEdge edge);
  void  addLabels(ArrayList<ILabel> labels);
  void  addLabel(ILabel label);
  SimpleGraph<GSVertex, DefaultEdge> createGraph();
}
