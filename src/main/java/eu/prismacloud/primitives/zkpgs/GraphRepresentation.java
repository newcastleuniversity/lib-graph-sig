package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.encoding.GSGraphEncoding;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;

public class GraphRepresentation implements IGraphRepresentation {

  public IGraphRepresentation encodeGraph(GSGraph graph, GSGraphEncoding graphEncoding) {
    return new GraphRepresentation();
  }
}
