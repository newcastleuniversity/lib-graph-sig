package eu.prismacloud.primitives.grs;

import eu.prismacloud.primitives.grs.encoding.GSGraphEncoding;
import eu.prismacloud.primitives.grs.graph.GSGraph;

public interface IGraphRepresentation {

  public IGraphRepresentation encodeGraph(GSGraph graph, GSGraphEncoding graphEncoding);
}
