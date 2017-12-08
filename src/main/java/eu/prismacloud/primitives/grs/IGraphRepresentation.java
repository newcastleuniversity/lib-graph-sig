package eu.prismacloud.primitives.grs;

import eu.prismacloud.primitives.grs.encoding.GSGraphEncoding;
import eu.prismacloud.primitives.grs.graph.GSGraph;

/**
 * Created by Ioannis Sfyrakis on 20/07/2017
 */
public interface IGraphRepresentation {

    public IGraphRepresentation encodeGraph(GSGraph graph, GSGraphEncoding graphEncoding);
    
}
