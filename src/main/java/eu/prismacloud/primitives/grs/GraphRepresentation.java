package eu.prismacloud.primitives.grs;

import eu.prismacloud.primitives.grs.encoding.GSGraphEncoding;
import eu.prismacloud.primitives.grs.graph.GSGraph;

/**
 * Created by Ioannis Sfyrakis on 27/07/2017
 */
public class GraphRepresentation implements IGraphRepresentation {

    public IGraphRepresentation encodeGraph(GSGraph graph, GSGraphEncoding graphEncoding) {
        return new GraphRepresentation();
    }

}
