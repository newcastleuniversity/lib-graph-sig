/**
 * Offers classes for representing general graphs (org.jgrapht.Graph) 
 * with graph encodings.
 * 
 * <p>The classes GSVertex and GSEdge are designated Graph elements
 * which can be encoded with an IGraphEncoding.
 * 
 * <p>There is a separation of duty between different classes:
 * <ul>
 *   <li>GSGraph acts as Graph wrapper and organizes the construction of 
 *   a graph from graphml as well as encoding the graph with a given
 *   IGraphEncoding.
 *   <li>IGraphEncoding specified in the encoding package is responsible for 
 *   mapping vertex ids and label strings to a finite set of prime 
 *   representatives.
 *   <li>GraphRepresentation is responsible to map a given GSGraph onto
 *   a particular structure of bases (GroupElement instances of an ExtendedPublicKey)
 *   that represent the GSGraph for a specific GSSignature.
 * </ul>
 * 
 * <p>A typical call sequence to instantiate a GSGraph and to encode it will be as follows:
 * <ol>
 *   <li>GSGraph gsgraph = GSGraph.createGraph(filename); a factory method that reads a graph structure 
 *   from a standard graphml file.
 *   <li>IGraphEncoding encoding = new IGraphEncoding(GraphEncodingParameters params); 
 *   followed by encoding.setupEncoding(). These calls instantiate a graph encoding,
 *   for instance, a GeoLocationGraphEncoding.
 *   <li>gsgraph.encode(encoding); applies the encoding to the given GSGraph and
 *   adds the prime representatives to its GSVertex and GSEdge instances.
 *   <li>GraphRepresentation graphRep = GraphRepresetation.encodeGraph(gsgraph, epk) - 
 *   The GraphRepresentation is then meant to hold a graph in the form of bases and 
 *   their exponents for a given GSSignature. 
 * </ol>
 */
package uk.ac.ncl.cascade.zkpgs.graph;