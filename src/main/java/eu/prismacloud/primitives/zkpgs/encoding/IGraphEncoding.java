package eu.prismacloud.primitives.zkpgs.encoding;

import java.math.BigInteger;
import java.util.Map;

import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.util.URN;

/** 
 * Interface for classes that offer representative encodings.
 *
 */
public interface IGraphEncoding {

	GraphEncodingParameters getGraphEncodingParameters();
	Map<URN, BigInteger> getVertexRepresentatives();
	Map<URN, BigInteger> getLabelRepresentatives();
	void setupEncoding() throws EncodingException;
}
