package uk.ac.ncl.cascade.zkpgs.encoding;

import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Realizes an encoding for prime e_{i} that represents a pseudonym in a binding credential.
 */
public class PseudonymPrimeEncoding implements IGraphEncoding, Serializable {

	private final Map<URN, BigInteger> vertexRepresentatives;
	private final GraphEncodingParameters graphEncodingParameters;
	private final List<String> values;
	private boolean setupCompleted = false;
	private FilePersistenceUtil persistenceUtil;
	private List<String> primes;


	/**
	 * Creates a new prime encoding associated with the signer's public key.
	 * The primes in the encoding represent a pseudonym in the binding credential.
	 *
	 * @param graphEncodingParameters the graph encoding parameters to use
	 * @param values                  the list of prime numbers to encode
	 */
	public PseudonymPrimeEncoding(final GraphEncodingParameters graphEncodingParameters, final List<String> values) {
		this.vertexRepresentatives = new LinkedHashMap<URN, BigInteger>();
		this.graphEncodingParameters = graphEncodingParameters;
		this.values = values;
	}

	@Override
	public void setupEncoding() throws EncodingException {
		BigInteger vertexPrimeRepresentative = this.graphEncodingParameters.getLeastVertexRepresentative();

		for (int i = 0; i < this.values.size(); i++) {

			vertexPrimeRepresentative = new BigInteger(this.values.get(i));

			if (!CryptoUtilsFacade.isInRange(
					vertexPrimeRepresentative,
					this.graphEncodingParameters.getLeastVertexRepresentative(),
					this.graphEncodingParameters.getUpperBoundVertexRepresentatives())) {
				throw new EncodingException(
						"The encoding attempted to "
								+ "create a vertex representative outside of the designated range.");
			}

			this.vertexRepresentatives.put(
					URN.createZkpgsURN("vertex.representative.e_i_" + i), vertexPrimeRepresentative);
		}


		setupCompleted = true;


	}

	@Override
	public GraphEncodingParameters getGraphEncodingParameters() {
		return this.graphEncodingParameters;
	}

	@Override
	public Map<URN, BigInteger> getVertexRepresentatives() {
		return this.vertexRepresentatives;
	}

	@Override
	public Map<URN, BigInteger> getLabelRepresentatives() {
		return null;
	}

	@Override
	public BigInteger getVertexRepresentative(String id) {
		if (!setupCompleted) throw new IllegalStateException("The setup has not been completed.");
		return vertexRepresentatives.get(URN.createZkpgsURN("vertex.representative.e_i_" + id));
	}

	@Override
	public BigInteger getVertexLabelRepresentative(String label) {
		return BigInteger.ONE;
	}

	@Override
	public BigInteger getEdgeLabelRepresentative(String label) {
		return BigInteger.ONE;
	}
}
