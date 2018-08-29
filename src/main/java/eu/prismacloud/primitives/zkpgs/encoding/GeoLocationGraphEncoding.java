package eu.prismacloud.primitives.zkpgs.encoding;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JsonIsoCountries;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/** The type Graph encoding. */
public class GeoLocationGraphEncoding implements IGraphEncoding {

	private final SignerPublicKey signerPublicKey;
	private Map<BigInteger, GSSignature> signatureMap;
	private Map<URN, BigInteger> vertexRepresentatives;
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private Map<URN, BigInteger> countryLabels;
	private JsonIsoCountries jsonIsoCountries;
	private Map<URN, Object> certifiedPrimeRepresenatives = new HashMap<URN, Object>();

	/**
	 * Instantiates a new graph encoding setting the vertex representatives externally.
	 *
	 * @param vertexRepresentatives the vertex prime representatives
	 * @param publicKey the country labels
	 * @param keyGenParameters the key gen parameters
	 * @param graphEncodingParameters the graph encoding parameters
	 */
	public GeoLocationGraphEncoding(
			final Map<URN, BigInteger> vertexRepresentatives,
			final SignerPublicKey publicKey,
			final KeyGenParameters keyGenParameters,
			final GraphEncodingParameters graphEncodingParameters) {

		this.vertexRepresentatives = vertexRepresentatives;
		this.signerPublicKey = publicKey;
		this.keyGenParameters = keyGenParameters;
		this.graphEncodingParameters = graphEncodingParameters;
	}
	
	/**
	 * Instantiates a new Graph encoding.
	 *
	 * @param bases the bases
	 * @param vertexPrimeRepresentatives the vertex prime representatives
	 * @param publicKey the country labels
	 * @param keyGenParameters the key gen parameters
	 * @param graphEncodingParameters the graph encoding parameters
	 */
	public GeoLocationGraphEncoding(
			final SignerPublicKey publicKey,
			final KeyGenParameters keyGenParameters,
			final GraphEncodingParameters graphEncodingParameters) {

		this.vertexRepresentatives = new LinkedHashMap<URN, BigInteger>();
		this.signerPublicKey = publicKey;
		this.keyGenParameters = keyGenParameters;
		this.graphEncodingParameters = graphEncodingParameters;
	}

	/** Setups the graph encoding. */
	public void setupEncoding() throws EncodingException {

		generateVertexRepresentatives();

		jsonIsoCountries = new JsonIsoCountries();
		countryLabels = jsonIsoCountries.getCountryMap();

		Iterator<BigInteger> labelRepIter = countryLabels.values().iterator();
		while (labelRepIter.hasNext()) {
			BigInteger label = (BigInteger) labelRepIter.next();
			if (!CryptoUtilsFacade.isInRange(label, 
					graphEncodingParameters.getLeastLabelRepresentative(), 
					graphEncodingParameters.getUpperBoundLabelRepresentatives())) {
				throw new EncodingException("The label representatives exceeded the designated range.");
			}
		}
	}

	/**
	 * Gets vertex prime representatives.
	 *
	 * @return the vertex prime representatives
	 */
	@Override
	public Map<URN, BigInteger> getVertexRepresentatives() {
		return this.vertexRepresentatives;
	}

	/**
	 * Gets label prime representatives.
	 *
	 * @return the label prime representatives
	 */
	@Override
	public Map<URN, BigInteger> getLabelRepresentatives() {
		return this.countryLabels;
	}

	/**
	 * Certify prime representatives.
	 *
	 * @param vertexPrimeRepresentatives the base representation
	 * @param baseV the base v
	 * @param labelRepresenatives the public key
	 * @param baseL the base l
	 */
	public void certify(
			Map<URN, BigInteger> vertexPrimeRepresentatives,
			BaseRepresentation baseV,
			Map<URN, BigInteger> labelRepresenatives,
			BaseRepresentation baseL) {

		signatureMap = new HashMap<BigInteger, GSSignature>();
		GSSignature gsSignature;

		for (BigInteger vertexPrime : vertexPrimeRepresentatives.values()) {
			gsSignature = CryptoUtilsFacade.generateSignature(vertexPrime, baseV, signerPublicKey);
			signatureMap.put(vertexPrime, gsSignature);
		}

		for (BigInteger label : labelRepresenatives.values()) {
			gsSignature = CryptoUtilsFacade.generateSignature(label, baseL, signerPublicKey);
			signatureMap.put(label, gsSignature);
		}
	}

	/**
	 * Generates the map of vertex representatives.
	 * 
	 * <p>The vertex representatives are chosen such that they start with the smallest permissible 
	 * prime value for vertex 0 and enumerate the successive primes to the successive 
	 * vertex representatives.
	 * 
	 * <p> The chosen vertex representatives are guaranteed not to collide with the
	 * label encoding space and are guaranteed to take at most lPrime_V space.
	 * 
	 * @complexity This method is resource-intensive as BigInteger.nextProbablePrime() will be
	 * called l_V times.
	 * 
	 * @param extendedKeyPair TODO
	 * @throws EncodingException if the graph encoding attempted to create a prime representative
	 * outside of the range designated for vertex encoding. This will only occur if the
	 * graph encoding parameters lPrime_V and l_V are contradicting each other, e.g, if
	 * the encoding bitlength lPrime_V is too small to encode the number of vertices l_V. 
	 */
	public void generateVertexRepresentatives() throws EncodingException {
		BigInteger vertexPrimeRepresentative = this.graphEncodingParameters.getLeastVertexRepresentative();
		Assert.notNull(vertexPrimeRepresentative, "Least vertex representative was null.");
		for (int i = 0; i < this.graphEncodingParameters.getL_V(); i++) {

			if (i == 0) {
				// The first vertex representative is chosen as the smallest prime possible.
				vertexPrimeRepresentative = this.graphEncodingParameters.getLeastVertexRepresentative();
			} else {
				// The subsequent representatives are chosen as the successive next primes.
				// This yields the most space/computation efficient encoding.
				vertexPrimeRepresentative = vertexPrimeRepresentative.nextProbablePrime();
			}
			
			Assert.notNull(vertexPrimeRepresentative, "Designated vertex representative was null.");

			if (!CryptoUtilsFacade.isInRange(vertexPrimeRepresentative, 
					this.graphEncodingParameters.getLeastVertexRepresentative(), 
					this.graphEncodingParameters.getUpperBoundVertexRepresentatives())) {
				throw new EncodingException("The graph encoding attempted to "
						+ "create a vertex representative outside of the designated range.");
			}

			this.vertexRepresentatives.put(
					URN.createZkpgsURN("vertex.representative.e_i_" + i), vertexPrimeRepresentative);
		}
	}

	@Override
	public GraphEncodingParameters getGraphEncodingParameters() {
		return graphEncodingParameters;
	}
}
